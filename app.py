from flask import Flask, render_template_string, request, jsonify
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_analyzer.predefined_recognizers import AuTfnRecognizer, AuAbnRecognizer, AuAcnRecognizer, AuMedicareRecognizer, PhoneRecognizer
from presidio_anonymizer import AnonymizerEngine
import json
import os
import re
import logging
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# Ensure data directory exists
os.makedirs(app.config['DATA_DIR'], exist_ok=True)

# Initialize Presidio with Australian recognizers
registry = RecognizerRegistry()
registry.load_predefined_recognizers()

# Add Australian tax/business number recognizers
registry.add_recognizer(AuTfnRecognizer())
registry.add_recognizer(AuAbnRecognizer())
registry.add_recognizer(AuAcnRecognizer())
registry.add_recognizer(AuMedicareRecognizer())

# Add Australian phone number support using phonenumbers library
au_phone_recognizer = PhoneRecognizer(supported_regions=["AU"])
registry.add_recognizer(au_phone_recognizer)

analyzer = AnalyzerEngine(registry=registry)
anonymizer = AnonymizerEngine()

# Storage files
MAPPING_FILE = os.path.join(app.config['DATA_DIR'], "pii_mappings.json")
IGNORE_LIST_FILE = os.path.join(app.config['DATA_DIR'], "ignore_list.json")
CUSTOM_NAMES_FILE = os.path.join(app.config['DATA_DIR'], "custom_names.json")

def load_json_file(filepath, default=None):
    """Load JSON file with error handling."""
    if default is None:
        default = {}
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Error loading {filepath}: {e}")
            return default
    return default

def save_json_file(filepath, data):
    """Save JSON file with error handling."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error saving {filepath}: {e}")
        raise

def load_mappings():
    """Load PII mappings dictionary."""
    return load_json_file(MAPPING_FILE, {})

def save_mappings(mappings):
    """Save PII mappings dictionary."""
    save_json_file(MAPPING_FILE, mappings)

def load_ignore_list():
    """Load words to ignore during PII detection."""
    return load_json_file(IGNORE_LIST_FILE, [])

def load_custom_names():
    """Load custom names dictionary."""
    return load_json_file(CUSTOM_NAMES_FILE, [])

def post_process_lastname_firstname(text, results):
    """
    Post-process results to detect 'LastName, FirstName' pattern.
    Only adds lastname if firstname is already detected as PERSON.
    """
    # Find all PERSON entities
    person_entities = {(r.start, r.end): r for r in results if r.entity_type == "PERSON"}

    # Pattern: Capital word followed by comma and space
    pattern = r'\b([A-Z][a-z]+),\s+'

    additional_results = []
    for match in re.finditer(pattern, text):
        potential_lastname_start = match.start(1)
        potential_lastname_end = match.end(1)
        comma_position = match.end()

        # Check if any PERSON entity starts right after the comma
        found_firstname = False
        for (start, end), result in person_entities.items():
            # FirstName starts within 0-2 chars after comma (allowing for whitespace)
            if start >= comma_position and start <= comma_position + 2:
                found_firstname = True
                break

        # Only add lastname if firstname was detected
        if found_firstname:
            # Check if this lastname isn't already covered by an existing entity
            overlap = False
            for (start, end) in person_entities.keys():
                if start <= potential_lastname_start < end or start < potential_lastname_end <= end:
                    overlap = True
                    break

            if not overlap:
                # Create new RecognizerResult for the lastname
                lastname_result = RecognizerResult(
                    entity_type="PERSON",
                    start=potential_lastname_start,
                    end=potential_lastname_end,
                    score=0.85
                )
                additional_results.append(lastname_result)

    return results + additional_results

def filter_ignore_list(text, results):
    """Remove entities that match the ignore list."""
    ignore_list = load_ignore_list()
    if not ignore_list:
        return results

    filtered_results = []
    for result in results:
        entity_text = text[result.start:result.end]
        if entity_text not in ignore_list:
            filtered_results.append(result)

    return filtered_results

def add_custom_names(text, results):
    """Add custom names from dictionary as PERSON entities."""
    custom_names = load_custom_names()
    if not custom_names:
        return results

    additional_results = []
    for name in custom_names:
        # Find all occurrences of this name
        for match in re.finditer(r'\b' + re.escape(name) + r'\b', text, re.IGNORECASE):
            start = match.start()
            end = match.end()

            # Check if already covered by existing entity
            overlap = False
            for result in results:
                if result.start <= start < result.end or result.start < end <= result.end:
                    overlap = True
                    break

            if not overlap:
                custom_result = RecognizerResult(
                    entity_type="PERSON",
                    start=start,
                    end=end,
                    score=1.0
                )
                additional_results.append(custom_result)

    return results + additional_results

def merge_adjacent_persons(text, results):
    """Merge adjacent PERSON entities (handles 'LastName, FirstName' from NER)."""
    if not results:
        return results

    # Group adjacent PERSON entities (within 3 chars - comma + space)
    merged_results = []
    skip_indices = set()

    sorted_results = sorted(results, key=lambda x: x.start)

    for i, result in enumerate(sorted_results):
        if i in skip_indices:
            continue

        if result.entity_type == "PERSON":
            merged_start = result.start
            merged_end = result.end

            # Look ahead for adjacent PERSON entities
            for j in range(i + 1, len(sorted_results)):
                next_result = sorted_results[j]
                if next_result.entity_type == "PERSON" and next_result.start - merged_end <= 3:
                    merged_end = next_result.end
                    skip_indices.add(j)
                else:
                    break

            # Create merged result
            merged_result = RecognizerResult(
                entity_type="PERSON",
                start=merged_start,
                end=merged_end,
                score=result.score
            )
            merged_results.append(merged_result)
        else:
            merged_results.append(result)

    return merged_results

def filter_by_entity_types(results, enabled_entities):
    """Filter results to only include enabled entity types."""
    if not enabled_entities:
        return results
    return [r for r in results if r.entity_type in enabled_entities]

def anonymize_text(text, threshold=0.5, enabled_entities=None):
    """Anonymize text by replacing PII with generic placeholders."""
    results = analyzer.analyze(text=text, language='en', score_threshold=threshold)

    # Apply filters and enhancements
    results = filter_by_entity_types(results, enabled_entities)
    results = filter_ignore_list(text, results)
    results = add_custom_names(text, results)
    results = post_process_lastname_firstname(text, results)
    results = merge_adjacent_persons(text, results)

    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
    return anonymized.text, len(results)

def deidentify_text(text, threshold=0.5, enabled_entities=None):
    """De-identify text by replacing PII with reversible placeholders."""
    results = analyzer.analyze(text=text, language='en', score_threshold=threshold)

    # Apply filters and enhancements
    results = filter_by_entity_types(results, enabled_entities)
    results = filter_ignore_list(text, results)
    results = add_custom_names(text, results)
    results = post_process_lastname_firstname(text, results)
    results = merge_adjacent_persons(text, results)

    mappings = load_mappings()
    entity_counters = {}

    # Sort by position in reverse to replace from end to start
    sorted_results = sorted(results, key=lambda x: x.start, reverse=True)

    deidentified_text = text

    for result in sorted_results:
        entity_type = result.entity_type
        original_value = text[result.start:result.end]

        # Initialize counter for this entity type
        if entity_type not in entity_counters:
            entity_counters[entity_type] = len([k for k in mappings.keys() if k.startswith(f"{entity_type}_")])

        # Generate placeholder
        entity_counters[entity_type] += 1
        placeholder = f"{entity_type}_{entity_counters[entity_type]:03d}"

        # Store mapping
        mappings[placeholder] = original_value

        # Replace in text
        deidentified_text = deidentified_text[:result.start] + placeholder + deidentified_text[result.end:]

    save_mappings(mappings)
    return deidentified_text, len(results)

def reidentify_text(text):
    """Restore original PII values from de-identified text."""
    mappings = load_mappings()
    reidentified_text = text

    # Sort by placeholder length (longest first) to avoid partial replacements
    sorted_mappings = sorted(mappings.items(), key=lambda x: len(x[0]), reverse=True)

    for placeholder, original_value in sorted_mappings:
        reidentified_text = reidentified_text.replace(placeholder, original_value)

    return reidentified_text, 0

def clear_mappings():
    """Clear the PII mappings file."""
    save_mappings({})

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>PII Removal Tool</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f7fa;
            color: #333;
        }
        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            text-align: center;
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        .info-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 25px;
        }
        .info-box h3 {
            margin-bottom: 12px;
            font-size: 18px;
        }
        .info-box p {
            margin: 6px 0;
            font-size: 14px;
            opacity: 0.95;
        }
        .entity-selector {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 25px;
            border: 2px solid #e1e8ed;
        }
        .entity-selector h3 {
            margin-bottom: 15px;
            color: #2c3e50;
            font-size: 16px;
        }
        .entity-section {
            margin-bottom: 20px;
        }
        .section-header {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            padding: 10px;
            background-color: white;
            border-radius: 6px;
            cursor: pointer;
            user-select: none;
        }
        .section-header:hover {
            background-color: #f0f0f0;
        }
        .section-header input[type="checkbox"] {
            margin-right: 10px;
            cursor: pointer;
            width: 18px;
            height: 18px;
        }
        .section-header label {
            flex: 1;
            font-weight: 600;
            cursor: pointer;
            margin: 0;
        }
        .toggle-icon {
            font-size: 12px;
            color: #666;
        }
        .entity-group {
            margin-left: 30px;
            padding: 10px;
            background-color: white;
            border-radius: 6px;
            border-left: 3px solid #667eea;
        }
        .entity-group.collapsed {
            display: none;
        }
        .entity-item {
            display: flex;
            align-items: center;
            padding: 6px 0;
        }
        .entity-item input[type="checkbox"] {
            margin-right: 10px;
            cursor: pointer;
            width: 16px;
            height: 16px;
        }
        .entity-item label {
            cursor: pointer;
            margin: 0;
            font-size: 14px;
        }
        .entity-description {
            color: #666;
            font-size: 12px;
            margin-left: 5px;
        }
        .threshold-control {
            background-color: #fff3cd;
            padding: 18px;
            border-radius: 8px;
            margin-bottom: 25px;
            border-left: 4px solid #ffc107;
        }
        .threshold-control label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        .slider-container {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .threshold-control input[type="range"] {
            flex: 1;
            height: 6px;
            border-radius: 3px;
            background: #ddd;
            outline: none;
            cursor: pointer;
        }
        .threshold-control input[type="range"]::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: #f57c00;
            cursor: pointer;
        }
        .threshold-value {
            font-weight: bold;
            color: #f57c00;
            font-size: 18px;
            min-width: 50px;
            text-align: center;
        }
        .help-text {
            margin-top: 8px;
            font-size: 13px;
            color: #666;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        textarea {
            width: 100%;
            height: 200px;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            resize: vertical;
            transition: border-color 0.3s;
        }
        textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        .button-group {
            margin: 25px 0;
            display: flex;
            gap: 12px;
            justify-content: center;
            flex-wrap: wrap;
        }
        button {
            padding: 12px 28px;
            font-size: 15px;
            font-weight: 600;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        button:active {
            transform: translateY(0);
        }
        .btn-anonymize {
            background-color: #e74c3c;
            color: white;
        }
        .btn-anonymize:hover {
            background-color: #c0392b;
        }
        .btn-deidentify {
            background-color: #3498db;
            color: white;
        }
        .btn-deidentify:hover {
            background-color: #2980b9;
        }
        .btn-reidentify {
            background-color: #2ecc71;
            color: white;
        }
        .btn-reidentify:hover {
            background-color: #27ae60;
        }
        .btn-clear {
            background-color: #95a5a6;
            color: white;
        }
        .btn-clear:hover {
            background-color: #7f8c8d;
        }
        .btn-clear-mappings {
            background-color: #e67e22;
            color: white;
        }
        .btn-clear-mappings:hover {
            background-color: #d35400;
        }
        .output-section {
            margin-top: 25px;
        }
        .stats {
            display: flex;
            gap: 20px;
            margin-top: 15px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }
        .stat-item {
            flex: 1;
            text-align: center;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            font-size: 12px;
            color: #666;
            margin-top: 4px;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 13px;
            color: #7f8c8d;
        }
        .footer a {
            color: #667eea;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <h1>🔒 PII Removal Tool</h1>
    <div class="subtitle">Secure, Local PII Detection and De-identification</div>

    <div class="container">
        <div class="info-box">
            <h3>How It Works</h3>
            <p><strong>Anonymize:</strong> Replaces PII with generic placeholders (e.g., &lt;PERSON&gt;, &lt;PHONE_NUMBER&gt;)</p>
            <p><strong>De-identify:</strong> Replaces PII with numbered placeholders (e.g., PERSON_001) - fully reversible</p>
            <p><strong>Re-identify:</strong> Restores original values from de-identified text using local mapping</p>
        </div>

        <div class="entity-selector">
            <h3>Select PII Types to Detect</h3>

            <!-- Recommended Section -->
            <div class="entity-section">
                <div class="section-header" onclick="toggleSection('recommended')">
                    <input type="checkbox" id="recommended-parent" onchange="toggleParent('recommended')" checked>
                    <label for="recommended-parent">✅ Recommended (Default ON)</label>
                    <span class="toggle-icon" id="recommended-toggle">▼</span>
                </div>
                <div id="recommended-group" class="entity-group">
                    <!-- Personal Information -->
                    <div class="section-header" onclick="toggleSection('personal')">
                        <input type="checkbox" id="personal-parent" onchange="toggleGroup('personal')" checked>
                        <label for="personal-parent">Personal Information</label>
                        <span class="toggle-icon" id="personal-toggle">▼</span>
                    </div>
                    <div id="personal-group" class="entity-group">
                        <div class="entity-item">
                            <input type="checkbox" id="PERSON" class="personal-child recommended-child" checked>
                            <label for="PERSON">PERSON <span class="entity-description">- Names</span></label>
                        </div>
                        <div class="entity-item">
                            <input type="checkbox" id="EMAIL_ADDRESS" class="personal-child recommended-child" checked>
                            <label for="EMAIL_ADDRESS">EMAIL_ADDRESS</label>
                        </div>
                        <div class="entity-item">
                            <input type="checkbox" id="PHONE_NUMBER" class="personal-child recommended-child" checked>
                            <label for="PHONE_NUMBER">PHONE_NUMBER</label>
                        </div>
                        <div class="entity-item">
                            <input type="checkbox" id="LOCATION" class="personal-child recommended-child" checked>
                            <label for="LOCATION">LOCATION <span class="entity-description">- Addresses, cities</span></label>
                        </div>
                    </div>

                    <!-- Financial & ID Numbers -->
                    <div class="section-header" onclick="toggleSection('financial')" style="margin-top: 10px;">
                        <input type="checkbox" id="financial-parent" onchange="toggleGroup('financial')" checked>
                        <label for="financial-parent">Financial & ID Numbers</label>
                        <span class="toggle-icon" id="financial-toggle">▼</span>
                    </div>
                    <div id="financial-group" class="entity-group">
                        <div class="entity-item">
                            <input type="checkbox" id="AU_TFN" class="financial-child recommended-child" checked>
                            <label for="AU_TFN">AU_TFN <span class="entity-description">- Tax File Number</span></label>
                        </div>
                        <div class="entity-item">
                            <input type="checkbox" id="AU_ABN" class="financial-child recommended-child" checked>
                            <label for="AU_ABN">AU_ABN <span class="entity-description">- Business Number</span></label>
                        </div>
                        <div class="entity-item">
                            <input type="checkbox" id="AU_ACN" class="financial-child recommended-child" checked>
                            <label for="AU_ACN">AU_ACN <span class="entity-description">- Company Number</span></label>
                        </div>
                        <div class="entity-item">
                            <input type="checkbox" id="AU_MEDICARE" class="financial-child recommended-child" checked>
                            <label for="AU_MEDICARE">AU_MEDICARE</label>
                        </div>
                        <div class="entity-item">
                            <input type="checkbox" id="CREDIT_CARD" class="financial-child recommended-child" checked>
                            <label for="CREDIT_CARD">CREDIT_CARD</label>
                        </div>
                        <div class="entity-item">
                            <input type="checkbox" id="IBAN_CODE" class="financial-child recommended-child" checked>
                            <label for="IBAN_CODE">IBAN_CODE <span class="entity-description">- International bank account</span></label>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Situational Section -->
            <div class="entity-section" style="margin-top: 20px;">
                <div class="section-header" onclick="toggleSection('situational')">
                    <input type="checkbox" id="situational-parent" onchange="toggleParent('situational')">
                    <label for="situational-parent">⚠️ Situational (Default OFF)</label>
                    <span class="toggle-icon" id="situational-toggle">▼</span>
                </div>
                <div id="situational-group" class="entity-group">
                    <div class="entity-item">
                        <input type="checkbox" id="DATE_TIME" class="situational-child">
                        <label for="DATE_TIME">DATE_TIME <span class="entity-description">- Dates and times</span></label>
                    </div>
                    <div class="entity-item">
                        <input type="checkbox" id="ORGANIZATION" class="situational-child">
                        <label for="ORGANIZATION">ORGANIZATION <span class="entity-description">- Company names</span></label>
                    </div>
                    <div class="entity-item">
                        <input type="checkbox" id="URL" class="situational-child">
                        <label for="URL">URL</label>
                    </div>
                    <div class="entity-item">
                        <input type="checkbox" id="IP_ADDRESS" class="situational-child">
                        <label for="IP_ADDRESS">IP_ADDRESS</label>
                    </div>
                    <div class="entity-item">
                        <input type="checkbox" id="NRP" class="situational-child">
                        <label for="NRP">NRP <span class="entity-description">- Nationality/Religion/Politics</span></label>
                    </div>
                </div>
            </div>
        </div>

        <div class="threshold-control">
            <label for="threshold">Detection Confidence Threshold</label>
            <div class="slider-container">
                <input type="range" id="threshold" min="0" max="1" step="0.05" value="0.5" oninput="updateThreshold()">
                <span class="threshold-value" id="thresholdValue">0.50</span>
            </div>
            <p class="help-text">Lower = catches more entities (may include false positives) | Higher = more precise (may miss some entities)</p>
        </div>

        <label for="inputText">Input Text:</label>
        <textarea id="inputText" placeholder="Paste your text here..."></textarea>

        <div class="button-group">
            <button class="btn-anonymize" onclick="processText('anonymize')">🔴 Anonymize</button>
            <button class="btn-deidentify" onclick="processText('deidentify')">🔵 De-identify</button>
            <button class="btn-reidentify" onclick="processText('reidentify')">🟢 Re-identify</button>
            <button class="btn-clear" onclick="clearAll()">🗑️ Clear All</button>
            <button class="btn-clear-mappings" onclick="clearMappings()">🧹 Clear Mappings</button>
        </div>

        <div class="output-section">
            <label for="outputText">Output Text:</label>
            <textarea id="outputText" readonly></textarea>
        </div>

        <div class="stats" id="stats" style="display: none;">
            <div class="stat-item">
                <div class="stat-value" id="entitiesFound">0</div>
                <div class="stat-label">Entities Found</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="processingTime">0ms</div>
                <div class="stat-label">Processing Time</div>
            </div>
        </div>
    </div>

    <div class="footer">
        <p>Powered by <a href="https://microsoft.github.io/presidio/" target="_blank">Microsoft Presidio</a> | All processing happens locally - no data sent to cloud</p>
    </div>

    <script>
        function updateThreshold() {
            const threshold = document.getElementById('threshold').value;
            document.getElementById('thresholdValue').textContent = parseFloat(threshold).toFixed(2);
        }

        function toggleSection(sectionId) {
            const group = document.getElementById(sectionId + '-group');
            const toggle = document.getElementById(sectionId + '-toggle');
            if (group.classList.contains('collapsed')) {
                group.classList.remove('collapsed');
                toggle.textContent = '▼';
            } else {
                group.classList.add('collapsed');
                toggle.textContent = '▶';
            }
        }

        function toggleParent(parentId) {
            const checkbox = document.getElementById(parentId + '-parent');
            const children = document.querySelectorAll('.' + parentId + '-child');
            children.forEach(child => {
                child.checked = checkbox.checked;
            });
        }

        function toggleGroup(groupId) {
            const checkbox = document.getElementById(groupId + '-parent');
            const children = document.querySelectorAll('.' + groupId + '-child');
            children.forEach(child => {
                child.checked = checkbox.checked;
            });

            // Update recommended parent if needed
            updateRecommendedParent();
        }

        function updateRecommendedParent() {
            const allChildren = document.querySelectorAll('.recommended-child');
            const checkedChildren = Array.from(allChildren).filter(c => c.checked);
            const recommendedParent = document.getElementById('recommended-parent');
            recommendedParent.checked = checkedChildren.length > 0;
        }

        function updateSituationalParent() {
            const allChildren = document.querySelectorAll('.situational-child');
            const checkedChildren = Array.from(allChildren).filter(c => c.checked);
            const situationalParent = document.getElementById('situational-parent');
            situationalParent.checked = checkedChildren.length > 0;
        }

        // Add event listeners to children to update parents
        document.querySelectorAll('.recommended-child').forEach(child => {
            child.addEventListener('change', updateRecommendedParent);
        });

        document.querySelectorAll('.situational-child').forEach(child => {
            child.addEventListener('change', updateSituationalParent);
        });

        function getEnabledEntities() {
            const entities = [
                'PERSON', 'EMAIL_ADDRESS', 'PHONE_NUMBER', 'LOCATION',
                'AU_TFN', 'AU_ABN', 'AU_ACN', 'AU_MEDICARE', 'CREDIT_CARD', 'IBAN_CODE',
                'DATE_TIME', 'ORGANIZATION', 'URL', 'IP_ADDRESS', 'NRP'
            ];
            return entities.filter(id => document.getElementById(id)?.checked);
        }

        async function processText(action) {
            const inputText = document.getElementById('inputText').value;
            const threshold = document.getElementById('threshold').value;
            const enabledEntities = getEnabledEntities();

            if (!inputText.trim() && action !== 'reidentify') {
                alert('Please enter some text first');
                return;
            }

            if (enabledEntities.length === 0 && action !== 'reidentify') {
                alert('Please select at least one PII type to detect');
                return;
            }

            const startTime = performance.now();

            try {
                const response = await fetch('/process', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        text: inputText,
                        action: action,
                        threshold: parseFloat(threshold),
                        enabled_entities: enabledEntities
                    })
                });

                const data = await response.json();
                const endTime = performance.now();

                document.getElementById('outputText').value = data.result;

                // Show stats
                document.getElementById('stats').style.display = 'flex';
                document.getElementById('entitiesFound').textContent = data.entities_found || 0;
                document.getElementById('processingTime').textContent = Math.round(endTime - startTime) + 'ms';

            } catch (error) {
                alert('Error processing text: ' + error.message);
            }
        }

        function clearAll() {
            document.getElementById('inputText').value = '';
            document.getElementById('outputText').value = '';
            document.getElementById('stats').style.display = 'none';
        }

        async function clearMappings() {
            if (!confirm('This will clear all saved PII mappings. Are you sure?')) {
                return;
            }

            try {
                const response = await fetch('/clear_mappings', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                });

                const data = await response.json();
                alert(data.message);
            } catch (error) {
                alert('Error clearing mappings: ' + error.message);
            }
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/health')
def health():
    """Health check endpoint for container orchestration."""
    return jsonify({
        'status': 'healthy',
        'service': 'pii-removal-tool',
        'version': '1.0.0'
    })

@app.route('/process', methods=['POST'])
def process():
    try:
        data = request.json
        text = data.get('text', '')
        action = data.get('action', '')
        threshold = data.get('threshold', 0.5)
        enabled_entities = data.get('enabled_entities', [])

        logger.info(f"Processing request - action: {action}, threshold: {threshold}, entities: {len(enabled_entities)}")

        if action == 'anonymize':
            result, entities_found = anonymize_text(text, threshold, enabled_entities)
        elif action == 'deidentify':
            result, entities_found = deidentify_text(text, threshold, enabled_entities)
        elif action == 'reidentify':
            result, entities_found = reidentify_text(text)
        else:
            result = text
            entities_found = 0

        logger.info(f"Processing complete - entities found: {entities_found}")

        return jsonify({
            'result': result,
            'entities_found': entities_found
        })
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/clear_mappings', methods=['POST'])
def clear_mappings_endpoint():
    try:
        clear_mappings()
        logger.info("Mappings cleared successfully")
        return jsonify({'message': 'Mappings cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing mappings: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("🔒 PII Removal Tool - Production Ready")
    print("=" * 60)
    print("Starting server...")
    print(f"Server will run on port {app.config['PORT']}")
    print("\nFeatures:")
    print("  ✓ Configurable PII type selection")
    print("  ✓ Anonymize - Generic placeholders")
    print("  ✓ De-identify - Reversible numbered placeholders")
    print("  ✓ Re-identify - Restore original values")
    print("  ✓ LastName, FirstName detection")
    print("  ✓ Adjustable confidence threshold")
    print("  ✓ Local processing - no cloud")
    print("\nDefault PII Detection (Australian context):")
    print("  Recommended ON:")
    print("    • Personal: PERSON, EMAIL, PHONE, LOCATION")
    print("    • Financial: AU_TFN, AU_ABN, AU_ACN, AU_MEDICARE,")
    print("                 CREDIT_CARD, IBAN_CODE")
    print("  Situational OFF:")
    print("    • DATE_TIME, ORGANIZATION, URL, IP_ADDRESS, NRP")
    print("\nAustralian-specific recognizers:")
    print("  • AU_TFN, AU_ABN, AU_ACN, AU_MEDICARE (manually loaded)")
    print("  • AU phone numbers via PhoneRecognizer (phonenumbers library)")
    print(f"\nData directory: {app.config['DATA_DIR']}")
    print("=" * 60)
    app.run(host='0.0.0.0', port=app.config['PORT'], debug=app.config['DEBUG'])
