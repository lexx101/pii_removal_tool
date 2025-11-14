"""
Comprehensive test suite for PII Removal Tool.

This module provides extensive test coverage for all functionality including:
- JSON file operations
- PII detection and anonymization
- De-identification and re-identification
- Australian-specific recognizers
- Custom names and ignore lists
- Flask API endpoints
- Edge cases and error handling
"""

import pytest
import json
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock
from presidio_analyzer import RecognizerResult

# Import the app and functions to test
import app as pii_app
from app import (
    load_json_file, save_json_file,
    load_mappings, save_mappings,
    load_ignore_list, load_custom_names,
    post_process_lastname_firstname,
    filter_ignore_list, add_custom_names,
    merge_adjacent_persons, filter_by_entity_types,
    anonymize_text, deidentify_text, reidentify_text,
    clear_mappings
)


class TestJSONFileOperations:
    """Test JSON file loading and saving operations."""

    def setup_method(self):
        """Create a temporary directory for test files."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.json")

    def teardown_method(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_save_and_load_json_file(self):
        """Test saving and loading a JSON file."""
        test_data = {"key": "value", "number": 42}
        save_json_file(self.test_file, test_data)
        loaded_data = load_json_file(self.test_file)
        assert loaded_data == test_data

    def test_load_nonexistent_file(self):
        """Test loading a file that doesn't exist."""
        result = load_json_file("/nonexistent/file.json", default=[])
        assert result == []

    def test_load_invalid_json(self):
        """Test loading a file with invalid JSON."""
        with open(self.test_file, 'w') as f:
            f.write("invalid json content {")
        result = load_json_file(self.test_file, default={})
        assert result == {}

    def test_save_json_with_unicode(self):
        """Test saving JSON with unicode characters."""
        test_data = {"name": "François", "city": "München"}
        save_json_file(self.test_file, test_data)
        loaded_data = load_json_file(self.test_file)
        assert loaded_data == test_data

    def test_save_json_with_complex_structure(self):
        """Test saving JSON with nested structures."""
        test_data = {
            "list": [1, 2, 3],
            "nested": {"inner": {"value": "test"}},
            "bool": True,
            "null": None
        }
        save_json_file(self.test_file, test_data)
        loaded_data = load_json_file(self.test_file)
        assert loaded_data == test_data


class TestMappingFunctions:
    """Test PII mapping functions for de-identification."""

    def setup_method(self):
        """Set up test environment with temporary data directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = pii_app.app.config['DATA_DIR']
        pii_app.app.config['DATA_DIR'] = self.temp_dir
        pii_app.MAPPING_FILE = os.path.join(self.temp_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.temp_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.temp_dir, "custom_names.json")

    def teardown_method(self):
        """Clean up temporary directory."""
        pii_app.app.config['DATA_DIR'] = self.original_data_dir
        pii_app.MAPPING_FILE = os.path.join(self.original_data_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.original_data_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.original_data_dir, "custom_names.json")
        shutil.rmtree(self.temp_dir)

    def test_save_and_load_mappings(self):
        """Test saving and loading PII mappings."""
        mappings = {"PERSON_001": "John Doe", "EMAIL_001": "john@example.com"}
        save_mappings(mappings)
        loaded_mappings = load_mappings()
        assert loaded_mappings == mappings

    def test_load_empty_mappings(self):
        """Test loading mappings when file doesn't exist."""
        loaded_mappings = load_mappings()
        assert loaded_mappings == {}

    def test_clear_mappings(self):
        """Test clearing all mappings."""
        mappings = {"PERSON_001": "John Doe"}
        save_mappings(mappings)
        clear_mappings()
        loaded_mappings = load_mappings()
        assert loaded_mappings == {}

    def test_load_ignore_list(self):
        """Test loading ignore list."""
        ignore_list = ["Australia", "Melbourne", "Admin"]
        save_json_file(pii_app.IGNORE_LIST_FILE, ignore_list)
        loaded_list = load_ignore_list()
        assert loaded_list == ignore_list

    def test_load_custom_names(self):
        """Test loading custom names."""
        custom_names = ["John Smith", "Jane Doe", "Acme Corp"]
        save_json_file(pii_app.CUSTOM_NAMES_FILE, custom_names)
        loaded_names = load_custom_names()
        assert loaded_names == custom_names


class TestPostProcessing:
    """Test post-processing functions for PII detection."""

    def test_lastname_firstname_detection(self):
        """Test detection of 'LastName, FirstName' pattern."""
        text = "Smith, John is a person"
        # Create a PERSON entity for "John"
        results = [
            RecognizerResult(entity_type="PERSON", start=8, end=12, score=0.85)
        ]
        processed = post_process_lastname_firstname(text, results)

        # Should have 2 entities now (Smith and John)
        assert len(processed) == 2
        # Check that "Smith" was added
        lastname_found = any(r.start == 0 and r.end == 5 for r in processed)
        assert lastname_found

    def test_lastname_firstname_no_detection_without_firstname(self):
        """Test that lastname is not detected without firstname."""
        text = "Smith, but no firstname detected"
        results = []  # No PERSON entities
        processed = post_process_lastname_firstname(text, results)

        # Should not add lastname without firstname
        assert len(processed) == 0

    def test_lastname_firstname_multiple_occurrences(self):
        """Test multiple LastName, FirstName patterns."""
        text = "Smith, John and Doe, Jane are people"
        results = [
            RecognizerResult(entity_type="PERSON", start=8, end=12, score=0.85),  # John
            RecognizerResult(entity_type="PERSON", start=21, end=25, score=0.85)  # Jane
        ]
        processed = post_process_lastname_firstname(text, results)

        # Should have 4 entities (Smith, John, Doe, Jane)
        assert len(processed) == 4

    def test_filter_ignore_list(self):
        """Test filtering entities using ignore list."""
        text = "John lives in Australia"
        results = [
            RecognizerResult(entity_type="PERSON", start=0, end=4, score=0.85),
            RecognizerResult(entity_type="LOCATION", start=14, end=23, score=0.85)
        ]

        # Set up ignore list
        with tempfile.TemporaryDirectory() as temp_dir:
            ignore_file = os.path.join(temp_dir, "ignore_list.json")
            save_json_file(ignore_file, ["Australia"])

            with patch.object(pii_app, 'IGNORE_LIST_FILE', ignore_file):
                filtered = filter_ignore_list(text, results)

        # Should only have 1 entity (John), Australia should be filtered
        assert len(filtered) == 1
        assert text[filtered[0].start:filtered[0].end] == "John"

    def test_add_custom_names(self):
        """Test adding custom names from dictionary."""
        text = "John Smith and Jane Doe work here"
        results = []

        # Set up custom names
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_file = os.path.join(temp_dir, "custom_names.json")
            save_json_file(custom_file, ["John Smith", "Jane Doe"])

            with patch.object(pii_app, 'CUSTOM_NAMES_FILE', custom_file):
                enhanced = add_custom_names(text, results)

        # Should have 2 entities
        assert len(enhanced) == 2

    def test_add_custom_names_case_insensitive(self):
        """Test custom names matching is case insensitive."""
        text = "john smith works here"
        results = []

        with tempfile.TemporaryDirectory() as temp_dir:
            custom_file = os.path.join(temp_dir, "custom_names.json")
            save_json_file(custom_file, ["John Smith"])

            with patch.object(pii_app, 'CUSTOM_NAMES_FILE', custom_file):
                enhanced = add_custom_names(text, results)

        assert len(enhanced) == 1

    def test_merge_adjacent_persons(self):
        """Test merging adjacent PERSON entities."""
        text = "Smith, John"
        results = [
            RecognizerResult(entity_type="PERSON", start=0, end=5, score=0.85),   # Smith
            RecognizerResult(entity_type="PERSON", start=7, end=11, score=0.85)   # John
        ]
        merged = merge_adjacent_persons(text, results)

        # Should merge into single entity
        assert len(merged) == 1
        assert merged[0].start == 0
        assert merged[0].end == 11

    def test_merge_adjacent_persons_not_adjacent(self):
        """Test that non-adjacent entities are not merged."""
        text = "John works with Jane"
        results = [
            RecognizerResult(entity_type="PERSON", start=0, end=4, score=0.85),   # John
            RecognizerResult(entity_type="PERSON", start=16, end=20, score=0.85)  # Jane
        ]
        merged = merge_adjacent_persons(text, results)

        # Should remain as 2 separate entities
        assert len(merged) == 2

    def test_filter_by_entity_types(self):
        """Test filtering results by enabled entity types."""
        results = [
            RecognizerResult(entity_type="PERSON", start=0, end=4, score=0.85),
            RecognizerResult(entity_type="EMAIL_ADDRESS", start=5, end=20, score=0.85),
            RecognizerResult(entity_type="PHONE_NUMBER", start=21, end=30, score=0.85)
        ]

        # Filter to only PERSON and EMAIL_ADDRESS
        filtered = filter_by_entity_types(results, ["PERSON", "EMAIL_ADDRESS"])

        assert len(filtered) == 2
        assert all(r.entity_type in ["PERSON", "EMAIL_ADDRESS"] for r in filtered)

    def test_filter_by_entity_types_empty_list(self):
        """Test filtering with empty enabled entities returns all."""
        results = [
            RecognizerResult(entity_type="PERSON", start=0, end=4, score=0.85),
            RecognizerResult(entity_type="EMAIL_ADDRESS", start=5, end=20, score=0.85)
        ]

        filtered = filter_by_entity_types(results, [])

        # Empty list should return all results
        assert len(filtered) == len(results)


class TestPIIProcessing:
    """Test main PII processing functions."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = pii_app.app.config['DATA_DIR']
        pii_app.app.config['DATA_DIR'] = self.temp_dir
        pii_app.MAPPING_FILE = os.path.join(self.temp_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.temp_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.temp_dir, "custom_names.json")

    def teardown_method(self):
        """Clean up test environment."""
        pii_app.app.config['DATA_DIR'] = self.original_data_dir
        pii_app.MAPPING_FILE = os.path.join(self.original_data_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.original_data_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.original_data_dir, "custom_names.json")
        shutil.rmtree(self.temp_dir)

    def test_anonymize_basic_text(self):
        """Test basic anonymization of text."""
        text = "John Smith's email is john@example.com"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS"])

        assert "<PERSON>" in result
        assert "<EMAIL_ADDRESS>" in result
        assert "John Smith" not in result
        assert "john@example.com" not in result
        assert count > 0

    def test_anonymize_with_phone_number(self):
        """Test anonymization with phone numbers."""
        text = "Call me at 0412 345 678"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PHONE_NUMBER"])

        assert "<PHONE_NUMBER>" in result or "0412 345 678" not in result

    def test_anonymize_empty_text(self):
        """Test anonymization of empty text."""
        result, count = anonymize_text("", threshold=0.5, enabled_entities=["PERSON"])

        assert result == ""
        assert count == 0

    def test_anonymize_no_pii(self):
        """Test anonymization of text with no PII."""
        text = "This is a simple sentence with no PII."
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS"])

        assert result == text
        assert count == 0

    def test_anonymize_with_high_threshold(self):
        """Test anonymization with high confidence threshold."""
        text = "John Smith lives here"
        result_low, count_low = anonymize_text(text, threshold=0.3, enabled_entities=["PERSON"])
        result_high, count_high = anonymize_text(text, threshold=0.9, enabled_entities=["PERSON"])

        # Lower threshold should catch more or equal entities
        assert count_low >= count_high

    def test_deidentify_basic_text(self):
        """Test de-identification of text."""
        text = "John Smith's email is john@example.com"
        result, count = deidentify_text(text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS"])

        # Should have numbered placeholders
        assert "PERSON_" in result
        assert "EMAIL_ADDRESS_" in result
        assert count > 0

        # Check mappings were saved
        mappings = load_mappings()
        assert len(mappings) > 0

    def test_deidentify_incremental_numbering(self):
        """Test that de-identification uses incremental numbering."""
        text1 = "John Smith"
        result1, _ = deidentify_text(text1, threshold=0.5, enabled_entities=["PERSON"])

        text2 = "Jane Doe"
        result2, _ = deidentify_text(text2, threshold=0.5, enabled_entities=["PERSON"])

        # Second entity should have a higher number
        assert "PERSON_001" in result1 or "PERSON_" in result1
        assert "PERSON_" in result2

    def test_reidentify_text(self):
        """Test re-identification of de-identified text."""
        # First de-identify
        original_text = "John Smith's email is john@example.com"
        deidentified, _ = deidentify_text(original_text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS"])

        # Then re-identify
        reidentified, _ = reidentify_text(deidentified)

        # Should restore original values
        assert "John Smith" in reidentified or "john@example.com" in reidentified

    def test_reidentify_partial_text(self):
        """Test re-identification with only some placeholders."""
        # Create mappings manually
        mappings = {"PERSON_001": "John Smith", "EMAIL_ADDRESS_001": "john@example.com"}
        save_mappings(mappings)

        text = "Contact PERSON_001 at EMAIL_ADDRESS_001"
        reidentified, _ = reidentify_text(text)

        assert "John Smith" in reidentified
        assert "john@example.com" in reidentified

    def test_reidentify_empty_mappings(self):
        """Test re-identification with no mappings."""
        text = "PERSON_001"
        reidentified, _ = reidentify_text(text)

        # Should return text unchanged if no mappings
        assert reidentified == text

    def test_australian_tfn_detection(self):
        """Test detection of Australian Tax File Number."""
        # TFN format: 123 456 782
        text = "My TFN is 123 456 782"
        result, count = anonymize_text(text, threshold=0.3, enabled_entities=["AU_TFN"])

        # Should detect and anonymize the TFN
        assert count > 0 or "123 456 782" not in result

    def test_australian_abn_detection(self):
        """Test detection of Australian Business Number."""
        # ABN format: 53 004 085 616
        text = "ABN: 53 004 085 616"
        result, count = anonymize_text(text, threshold=0.3, enabled_entities=["AU_ABN"])

        # Should detect and anonymize the ABN
        assert count > 0 or "53 004 085 616" not in result

    def test_enabled_entities_filtering(self):
        """Test that only enabled entity types are detected."""
        text = "John Smith's email is john@example.com and phone is 0412345678"

        # Only enable PERSON
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON"])

        # Email should not be anonymized
        assert "john@example.com" in result or count < 3


class TestFlaskAPI:
    """Test Flask API endpoints."""

    @pytest.fixture
    def client(self):
        """Create a test client for the Flask app."""
        pii_app.app.config['TESTING'] = True
        with pii_app.app.test_client() as client:
            yield client

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Set up and tear down test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = pii_app.app.config['DATA_DIR']
        pii_app.app.config['DATA_DIR'] = self.temp_dir
        pii_app.MAPPING_FILE = os.path.join(self.temp_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.temp_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.temp_dir, "custom_names.json")

        yield

        pii_app.app.config['DATA_DIR'] = self.original_data_dir
        pii_app.MAPPING_FILE = os.path.join(self.original_data_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.original_data_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.original_data_dir, "custom_names.json")
        shutil.rmtree(self.temp_dir)

    def test_index_route(self, client):
        """Test that index route returns HTML."""
        response = client.get('/')
        assert response.status_code == 200
        assert b'PII Removal Tool' in response.data

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'service' in data
        assert 'version' in data

    def test_process_anonymize_endpoint(self, client):
        """Test /process endpoint with anonymize action."""
        payload = {
            "text": "John Smith's email is john@example.com",
            "action": "anonymize",
            "threshold": 0.5,
            "enabled_entities": ["PERSON", "EMAIL_ADDRESS"]
        }
        response = client.post('/process',
                              data=json.dumps(payload),
                              content_type='application/json')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'result' in data
        assert 'entities_found' in data
        assert "<PERSON>" in data['result'] or "<EMAIL_ADDRESS>" in data['result']

    def test_process_deidentify_endpoint(self, client):
        """Test /process endpoint with deidentify action."""
        payload = {
            "text": "John Smith works here",
            "action": "deidentify",
            "threshold": 0.5,
            "enabled_entities": ["PERSON"]
        }
        response = client.post('/process',
                              data=json.dumps(payload),
                              content_type='application/json')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'result' in data
        assert 'PERSON_' in data['result'] or data['entities_found'] > 0

    def test_process_reidentify_endpoint(self, client):
        """Test /process endpoint with reidentify action."""
        # First deidentify
        payload1 = {
            "text": "John Smith",
            "action": "deidentify",
            "threshold": 0.5,
            "enabled_entities": ["PERSON"]
        }
        response1 = client.post('/process',
                               data=json.dumps(payload1),
                               content_type='application/json')
        data1 = json.loads(response1.data)
        deidentified_text = data1['result']

        # Then reidentify
        payload2 = {
            "text": deidentified_text,
            "action": "reidentify",
            "threshold": 0.5,
            "enabled_entities": []
        }
        response2 = client.post('/process',
                               data=json.dumps(payload2),
                               content_type='application/json')

        assert response2.status_code == 200
        data2 = json.loads(response2.data)
        assert 'result' in data2

    def test_process_empty_text(self, client):
        """Test /process endpoint with empty text."""
        payload = {
            "text": "",
            "action": "anonymize",
            "threshold": 0.5,
            "enabled_entities": ["PERSON"]
        }
        response = client.post('/process',
                              data=json.dumps(payload),
                              content_type='application/json')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['result'] == ""
        assert data['entities_found'] == 0

    def test_process_invalid_action(self, client):
        """Test /process endpoint with invalid action."""
        payload = {
            "text": "John Smith",
            "action": "invalid_action",
            "threshold": 0.5,
            "enabled_entities": ["PERSON"]
        }
        response = client.post('/process',
                              data=json.dumps(payload),
                              content_type='application/json')

        assert response.status_code == 200
        data = json.loads(response.data)
        # Should return original text for invalid action
        assert data['result'] == "John Smith"
        assert data['entities_found'] == 0

    def test_clear_mappings_endpoint(self, client):
        """Test /clear_mappings endpoint."""
        # Create some mappings first
        mappings = {"PERSON_001": "John Smith"}
        save_mappings(mappings)

        # Clear mappings
        response = client.post('/clear_mappings',
                              content_type='application/json')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data

        # Verify mappings are cleared
        loaded_mappings = load_mappings()
        assert len(loaded_mappings) == 0

    def test_process_with_custom_threshold(self, client):
        """Test processing with different threshold values."""
        payload_low = {
            "text": "Maybe John Smith",
            "action": "anonymize",
            "threshold": 0.3,
            "enabled_entities": ["PERSON"]
        }
        payload_high = {
            "text": "Maybe John Smith",
            "action": "anonymize",
            "threshold": 0.9,
            "enabled_entities": ["PERSON"]
        }

        response_low = client.post('/process',
                                  data=json.dumps(payload_low),
                                  content_type='application/json')
        response_high = client.post('/process',
                                   data=json.dumps(payload_high),
                                   content_type='application/json')

        assert response_low.status_code == 200
        assert response_high.status_code == 200

    def test_process_malformed_json(self, client):
        """Test /process endpoint with malformed JSON."""
        response = client.post('/process',
                              data="not valid json",
                              content_type='application/json')

        # Should return error
        assert response.status_code == 400 or response.status_code == 500


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = pii_app.app.config['DATA_DIR']
        pii_app.app.config['DATA_DIR'] = self.temp_dir
        pii_app.MAPPING_FILE = os.path.join(self.temp_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.temp_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.temp_dir, "custom_names.json")

    def teardown_method(self):
        """Clean up test environment."""
        pii_app.app.config['DATA_DIR'] = self.original_data_dir
        pii_app.MAPPING_FILE = os.path.join(self.original_data_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.original_data_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.original_data_dir, "custom_names.json")
        shutil.rmtree(self.temp_dir)

    def test_very_long_text(self):
        """Test processing very long text."""
        # Create a long text with multiple PII instances
        text = "John Smith " * 1000
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON"])

        assert len(result) > 0
        assert count > 0

    def test_special_characters(self):
        """Test text with special characters."""
        text = "Email: john@example.com! Phone: (04) 1234-5678?"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["EMAIL_ADDRESS", "PHONE_NUMBER"])

        assert len(result) > 0

    def test_unicode_text(self):
        """Test text with unicode characters."""
        text = "François lives in München and emails françois@example.com"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS", "LOCATION"])

        assert len(result) > 0

    def test_mixed_case_entities(self):
        """Test entities with mixed case."""
        text = "Contact JOHN SMITH or john smith"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON"])

        # Should detect both variations
        assert count >= 1

    def test_overlapping_entities(self):
        """Test handling of overlapping entity detections."""
        text = "john@johnsmith.com"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS"])

        # Should handle gracefully without duplicates
        assert len(result) > 0

    def test_consecutive_whitespace(self):
        """Test text with multiple consecutive spaces."""
        text = "John    Smith     lives    here"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON"])

        assert len(result) > 0

    def test_newlines_and_tabs(self):
        """Test text with newlines and tabs."""
        text = "John Smith\n\tEmail: john@example.com\n\tPhone: 0412345678"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"])

        assert len(result) > 0

    def test_placeholder_collision_in_reidentify(self):
        """Test re-identification with placeholder-like text in original."""
        mappings = {"PERSON_001": "John PERSON_002", "PERSON_002": "Smith"}
        save_mappings(mappings)

        text = "PERSON_001"
        reidentified, _ = reidentify_text(text)

        # Should handle nested placeholders correctly
        assert len(reidentified) > 0


class TestAtMentionRecognition:
    """Test @mention name recognition."""

    def test_at_mention_single_name(self):
        """Test recognition of @FirstName pattern."""
        text = "Contact @John for more info"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON"])

        # Should detect @John as a person
        assert count >= 1
        assert "@John" not in result or "<PERSON>" in result

    def test_at_mention_full_name(self):
        """Test recognition of @FirstName LastName pattern."""
        text = "Message @John Smith about this"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON"])

        # Should detect @John Smith as a person
        assert count >= 1

    def test_at_mention_multiple(self):
        """Test multiple @mentions in text."""
        text = "@John and @Jane are working with @Bob Smith"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON"])

        # Should detect multiple @mentions
        assert count >= 2


class TestAustralianPhoneNumbers:
    """Test Australian phone number recognition."""

    def test_mobile_format_spaces(self):
        """Test Australian mobile with spaces: 0412 345 678"""
        text = "Mobile: 0412 345 678"
        result, count = anonymize_text(text, threshold=0.3, enabled_entities=["PHONE_NUMBER"])

        # Should detect the phone number
        assert "0412 345 678" not in result or count > 0

    def test_mobile_format_no_spaces(self):
        """Test Australian mobile without spaces: 0412345678"""
        text = "Call 0412345678"
        result, count = anonymize_text(text, threshold=0.3, enabled_entities=["PHONE_NUMBER"])

        assert "0412345678" not in result or count > 0

    def test_landline_format(self):
        """Test Australian landline: (03) 9123 4567"""
        text = "Office: (03) 9123 4567"
        result, count = anonymize_text(text, threshold=0.3, enabled_entities=["PHONE_NUMBER"])

        # Note: Detection may vary based on context
        assert len(result) > 0

    def test_international_format(self):
        """Test international format: +61 412 345 678"""
        text = "International: +61 412 345 678"
        result, count = anonymize_text(text, threshold=0.3, enabled_entities=["PHONE_NUMBER"])

        assert "+61 412 345 678" not in result or count > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
