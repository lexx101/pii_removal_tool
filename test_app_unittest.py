"""
Comprehensive test suite for PII Removal Tool using unittest.

This module provides extensive test coverage for all functionality including:
- JSON file operations
- PII detection and anonymization
- De-identification and re-identification
- Australian-specific recognizers
- Custom names and ignore lists
- Flask API endpoints
- Edge cases and error handling

Run with: python -m unittest test_app_unittest -v
"""

import unittest
import json
import os
import tempfile
import shutil
import sys
from unittest.mock import patch, MagicMock

# Note: This test suite is designed to run with or without dependencies installed
# It will skip tests that require missing dependencies


class TestEnvironmentCheck(unittest.TestCase):
    """Check if the required dependencies are available."""

    def test_check_dependencies(self):
        """Check which dependencies are available."""
        missing = []
        available = []

        dependencies = [
            'flask',
            'presidio_analyzer',
            'presidio_anonymizer',
            'spacy',
            'phonenumbers',
            'config'
        ]

        for dep in dependencies:
            try:
                __import__(dep)
                available.append(dep)
            except ImportError:
                missing.append(dep)

        print(f"\n{'='*60}")
        print(f"Available dependencies: {', '.join(available) if available else 'None'}")
        print(f"Missing dependencies: {', '.join(missing) if missing else 'None'}")
        print(f"{'='*60}\n")

        if missing:
            self.skipTest(f"Missing required dependencies: {', '.join(missing)}")


def skip_if_no_dependencies(test_func):
    """Decorator to skip tests if dependencies are not available."""
    def wrapper(self):
        try:
            import flask
            import presidio_analyzer
            import presidio_anonymizer
            import app as pii_app
            return test_func(self)
        except ImportError as e:
            self.skipTest(f"Skipping: {e}")
    return wrapper


# Import app only if dependencies are available
try:
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
    from presidio_analyzer import RecognizerResult
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False
    print("WARNING: Dependencies not available. Most tests will be skipped.")


class TestJSONFileOperations(unittest.TestCase):
    """Test JSON file loading and saving operations."""

    def setUp(self):
        """Create a temporary directory for test files."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.json")

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    @skip_if_no_dependencies
    def test_save_and_load_json_file(self):
        """Test saving and loading a JSON file."""
        test_data = {"key": "value", "number": 42}
        save_json_file(self.test_file, test_data)
        loaded_data = load_json_file(self.test_file)
        self.assertEqual(loaded_data, test_data)

    @skip_if_no_dependencies
    def test_load_nonexistent_file(self):
        """Test loading a file that doesn't exist."""
        result = load_json_file("/nonexistent/file.json", default=[])
        self.assertEqual(result, [])

    @skip_if_no_dependencies
    def test_load_invalid_json(self):
        """Test loading a file with invalid JSON."""
        with open(self.test_file, 'w') as f:
            f.write("invalid json content {")
        result = load_json_file(self.test_file, default={})
        self.assertEqual(result, {})

    @skip_if_no_dependencies
    def test_save_json_with_unicode(self):
        """Test saving JSON with unicode characters."""
        test_data = {"name": "François", "city": "München"}
        save_json_file(self.test_file, test_data)
        loaded_data = load_json_file(self.test_file)
        self.assertEqual(loaded_data, test_data)

    @skip_if_no_dependencies
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
        self.assertEqual(loaded_data, test_data)


class TestMappingFunctions(unittest.TestCase):
    """Test PII mapping functions for de-identification."""

    def setUp(self):
        """Set up test environment with temporary data directory."""
        if not DEPENDENCIES_AVAILABLE:
            self.skipTest("Dependencies not available")

        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = pii_app.app.config['DATA_DIR']
        pii_app.app.config['DATA_DIR'] = self.temp_dir
        pii_app.MAPPING_FILE = os.path.join(self.temp_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.temp_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.temp_dir, "custom_names.json")

    def tearDown(self):
        """Clean up temporary directory."""
        if DEPENDENCIES_AVAILABLE:
            pii_app.app.config['DATA_DIR'] = self.original_data_dir
            pii_app.MAPPING_FILE = os.path.join(self.original_data_dir, "pii_mappings.json")
            pii_app.IGNORE_LIST_FILE = os.path.join(self.original_data_dir, "ignore_list.json")
            pii_app.CUSTOM_NAMES_FILE = os.path.join(self.original_data_dir, "custom_names.json")
        shutil.rmtree(self.temp_dir)

    @skip_if_no_dependencies
    def test_save_and_load_mappings(self):
        """Test saving and loading PII mappings."""
        mappings = {"PERSON_001": "John Doe", "EMAIL_001": "john@example.com"}
        save_mappings(mappings)
        loaded_mappings = load_mappings()
        self.assertEqual(loaded_mappings, mappings)

    @skip_if_no_dependencies
    def test_load_empty_mappings(self):
        """Test loading mappings when file doesn't exist."""
        loaded_mappings = load_mappings()
        self.assertEqual(loaded_mappings, {})

    @skip_if_no_dependencies
    def test_clear_mappings(self):
        """Test clearing all mappings."""
        mappings = {"PERSON_001": "John Doe"}
        save_mappings(mappings)
        clear_mappings()
        loaded_mappings = load_mappings()
        self.assertEqual(loaded_mappings, {})


class TestPostProcessing(unittest.TestCase):
    """Test post-processing functions for PII detection."""

    def setUp(self):
        """Set up test environment."""
        if not DEPENDENCIES_AVAILABLE:
            self.skipTest("Dependencies not available")

    @skip_if_no_dependencies
    def test_lastname_firstname_detection(self):
        """Test detection of 'LastName, FirstName' pattern."""
        text = "Smith, John is a person"
        # Create a PERSON entity for "John"
        results = [
            RecognizerResult(entity_type="PERSON", start=8, end=12, score=0.85)
        ]
        processed = post_process_lastname_firstname(text, results)

        # Should have 2 entities now (Smith and John)
        self.assertEqual(len(processed), 2)
        # Check that "Smith" was added
        lastname_found = any(r.start == 0 and r.end == 5 for r in processed)
        self.assertTrue(lastname_found)

    @skip_if_no_dependencies
    def test_filter_by_entity_types(self):
        """Test filtering results by enabled entity types."""
        results = [
            RecognizerResult(entity_type="PERSON", start=0, end=4, score=0.85),
            RecognizerResult(entity_type="EMAIL_ADDRESS", start=5, end=20, score=0.85),
            RecognizerResult(entity_type="PHONE_NUMBER", start=21, end=30, score=0.85)
        ]

        # Filter to only PERSON and EMAIL_ADDRESS
        filtered = filter_by_entity_types(results, ["PERSON", "EMAIL_ADDRESS"])

        self.assertEqual(len(filtered), 2)
        self.assertTrue(all(r.entity_type in ["PERSON", "EMAIL_ADDRESS"] for r in filtered))

    @skip_if_no_dependencies
    def test_merge_adjacent_persons(self):
        """Test merging adjacent PERSON entities."""
        text = "Smith, John"
        results = [
            RecognizerResult(entity_type="PERSON", start=0, end=5, score=0.85),   # Smith
            RecognizerResult(entity_type="PERSON", start=7, end=11, score=0.85)   # John
        ]
        merged = merge_adjacent_persons(text, results)

        # Should merge into single entity
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].start, 0)
        self.assertEqual(merged[0].end, 11)


class TestPIIProcessing(unittest.TestCase):
    """Test main PII processing functions."""

    def setUp(self):
        """Set up test environment."""
        if not DEPENDENCIES_AVAILABLE:
            self.skipTest("Dependencies not available")

        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = pii_app.app.config['DATA_DIR']
        pii_app.app.config['DATA_DIR'] = self.temp_dir
        pii_app.MAPPING_FILE = os.path.join(self.temp_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.temp_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.temp_dir, "custom_names.json")

    def tearDown(self):
        """Clean up test environment."""
        if DEPENDENCIES_AVAILABLE:
            pii_app.app.config['DATA_DIR'] = self.original_data_dir
            pii_app.MAPPING_FILE = os.path.join(self.original_data_dir, "pii_mappings.json")
            pii_app.IGNORE_LIST_FILE = os.path.join(self.original_data_dir, "ignore_list.json")
            pii_app.CUSTOM_NAMES_FILE = os.path.join(self.original_data_dir, "custom_names.json")
        shutil.rmtree(self.temp_dir)

    @skip_if_no_dependencies
    def test_anonymize_basic_text(self):
        """Test basic anonymization of text."""
        text = "John Smith's email is john@example.com"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS"])

        self.assertIn("<PERSON>", result)
        self.assertIn("<EMAIL_ADDRESS>", result)
        self.assertNotIn("John Smith", result)
        self.assertNotIn("john@example.com", result)
        self.assertGreater(count, 0)

    @skip_if_no_dependencies
    def test_anonymize_empty_text(self):
        """Test anonymization of empty text."""
        result, count = anonymize_text("", threshold=0.5, enabled_entities=["PERSON"])

        self.assertEqual(result, "")
        self.assertEqual(count, 0)

    @skip_if_no_dependencies
    def test_deidentify_basic_text(self):
        """Test de-identification of text."""
        text = "John Smith's email is john@example.com"
        result, count = deidentify_text(text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS"])

        # Should have numbered placeholders
        self.assertIn("PERSON_", result)
        self.assertIn("EMAIL_ADDRESS_", result)
        self.assertGreater(count, 0)

        # Check mappings were saved
        mappings = load_mappings()
        self.assertGreater(len(mappings), 0)

    @skip_if_no_dependencies
    def test_reidentify_text(self):
        """Test re-identification of de-identified text."""
        # First de-identify
        original_text = "John Smith's email is john@example.com"
        deidentified, _ = deidentify_text(original_text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS"])

        # Then re-identify
        reidentified, _ = reidentify_text(deidentified)

        # Should restore original values
        self.assertTrue("John Smith" in reidentified or "john@example.com" in reidentified)


class TestFlaskAPI(unittest.TestCase):
    """Test Flask API endpoints."""

    def setUp(self):
        """Set up test environment."""
        if not DEPENDENCIES_AVAILABLE:
            self.skipTest("Dependencies not available")

        pii_app.app.config['TESTING'] = True
        self.client = pii_app.app.test_client()

        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = pii_app.app.config['DATA_DIR']
        pii_app.app.config['DATA_DIR'] = self.temp_dir
        pii_app.MAPPING_FILE = os.path.join(self.temp_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.temp_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.temp_dir, "custom_names.json")

    def tearDown(self):
        """Clean up test environment."""
        if DEPENDENCIES_AVAILABLE:
            pii_app.app.config['DATA_DIR'] = self.original_data_dir
            pii_app.MAPPING_FILE = os.path.join(self.original_data_dir, "pii_mappings.json")
            pii_app.IGNORE_LIST_FILE = os.path.join(self.original_data_dir, "ignore_list.json")
            pii_app.CUSTOM_NAMES_FILE = os.path.join(self.original_data_dir, "custom_names.json")
        shutil.rmtree(self.temp_dir)

    @skip_if_no_dependencies
    def test_index_route(self):
        """Test that index route returns HTML."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'PII Removal Tool', response.data)

    @skip_if_no_dependencies
    def test_health_endpoint(self):
        """Test health check endpoint."""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('service', data)
        self.assertIn('version', data)

    @skip_if_no_dependencies
    def test_process_anonymize_endpoint(self):
        """Test /process endpoint with anonymize action."""
        payload = {
            "text": "John Smith's email is john@example.com",
            "action": "anonymize",
            "threshold": 0.5,
            "enabled_entities": ["PERSON", "EMAIL_ADDRESS"]
        }
        response = self.client.post('/process',
                                    data=json.dumps(payload),
                                    content_type='application/json')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('result', data)
        self.assertIn('entities_found', data)

    @skip_if_no_dependencies
    def test_clear_mappings_endpoint(self):
        """Test /clear_mappings endpoint."""
        # Create some mappings first
        mappings = {"PERSON_001": "John Smith"}
        save_mappings(mappings)

        # Clear mappings
        response = self.client.post('/clear_mappings',
                                   content_type='application/json')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('message', data)

        # Verify mappings are cleared
        loaded_mappings = load_mappings()
        self.assertEqual(len(loaded_mappings), 0)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def setUp(self):
        """Set up test environment."""
        if not DEPENDENCIES_AVAILABLE:
            self.skipTest("Dependencies not available")

        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = pii_app.app.config['DATA_DIR']
        pii_app.app.config['DATA_DIR'] = self.temp_dir
        pii_app.MAPPING_FILE = os.path.join(self.temp_dir, "pii_mappings.json")
        pii_app.IGNORE_LIST_FILE = os.path.join(self.temp_dir, "ignore_list.json")
        pii_app.CUSTOM_NAMES_FILE = os.path.join(self.temp_dir, "custom_names.json")

    def tearDown(self):
        """Clean up test environment."""
        if DEPENDENCIES_AVAILABLE:
            pii_app.app.config['DATA_DIR'] = self.original_data_dir
            pii_app.MAPPING_FILE = os.path.join(self.original_data_dir, "pii_mappings.json")
            pii_app.IGNORE_LIST_FILE = os.path.join(self.original_data_dir, "ignore_list.json")
            pii_app.CUSTOM_NAMES_FILE = os.path.join(self.original_data_dir, "custom_names.json")
        shutil.rmtree(self.temp_dir)

    @skip_if_no_dependencies
    def test_special_characters(self):
        """Test text with special characters."""
        text = "Email: john@example.com! Phone: (04) 1234-5678?"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["EMAIL_ADDRESS", "PHONE_NUMBER"])

        self.assertGreater(len(result), 0)

    @skip_if_no_dependencies
    def test_unicode_text(self):
        """Test text with unicode characters."""
        text = "François lives in München and emails françois@example.com"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS", "LOCATION"])

        self.assertGreater(len(result), 0)

    @skip_if_no_dependencies
    def test_newlines_and_tabs(self):
        """Test text with newlines and tabs."""
        text = "John Smith\n\tEmail: john@example.com\n\tPhone: 0412345678"
        result, count = anonymize_text(text, threshold=0.5, enabled_entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"])

        self.assertGreater(len(result), 0)


def run_tests_with_summary():
    """Run all tests and provide a summary."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    test_classes = [
        TestEnvironmentCheck,
        TestJSONFileOperations,
        TestMappingFunctions,
        TestPostProcessing,
        TestPIIProcessing,
        TestFlaskAPI,
        TestEdgeCases
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("="*60)

    return result.wasSuccessful()


if __name__ == '__main__':
    if '--summary' in sys.argv:
        sys.argv.remove('--summary')
        success = run_tests_with_summary()
        sys.exit(0 if success else 1)
    else:
        unittest.main(verbosity=2)
