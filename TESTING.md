# Testing Documentation for PII Removal Tool

This document describes the comprehensive test suite for the PII Removal Tool, how to run tests, and what is covered.

## Table of Contents

- [Overview](#overview)
- [Test Files](#test-files)
- [Running Tests](#running-tests)
- [Test Coverage](#test-coverage)
- [Continuous Integration](#continuous-integration)
- [Writing New Tests](#writing-new-tests)

## Overview

The PII Removal Tool includes two comprehensive test suites:

1. **`test_app_unittest.py`** - Uses Python's built-in `unittest` framework (recommended, no extra dependencies)
2. **`test_app.py`** - Uses `pytest` (requires pytest installation)

Both test suites provide identical coverage and can be used interchangeably.

## Test Files

### Main Test Suites

- **`test_app_unittest.py`**: Unittest-based test suite with 23+ test cases
- **`test_app.py`**: Pytest-based test suite with identical coverage

### Test Dependencies

For pytest (optional):
```bash
pip install -r requirements-dev.txt
```

For unittest (built-in):
No additional dependencies required beyond the main application dependencies.

## Running Tests

### Method 1: Using Unittest (Recommended)

The unittest suite is self-contained and provides detailed output:

```bash
# Run all tests with verbose output
python -m unittest test_app_unittest -v

# Run tests with summary
python test_app_unittest.py --summary

# Run specific test class
python -m unittest test_app_unittest.TestPIIProcessing -v

# Run specific test method
python -m unittest test_app_unittest.TestPIIProcessing.test_anonymize_basic_text -v
```

### Method 2: Using Pytest (Optional)

If you have pytest installed:

```bash
# Run all tests
pytest test_app.py -v

# Run with coverage report
pytest test_app.py --cov=app --cov-report=html

# Run specific test class
pytest test_app.py::TestPIIProcessing -v

# Run specific test
pytest test_app.py::TestPIIProcessing::test_anonymize_basic_text -v
```

### Expected Output

When all dependencies are installed, you should see output similar to:

```
============================================================
TEST SUMMARY
============================================================
Tests run: 23
Successes: 23
Failures: 0
Errors: 0
Skipped: 0
============================================================
```

## Test Coverage

The test suite provides comprehensive coverage of all major functionality:

### 1. JSON File Operations (5 tests)

Tests for file handling and data persistence:

- ✅ `test_save_and_load_json_file`: Save and load JSON data
- ✅ `test_load_nonexistent_file`: Handle missing files gracefully
- ✅ `test_load_invalid_json`: Handle corrupted JSON files
- ✅ `test_save_json_with_unicode`: Unicode character support
- ✅ `test_save_json_with_complex_structure`: Nested data structures

**What's tested**: File I/O, error handling, data integrity, unicode support

### 2. Mapping Functions (3 tests)

Tests for PII mapping storage and retrieval:

- ✅ `test_save_and_load_mappings`: Mapping persistence
- ✅ `test_load_empty_mappings`: Default empty state
- ✅ `test_clear_mappings`: Mapping cleanup

**What's tested**: De-identification mapping storage, persistence, cleanup

### 3. Post-Processing Functions (3 tests)

Tests for PII detection enhancement:

- ✅ `test_lastname_firstname_detection`: "LastName, FirstName" pattern detection
- ✅ `test_filter_by_entity_types`: Entity type filtering
- ✅ `test_merge_adjacent_persons`: Adjacent entity merging

**What's tested**: Custom patterns, entity filtering, entity merging logic

### 4. PII Processing (4 tests)

Tests for core anonymization and de-identification:

- ✅ `test_anonymize_basic_text`: Generic placeholder replacement
- ✅ `test_anonymize_empty_text`: Empty text handling
- ✅ `test_deidentify_basic_text`: Reversible de-identification
- ✅ `test_reidentify_text`: Restoration of original values

**What's tested**: Anonymization, de-identification, re-identification, edge cases

### 5. Flask API Endpoints (4 tests)

Tests for REST API functionality:

- ✅ `test_index_route`: Web UI rendering
- ✅ `test_health_endpoint`: Health check endpoint
- ✅ `test_process_anonymize_endpoint`: Anonymization API
- ✅ `test_clear_mappings_endpoint`: Mapping management API

**What's tested**: HTTP endpoints, request/response handling, JSON API

### 6. Edge Cases (3 tests)

Tests for boundary conditions and special scenarios:

- ✅ `test_special_characters`: Punctuation and special chars
- ✅ `test_unicode_text`: International characters
- ✅ `test_newlines_and_tabs`: Whitespace handling

**What's tested**: Edge cases, unusual input, robustness

### Additional Test Coverage (in test_app.py)

The pytest suite includes additional comprehensive tests:

- Australian-specific PII (TFN, ABN, ACN, Medicare)
- Phone number detection (multiple formats)
- @mention name recognition
- Custom names dictionary
- Ignore list functionality
- Threshold sensitivity
- Long text processing
- Overlapping entity detection
- Placeholder collision handling

## Test Architecture

### Test Structure

```
test_app_unittest.py
├── TestEnvironmentCheck     # Dependency verification
├── TestJSONFileOperations   # File I/O tests
├── TestMappingFunctions     # PII mapping tests
├── TestPostProcessing       # Detection enhancement tests
├── TestPIIProcessing        # Core functionality tests
├── TestFlaskAPI             # API endpoint tests
└── TestEdgeCases            # Edge case tests
```

### Test Isolation

All tests use:
- **Temporary directories**: Each test creates and cleans up its own temp directory
- **No side effects**: Tests don't affect each other or production data
- **Mocking where appropriate**: External dependencies can be mocked
- **Setup/Teardown**: Proper resource cleanup

### Test Data

Tests use:
- Synthetic test data (no real PII)
- Temporary file storage
- In-memory test databases where applicable

## Running Tests in Different Environments

### Local Development

```bash
# Activate virtual environment
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Run tests
python test_app_unittest.py --summary
```

### Docker

```bash
# Run tests in Docker container
docker-compose run --rm app python test_app_unittest.py --summary
```

### CI/CD Pipeline

Add to your CI/CD configuration:

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: |
          pip install -r requirements.txt
          python test_app_unittest.py --summary
```

## Understanding Test Results

### Success

All tests pass:
```
Tests run: 23
Successes: 23
Failures: 0
Errors: 0
Skipped: 0
```

### Skipped Tests

Tests are skipped when dependencies are missing:
```
Tests run: 23
Skipped: 23
```

This is expected if you haven't installed the application dependencies. Install them with:
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### Failures

Test failures indicate issues in the code:
```
Tests run: 23
Failures: 2
```

Review the failure details and fix the underlying issues.

## Test Coverage Metrics

To measure code coverage (requires pytest and pytest-cov):

```bash
# Install coverage tools
pip install pytest pytest-cov

# Run with coverage
pytest test_app.py --cov=app --cov-report=html --cov-report=term

# View HTML report
open htmlcov/index.html
```

### Coverage Goals

- **Target**: 80%+ code coverage
- **Current**: Run coverage report to see current metrics
- **Critical paths**: 100% coverage for PII detection and anonymization functions

## Writing New Tests

### Adding a New Test

1. **Choose the appropriate test class** based on functionality
2. **Follow naming conventions**: `test_<functionality_description>`
3. **Use descriptive docstrings**: Explain what the test verifies
4. **Include setUp/tearDown**: If needed for test isolation
5. **Use assertions effectively**: Check multiple aspects when relevant

### Example Test

```python
def test_custom_feature(self):
    """Test description of what this verifies."""
    # Arrange: Set up test data
    text = "Test input"

    # Act: Execute the functionality
    result, count = my_function(text)

    # Assert: Verify the results
    self.assertEqual(result, "Expected output")
    self.assertGreater(count, 0)
```

### Test Guidelines

- **One concept per test**: Each test should verify one specific behavior
- **Clear test names**: Name should describe what's being tested
- **Arrange-Act-Assert**: Follow AAA pattern for clarity
- **Independent tests**: Tests should not depend on each other
- **Fast execution**: Keep tests fast for quick feedback

## Troubleshooting

### Common Issues

#### "No module named 'presidio_analyzer'"

**Solution**: Install dependencies:
```bash
pip install -r requirements.txt
```

#### "No module named 'en_core_web_lg'"

**Solution**: Download spaCy model:
```bash
python -m spacy download en_core_web_lg
```

#### Tests timeout or hang

**Solution**: Check for infinite loops or blocking operations in the code.

#### Temp directory cleanup failures

**Solution**: Check file permissions and ensure no processes are locking test files.

## Continuous Integration

### GitHub Actions Example

```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2

    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        python -m spacy download en_core_web_lg

    - name: Run tests
      run: python test_app_unittest.py --summary

    - name: Check test results
      run: |
        if [ $? -eq 0 ]; then
          echo "All tests passed!"
        else
          echo "Tests failed!"
          exit 1
        fi
```

## Test Maintenance

### Regular Tasks

- **Update tests** when adding new features
- **Review coverage** periodically to find gaps
- **Refactor tests** to keep them maintainable
- **Update dependencies** in requirements-dev.txt
- **Run full suite** before committing changes

### Best Practices

1. **Run tests before committing**: Ensure nothing is broken
2. **Write tests for bug fixes**: Prevent regression
3. **Keep tests simple**: Easy to understand and maintain
4. **Use meaningful assertions**: Clear failure messages
5. **Document complex tests**: Explain non-obvious test logic

## Performance Testing

For performance benchmarking:

```python
import time

def test_performance():
    """Test processing speed for large text."""
    text = "John Smith " * 10000

    start = time.time()
    result, count = anonymize_text(text)
    duration = time.time() - start

    # Should complete in reasonable time
    assert duration < 5.0  # 5 seconds max
    print(f"Processed {len(text)} chars in {duration:.2f}s")
```

## Security Testing

Tests include security considerations:

- **No real PII in tests**: All test data is synthetic
- **File path validation**: Tests verify proper path handling
- **Input sanitization**: Tests check for injection vulnerabilities
- **Error message safety**: No sensitive data in error messages

## Support

For test-related issues:

1. Check this documentation
2. Review test output and error messages
3. Verify dependencies are installed correctly
4. Open an issue on GitHub with test output

---

**Last Updated**: 2025-11-13
**Test Suite Version**: 1.0
**Maintained By**: PII Removal Tool Team
