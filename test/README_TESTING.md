# PTNetInspector Testing Guide

## Overview

This guide covers the three levels of testing in the ptnetinspector project:

1. **Unit Tests** - Test individual functions in isolation
2. **Integration Tests** - Test components working together
3. **End-to-End Tests** - Test complete tool workflows

## Test Files Structure

```
test/
├── test_ip_utils.py           # Unit tests for IP utility functions
├── test_interface.py           # Unit tests for Interface class
├── test_csv_helpers.py         # Unit tests for CSV operations
├── test_cli.py                 # Unit tests for CLI parsing
├── test_path.py                # Unit tests for path utilities
├── test_integration.py         # Integration tests for components
├── test_end_to_end.py         # End-to-end tests for complete workflows
├── conftest.py                 # Pytest fixtures and configuration
├── requirements-test.txt       # Testing dependencies
└── README_TESTING.md          # This file
```

## Running Tests

### Install Dependencies

```bash
cd /home/kali/Documents/ptnetinspector
pip install -r test/requirements-test.txt
```

### Run All Tests

```bash
# Run all tests
pytest test/ -v

# Run with coverage report
pytest test/ --cov=ptnetinspector --cov-report=html

# Run with detailed output
pytest test/ -vv -s
```

### Run Specific Test Levels

```bash
# Unit tests only
pytest test/test_ip_utils.py test/test_interface.py test/test_csv_helpers.py test/test_cli.py test/test_path.py -v

# Integration tests only
pytest test/test_integration.py -v

# End-to-end tests only
pytest test/test_end_to_end.py -v
```

### Run Specific Test Classes

```bash
# Test a specific class
pytest test/test_ip_utils.py::TestIPv4Validation -v

# Test a specific method
pytest test/test_ip_utils.py::TestIPv4Validation::test_valid_ipv4 -v
```

### Run with Coverage Report

```bash
# Generate HTML coverage report
pytest test/ --cov=ptnetinspector --cov-report=html

# View coverage in terminal
pytest test/ --cov=ptnetinspector --cov-report=term-missing

# Generate XML for CI/CD
pytest test/ --cov=ptnetinspector --cov-report=xml
```

## Test Categories

### 1. Unit Tests

**Location:** `test_ip_utils.py`, `test_interface.py`, `test_csv_helpers.py`, `test_cli.py`, `test_path.py`

**Purpose:** Test individual functions and methods in isolation

**Key Features:**
- Fast execution (< 1 second)
- No external dependencies (use mocking)
- Test single responsibility
- High code coverage

**Example:**
```python
def test_valid_ipv4(self):
    assert is_valid_ipv4("192.168.1.1") is True
    assert is_valid_ipv4("256.1.1.1") is False
```

### 2. Integration Tests

**Location:** `test_integration.py`

**Purpose:** Test components working together

**Key Features:**
- Test CSV creation and data flow
- Test interface operations with mocking
- Test parameter processing
- Test vulnerability detection

**Example:**
```python
def test_create_and_verify_csv_files(self):
    create_csv()
    # Verify all CSV files were created with proper headers
    assert (tmp_dir / 'packets.csv').exists()
```

### 3. End-to-End Tests

**Location:** `test_end_to_end.py`

**Purpose:** Test complete tool workflows with different options

**Key Features:**
- Test passive scan flow
- Test active scan flow
- Test aggressive scan flow
- Test multiple scan modes combined
- Test JSON output generation
- Test output detail levels (more, less, default)
- Test IPv4/IPv6 filtering
- Test error handling

**Example:**
```python
@patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-d', '5'])
def test_passive_scan_execution_flow(self):
    args = parse_args()
    assert args.t == ['p']
    assert args.interface == 'eth0'
```

## Mocking Strategy

### Why Mock?

- Avoid requiring root privileges
- Avoid needing real network interfaces
- Avoid slow packet sniffing operations
- Avoid file system dependencies
- Make tests fast and reliable

### Common Mocking Patterns

```python
# Mock network interfaces
@patch('netifaces.interfaces', return_value=['eth0', 'lo'])

# Mock subprocess calls
@patch('subprocess.run')
@patch('subprocess.check_output')

# Mock file paths
@patch('ptnetinspector.utils.path.get_csv_path')

# Mock Scapy operations
@patch('ptnetinspector.sniff.Sniff.run_normal_mode')

# Mock CLI arguments
@patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0'])
```

## Coverage Goals

| Component | Target Coverage |
|-----------|-----------------|
| ip_utils.py | 95%+ |
| interface.py | 90%+ |
| csv_helpers.py | 95%+ |
| cli.py | 85%+ |
| path.py | 100% |
| **Overall** | **90%+** |

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - run: pip install -r requirements.txt
      - run: pip install -r test/requirements-test.txt
      - run: pytest test/ --cov=ptnetinspector --cov-report=xml
      - uses: codecov/codecov-action@v2
```

## Writing New Tests

### Best Practices

1. **Use descriptive names**: `test_passive_scan_with_custom_duration`
2. **One assertion per test** (or related assertions)
3. **Mock external dependencies**: network, files, processes
4. **Use fixtures** from `conftest.py`
5. **Test both success and failure cases**

### Template

```python
class TestNewFeature:
    """Test description."""
    
    @patch('external_dependency')
    def test_feature_works(self, mock_dep):
        """Test specific behavior."""
        # Arrange
        mock_dep.return_value = expected_value
        
        # Act
        result = function_to_test()
        
        # Assert
        assert result == expected_value
        mock_dep.assert_called_once()
```

## Troubleshooting

### Test fails with "No such file or directory"

**Solution:** Tests use mocking. If a test tries to access real files, add mock patches.

```python
@patch('ptnetinspector.utils.path.get_csv_path')
def test_feature(self, mock_csv):
    mock_csv.return_value = '/tmp/test.csv'
```

### Test fails with "Permission denied"

**Solution:** Most tests should be mocked to avoid requiring sudo. Check for subprocess calls that need mocking.

```python
@patch('subprocess.run')
def test_feature(self, mock_run):
    mock_run.return_value = Mock(returncode=0)
```

### Test passes locally but fails in CI/CD

**Solution:** Check for:
- Hard-coded paths (use temp directories)
- Timezone dependencies (use mocking)
- System-specific behavior (mock system calls)

## Test Execution Checklist

Before pushing code:

- [ ] All unit tests pass: `pytest test/test_*.py -v`
- [ ] All integration tests pass: `pytest test/test_integration.py -v`
- [ ] All end-to-end tests pass: `pytest test/test_end_to_end.py -v`
- [ ] Coverage is above 90%: `pytest test/ --cov=ptnetinspector --cov-report=term-missing`
- [ ] No warnings: `pytest test/ -W error`
- [ ] Code follows style: Code review

## Performance Benchmarks

Expected test execution times:

```
Unit Tests:         < 2 seconds
Integration Tests:  < 5 seconds
End-to-End Tests:   < 10 seconds
Full Suite:         < 20 seconds
With Coverage:      < 30 seconds
```

## Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [unittest.mock Documentation](https://docs.python.org/3/library/unittest.mock.html)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
