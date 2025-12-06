"""Pytest configuration and fixtures."""
import pytest
import tempfile
import shutil
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    tmp_dir = tempfile.mkdtemp()
    yield Path(tmp_dir)
    shutil.rmtree(tmp_dir)


@pytest.fixture
def sample_csv_file(temp_dir):
    """Create a sample CSV file for testing."""
    csv_path = temp_dir / "test.csv"
    csv_path.write_text("MAC,IP\n00:11:22:33:44:55,192.168.1.1\n")
    return csv_path


@pytest.fixture
def mock_interface():
    """Mock interface name for testing."""
    return "eth0"
