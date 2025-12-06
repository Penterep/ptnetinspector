"""Tests for path utility functions."""
import pytest
from pathlib import Path
from unittest.mock import patch, Mock
from ptnetinspector.utils.path import get_tmp_path, get_csv_path


class TestPathUtils:
    """Test path utility functions."""

    def test_get_tmp_path_returns_path(self):
        """Test that get_tmp_path returns a Path object."""
        tmp_path = get_tmp_path()
        assert isinstance(tmp_path, Path)
        assert tmp_path.name == 'tmp'

    def test_get_csv_path_returns_path(self):
        """Test that get_csv_path returns a Path object."""
        csv_path = get_csv_path('test.csv')
        assert isinstance(csv_path, Path)
        assert csv_path.name == 'test.csv'
        assert 'tmp' in str(csv_path)

    def test_get_csv_path_different_files(self):
        """Test getting paths for different CSV files."""
        path1 = get_csv_path('addresses.csv')
        path2 = get_csv_path('routers.csv')
        
        assert path1 != path2
        assert path1.name == 'addresses.csv'
        assert path2.name == 'routers.csv'
