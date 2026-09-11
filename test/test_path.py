"""Tests for path utility functions."""
import pytest
from pathlib import Path
from unittest.mock import patch, Mock
from ptnetinspector.utils.path import get_tmp_path, get_csv_path, get_output_dir


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

    def test_prefers_repo_local_output_dir_when_project_tmp_exists(self, tmp_path):
        project_root = tmp_path / "repo"
        project_root.mkdir(parents=True)
        (project_root / "pyproject.toml").write_text("[project]\nname='ptnetinspector'\n", encoding="utf-8")
        (project_root / "ptnetinspector" / "output" / "tmp").mkdir(parents=True)

        with patch("ptnetinspector.utils.path.Path.cwd", return_value=project_root):
            output_dir = get_output_dir()

        assert output_dir == project_root / "ptnetinspector" / "output"

    def test_falls_back_to_appdirs_outside_project_tree(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        app_dir = tmp_path / "appdata"

        with patch("ptnetinspector.utils.path.Path.cwd", return_value=outside), \
             patch("ptnetinspector.utils.path.AppDirs") as mock_appdirs:
            mock_appdirs.return_value.get_data_dir.return_value = str(app_dir)
            output_dir = get_output_dir()

        assert output_dir == app_dir

    def test_repo_local_mode_uses_tmp_root_even_with_interface(self, tmp_path):
        project_root = tmp_path / "repo"
        project_root.mkdir(parents=True)
        (project_root / "pyproject.toml").write_text("[project]\nname='ptnetinspector'\n", encoding="utf-8")
        (project_root / "ptnetinspector" / "output" / "tmp").mkdir(parents=True)

        with patch("ptnetinspector.utils.path.Path.cwd", return_value=project_root):
            tmp_dir = get_tmp_path("eth0")

        assert tmp_dir == project_root / "ptnetinspector" / "output" / "tmp"

    def test_appdirs_mode_keeps_interface_scoped_tmp(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        app_dir = tmp_path / "appdata"

        with patch("ptnetinspector.utils.path.Path.cwd", return_value=outside), \
             patch("ptnetinspector.utils.path.AppDirs") as mock_appdirs:
            mock_appdirs.return_value.get_data_dir.return_value = str(app_dir)
            tmp_dir = get_tmp_path("eth0")

        assert tmp_dir == app_dir / "tmp" / "eth0"
