"""Tests for target-scan code filtering (-ts argument)."""
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from ptnetinspector.utils.cli import _validate_target_codes
from ptnetinspector.send.send import IPMode


class TestTargetCodeValidation:
    """Test target vulnerability code filtering."""

    def test_validate_target_codes_all_valid(self):
        """Test validation with all valid codes."""
        target_codes = ["PTV-NET-IDENT-MDNS-PTR", "PTV-NET-IDENT-LLMNR-PTR"]
        list_error = []
        list_warning = []
        
        result = _validate_target_codes(target_codes, ["a"], IPMode(True, True), list_error, list_warning)
        
        assert result is not None
        assert "PTV-NET-IDENT-MDNS-PTR" in result
        assert "PTV-NET-IDENT-LLMNR-PTR" in result
        assert len(list_error) == 0
        # Some warnings might exist but not about validation

    def test_validate_target_codes_mixed_valid_invalid(self):
        """Test validation with mix of valid and invalid codes."""
        target_codes = ["PTV-NET-IDENT-MDNS-PTR", "INVALID-CODE-XYZ"]
        list_error = []
        list_warning = []
        
        result = _validate_target_codes(target_codes, ["a"], IPMode(True, True), list_error, list_warning)
        assert result is None
        assert len(list_error) >= 1
        assert any("Unknown target vulnerability code" in err or "Unknown target vulnerability code" in err for err in list_error)

    def test_validate_target_codes_all_invalid(self):
        """Test validation with all invalid codes."""
        target_codes = ["INVALID-CODE-1", "INVALID-CODE-2"]
        list_error = []
        list_warning = []
        
        result = _validate_target_codes(target_codes, ["a"], IPMode(True, True), list_error, list_warning)
        assert result is None
        assert len(list_error) >= 1
        assert any("Unknown target vulnerability code" in err or "Unknown target vulnerability code" in err for err in list_error)

    def test_validate_target_codes_empty(self):
        """Test validation with empty target codes."""
        target_codes = []
        list_error = []
        list_warning = []
        
        result = _validate_target_codes(target_codes, ["a"], IPMode(True, True), list_error, list_warning)
        
        assert result is None

    def test_validate_target_codes_none(self):
        """Test validation with None target codes."""
        target_codes = None
        list_error = []
        list_warning = []
        
        result = _validate_target_codes(target_codes, ["a"], IPMode(True, True), list_error, list_warning)
        
        assert result is None

    def test_validate_target_codes_case_insensitive(self):
        """Test that code validation is case-insensitive."""
        target_codes = ["ptv-net-ident-mdns-ptr", "PTV-NET-IDENT-LLMNR-PTR"]
        list_error = []
        list_warning = []
        
        result = _validate_target_codes(target_codes, ["a"], IPMode(True, True), list_error, list_warning)
        
        assert result is not None
        # Both should be uppercase in result
        assert "PTV-NET-IDENT-MDNS-PTR" in result
        assert "PTV-NET-IDENT-LLMNR-PTR" in result
