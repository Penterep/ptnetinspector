"""Tests for CSV helper functions."""
import pytest
import tempfile
import csv
from pathlib import Path
from unittest.mock import patch, Mock
from ptnetinspector.utils.csv_helpers import (
    has_additional_data,
    sort_csv,
    remove_duplicates_from_csv,
)


class TestCSVHelpers:
    """Test CSV helper functions."""

    def test_has_additional_data_with_data(self):
        """Test has_additional_data returns True when CSV has data."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            writer = csv.writer(f)
            writer.writerow(['MAC', 'IP'])
            writer.writerow(['00:11:22:33:44:55', '192.168.1.100'])
            temp_path = f.name
        
        try:
            assert has_additional_data(temp_path) is True
        finally:
            Path(temp_path).unlink()

    def test_has_additional_data_without_data(self):
        """Test has_additional_data returns False when CSV only has header."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            writer = csv.writer(f)
            writer.writerow(['MAC', 'IP'])
            temp_path = f.name
        
        try:
            assert has_additional_data(temp_path) is False
        finally:
            Path(temp_path).unlink()

    def test_has_additional_data_empty_file(self):
        """Test has_additional_data returns False for empty file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            temp_path = f.name
        
        try:
            assert has_additional_data(temp_path) is False
        finally:
            Path(temp_path).unlink()

    def test_sort_csv(self):
        """Test sorting CSV by MAC address."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as input_f:
            writer = csv.DictWriter(input_f, fieldnames=['src MAC', 'source IP'])
            writer.writeheader()
            writer.writerow({'src MAC': 'aa:bb:cc:dd:ee:ff', 'source IP': '192.168.1.1'})
            writer.writerow({'src MAC': 'aa:bb:cc:dd:ee:ff', 'source IP': '192.168.1.2'})
            writer.writerow({'src MAC': '00:11:22:33:44:55', 'source IP': '10.0.0.1'})
            input_path = input_f.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as output_f:
            output_path = output_f.name
        
        try:
            sort_csv(input_path, output_path)
            
            with open(output_path, 'r') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
                # Check that MACs are grouped
                assert len(rows) > 0
                assert 'MAC' in rows[0]
                assert 'IP' in rows[0]
        finally:
            Path(input_path).unlink()
            Path(output_path).unlink()

    def test_remove_duplicates_from_csv(self):
        """Test removing duplicate rows from CSV."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            writer = csv.DictWriter(f, fieldnames=['MAC', 'IP'])
            writer.writeheader()
            writer.writerow({'MAC': '00:11:22:33:44:55', 'IP': '192.168.1.1'})
            writer.writerow({'MAC': '00:11:22:33:44:55', 'IP': '192.168.1.1'})  # Duplicate
            writer.writerow({'MAC': 'aa:bb:cc:dd:ee:ff', 'IP': '10.0.0.1'})
            temp_path = f.name
        
        try:
            remove_duplicates_from_csv(temp_path)
            
            with open(temp_path, 'r') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
                assert len(rows) == 2  # Should have only 2 unique rows
        finally:
            Path(temp_path).unlink()
