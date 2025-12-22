"""Paths and per-interface directories used by ptnetinspector.

Provides helpers to compute output and tmp directories, scoped by the current
interface context, as well as convenience accessors used across the app.
"""
import os
from pathlib import Path
from ptlibs.app_dirs import AppDirs

# Module-level context for current interface (set by main.py)
_current_interface: str | None = None

def set_current_interface(interface: str | None) -> None:
    """Set the current interface context for tmp file operations."""
    global _current_interface
    _current_interface = interface

def get_current_interface() -> str | None:
    """Get the current interface context."""
    return _current_interface

def get_output_dir(base_path: str | None = None) -> Path:
    """
    Get the output directory path for ptnetinspector.
    Creates the directory if it doesn't exist.

    Args:
        base_path (str | None): Custom base path. Defaults to AppDirs("ptnetinspector").get_data_dir()

    Returns:
        Path: Path to the output directory
    """
    if base_path is None:
        output_dir = Path(AppDirs("ptnetinspector").get_data_dir())
    else:
        output_dir = Path(base_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def get_tmp_path(interface: str | None = None) -> Path:
    """
    Get the temporary directory path for ptnetinspector.
    Creates the directory if it doesn't exist.
    
    Args:
        interface (str | None): Network interface name. If provided, tmp files are stored in tmp/<interface>/.
                               If None, uses the module-level _current_interface if set, otherwise defaults to tmp/ root.
    
    Returns:
        Path: Path to .../tmp/ or .../tmp/<interface>/ if interface is provided or set in context
    """
    tmp_base = get_output_dir() / 'tmp'
    
    iface = interface or _current_interface
    if iface:
        tmp_dir = tmp_base / iface
    else:
        tmp_dir = tmp_base
    
    tmp_dir.mkdir(parents=True, exist_ok=True)
    return tmp_dir

def del_tmp_path(interface: str | None = None) -> None:
    """
    Delete all files in the tmp directory (or interface-specific tmp subdirectory).
    
    Args:
        interface (str | None): Network interface name. If provided, deletes only that interface's tmp folder.
                               If None, uses _current_interface if set.
    
    Output:
        None
    """
    iface = interface or _current_interface
    tmp_dir = get_tmp_path(iface)
    if tmp_dir.exists():
        file_list = os.listdir(tmp_dir)
        for file_name in file_list:
            file_path = os.path.join(tmp_dir, file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
            
def get_csv_path(filename: str, interface: str | None = None) -> Path:
    """
    Get the full path for a CSV file in the tmp directory.
    
    Args:
        filename (str): Name of the CSV file
        interface (str | None): Network interface name. If provided, retrieves from tmp/<interface>/ folder.
                               If None, uses _current_interface if set.
        
    Returns:
        Path: Full path to the CSV file in tmp directory (or interface-specific tmp directory)
    """
    iface = interface or _current_interface
    return get_tmp_path(iface) / filename
