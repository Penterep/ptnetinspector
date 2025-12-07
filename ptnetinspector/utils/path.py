import os
from pathlib import Path
from ptlibs.app_dirs import AppDirs

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


def get_tmp_path() -> Path:
    """
    Get the temporary directory path for ptnetinspector.
    Creates the directory if it doesn't exist.
    
    Returns:
        Path: Path to .../tmp/
    """
    tmp_dir = get_output_dir() / 'tmp'
    tmp_dir.mkdir(parents=True, exist_ok=True)
    return tmp_dir

def del_tmp_path() -> None:
    """
    Delete all files in the tmp directory.
    
    Output:
        None
    """
    tmp_dir = get_tmp_path()
    file_list = os.listdir(tmp_dir)
    for file_name in file_list:
        file_path = os.path.join(tmp_dir, file_name)
        if os.path.isfile(file_path):
            os.remove(file_path)
            
def get_csv_path(filename: str) -> Path:
    """
    Get the full path for a CSV file in the tmp directory.
    
    Args:
        filename (str): Name of the CSV file
        
    Returns:
        Path: Full path to the CSV file in tmp directory
    """
    return get_tmp_path() / filename
