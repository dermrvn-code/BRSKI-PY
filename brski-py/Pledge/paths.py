import os
import sys


def set_parent_dir(filepath: str) -> tuple[str, str]:
    """
    Sets the parent directory of the given file path to the system path.

    Args:
        filepath (str): The file path.

    Returns:
        Tuple:
        - str: The directory of the given file path.
        - str: The parent directory of the given file path.
    """
    # Add parent directory to path
    script_dir = os.path.dirname(os.path.abspath(filepath))
    parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
    sys.path.append(parent_dir)

    return script_dir, parent_dir
