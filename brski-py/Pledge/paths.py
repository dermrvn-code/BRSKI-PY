import os
import sys

cert_file_path = "certs/cert_pledge.crt"
key_file_path = "certs/cert_private_pledge.key"
passphrase_file_path = "certs/passphrase_pledge.txt"


def set_parent_dir(filepath: str) -> tuple[str, str]:
    """
    Sets the parent directory of the given file path to the system path.

    Args:
        filepath (str): The file path.

    Returns:
        script_dir (str): The directory of the given file path.
        parent_dir (str): The parent directory of the given file path.
    """
    # Add parent directory to path
    script_dir = os.path.dirname(os.path.abspath(filepath))
    parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
    sys.path.append(parent_dir)

    return script_dir, parent_dir
