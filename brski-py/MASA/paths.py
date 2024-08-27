import os
import sys

cert_file_path = "certs/cert_masa.crt"
key_file_path = "certs/cert_private_masa.key"
public_key_file_path = "certs/cert_public_masa.key"
passphrase_file_path = "certs/passphrase_masa.txt"

log_folder = "log"
global_log_file = f"{log_folder}/masa.log"
logs_folder = f"{log_folder}/pledgelogs"
auditlog_folder = f"{log_folder}/auditlogs"


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
