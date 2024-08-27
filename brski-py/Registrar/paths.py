import os
import sys

server_cert_file_path = "certs/server/cert_registrar_server.crt"
server_key_file_path = "certs/server/cert_private_registrar_server.key"
server_passphrase_file_path = "certs/server/passphrase_registrar_server.txt"

client_cert_file_path = "certs/client/cert_registrar_client.crt"
client_key_file_path = "certs/client/cert_private_registrar_client.key"
client_passphrase_file_path = "certs/client/passphrase_registrar_client.txt"

log_folder = "log"
global_log_file = f"{log_folder}/registrar.log"
logs_folder = f"{log_folder}/pledgelogs"
requestslog_folder = f"{log_folder}/requests"


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
