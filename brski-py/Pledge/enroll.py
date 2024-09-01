from cryptography.hazmat.primitives.serialization import Encoding
from paths import *
from sends_requests import server_connection

script_dir, parent_dir = set_parent_dir(__file__)

from Certificates.Certificate import (
    generate_ldevid_request,
    load_certificate_from_bytes,
    save_cert_to_file,
)
from Utils.Config import Config
from Utils.Printer import print_error, print_success


def request_ldevid_cert(serialnumber: str) -> tuple[str, str, str]:
    """
    Requests an LDevID certificate for a given serial number.

    Args:
        serialnumber (str): The serial number of the pledge.

    Returns:
        Tuple:
        - str: The path to the private key file.
        - str: The path to the certificate file.
    """

    # Destination folder for the LDevID certificate files
    dest_folder = os.path.join(script_dir, "certs")
    dest_folder_request = os.path.join(dest_folder, "ldevid_requests")
    dest_folder_key_cert = os.path.join(dest_folder, "ldevid")
    common_name = f"pledge.{serialnumber}"

    # Build the request
    request, file_path, private_key_path, passphrase_file_path = (
        generate_ldevid_request(
            dest_folder_request=dest_folder_request,
            dest_folder_key=dest_folder_key_cert,
            country_code="DE",
            serialnumber=serialnumber,
            common_name=common_name,
        )
    )
    request_bytes = request.public_bytes(Encoding.PEM)

    conn, _, _, _ = server_connection(
        Config.get("REGISTRAR", "hostname"), int(Config.get("REGISTRAR", "port"))
    )

    headers = {"Content-Type": "application/pkcs10"}
    data = request_bytes.decode()

    response = conn.post_request(
        Config.get("REGISTRAR", "ldevidrequestpath"), data=data, headers=headers
    )

    if response.status != 200:
        print_error(
            f"Request for LDevID certificate failed: {response.read().decode()}"
        )
        return "", "", ""

    cert_bytes = response.read()
    ldevid_cert = load_certificate_from_bytes(cert_bytes)
    cert_path = save_cert_to_file(
        ldevid_cert, dest_folder_key_cert, common_name=common_name
    )

    print_success(
        f"Request for LDevID certificate successful. Certificate saved to {dest_folder_key_cert}"
    )

    return cert_path, private_key_path, passphrase_file_path
