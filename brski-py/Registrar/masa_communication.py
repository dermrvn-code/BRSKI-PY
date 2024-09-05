import base64
import os
from urllib.parse import urlparse

from paths import *

script_dir, parent_dir = set_parent_dir(__file__)

import json

from Certificates.Certificate import (
    load_certificate_from_bytes,
    load_certificate_from_path,
)
from Certificates.Keys import load_passphrase_from_path, load_private_key_from_path
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from Utils.Config import Config
from Utils.HTTPS import SSLConnection
from Utils.Logger import Logger
from Utils.Printer import *
from Voucher.Voucher import Voucher, parse_voucher
from Voucher.VoucherRequest import (
    VoucherRequest,
    create_registrar_voucher_request,
    parse_voucher_request,
)


def get_masa_url(idevid_cert_bytes: bytes) -> tuple[str | None, int | None, str | None]:
    """
    Extracts the MASA URL from the idevid certificate.

    Args:
        idevid_cert_bytes (bytes): The idevid certificate in bytes.

    Returns:
        Tuple:
        - str: The hostname of the MASA server.
        - int: The port of the MASA server.
        - str: The path to the MASA post request.
    """
    idevid_cert = load_certificate_from_bytes(idevid_cert_bytes)

    masa_url_oid = x509.ObjectIdentifier(
        "1.3.6.1.5.5.7.1.32"
    )  # oid for masa url extension
    masa_url_ext = idevid_cert.extensions.get_extension_for_oid(masa_url_oid)
    masa_url = masa_url_ext.value.value.decode()  # type: ignore
    parsed_url = urlparse(masa_url)

    return parsed_url.hostname, parsed_url.port, parsed_url.path


def request_voucher_from_masa(
    voucher_request: VoucherRequest,
    *,
    idevid_cert_bytes: bytes,
    hostname: str,
    port: int,
    path: str,
) -> tuple[Voucher | None, str]:
    """
    Sends a voucher request to the MASA and retrieves a voucher.

    Args:
        voucher_request (VoucherRequest): The voucher request object containing the necessary information.
        hostname (str): The hostname of the MASA server.
        port (int): The port of the MASA server.
        path (str): The path to the MASA post request.

    Returns:
        Tuple:
        - Voucher: The voucher issued by the MASA server, or None if the server did not issue a voucher.
        - str: The error message if the server did not issue a voucher.
    """

    conn = server_connection(hostname, port)
    private_key = load_private_key_from_path(
        os.path.join(script_dir, server_key_file_path),
        load_passphrase_from_path(
            os.path.join(script_dir, server_passphrase_file_path)
        ),
    )
    ra_cert = load_certificate_from_path(
        os.path.join(script_dir, server_cert_file_path)
    )

    registrar_request = create_registrar_voucher_request(private_key, voucher_request)

    print_descriptor("registrar request")
    registrar_request.print()

    headers = {
        "Content-Type": "application/json",
        "X-RA-Cert": base64.b64encode(ra_cert.public_bytes(Encoding.DER)).decode(),
        "X-IDevID-Cert": base64.b64encode(idevid_cert_bytes).decode(),
    }
    response = conn.post_request(
        path,
        data=registrar_request.to_json(),
        headers=headers,
    )

    if response.status != 200:
        return None, response.read().decode()
    else:
        return parse_voucher(response.read().decode()), ""


def request_audit_log_from_masa(
    pledge_serial_number: str, idevid_certificate_bytes: bytes
) -> dict:
    """
    Sends a request to the MASA to retrieve the audit log.

    Args:
        request (VoucherRequest): The voucher request object containing the necessary information.

    Returns:
        dict: The audit log received from the MASA.
    """
    # Get most previous request of this pledge
    request_logger = Logger(
        os.path.join(script_dir, requestslog_folder, f"{pledge_serial_number}.log")
    )
    logs = request_logger.get_log_list()

    if len(logs) == 0:
        print_error("No previous request found")
        return {}

    most_recent_request = logs[-1]
    try:
        request = parse_voucher_request(most_recent_request["message"])
    except ValueError:
        print_error("No valid voucher request found")
        return {}

    if request.idevid_issuer == None:
        print_error("No idevid issuer in voucher request")
        return {}

    hostname, port, _ = get_masa_url(idevid_certificate_bytes)

    if hostname == None or port == None:
        print_error("No MASA URL found")
        return {}

    conn = server_connection(hostname, port)

    headers = {"Content-Type": "application/json"}
    data = request.to_json()
    response = conn.post_request(
        Config.get("MASA", "auditlogpath"), data=data, headers=headers
    )

    if response.status != 200:
        print_error(f"Audit log request failed: {response.read().decode()}")
        return {}
    else:
        return json.loads(response.read().decode())


def server_connection(hostname: str, port: int) -> SSLConnection:
    """
    Establishes a server connection using the registrars client identity

    Args:
        hostname (str): The hostname of the server.
        port (int): The port number of the server.

    Returns:
        SSLConnection: The SSL connection object.
    """

    return SSLConnection(
        host=hostname,
        port=port,
        cert=os.path.join(script_dir, client_cert_file_path),
        private_key=os.path.join(script_dir, client_key_file_path),
        passphrasefile=os.path.join(script_dir, client_passphrase_file_path),
        local_cas=Config.get_values_from_section("CAS"),
    )
