import base64
import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

import secrets

from Certificates.Certificate import load_certificate_bytes_from_path
from Certificates.Keys import (
    load_passphrase_from_path,
    load_private_key_from_path,
    load_public_key_from_bytes,
)
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from Utils.Config import Config
from Utils.HTTPS import SSLConnection
from Utils.Printer import *
from Voucher.Voucher import Voucher, parse_voucher
from Voucher.VoucherBase import Assertion
from Voucher.VoucherRequest import VoucherRequest, create_pledge_voucher_request


def main() -> None:
    print_title("Pledge")

    while True:
        try:
            input("Press enter to request a voucher...")
            print_info("Requesting voucher...")
            voucher = request_voucher(
                Config.get("REGISTRAR", "hostname"),
                int(Config.get("REGISTRAR", "port")),
            )

            if voucher:
                print_success("Voucher received and validated successfully:")
                voucher.print()
            else:
                print_error("No valid voucher received")
                continue

            # TODO: Implement a exchange of LDevID Certificate Requests and Establish secure connection

        except KeyboardInterrupt:
            break


def request_voucher(hostname: str, port: int) -> Voucher | None:
    """
    Requests a voucher from a well-known URI using the BRSKI protocol.

    Args:
        hostname (str): The hostname of the server to connect to.
        port (int): The port number of the server to connect to.

    Returns:
        Voucher: The voucher object received from the server.

    Raises:
        Exception: If no valid voucher is received.
    """
    conn, idevid_cert_path, pledge_private_key_path, pledge_passphrase = (
        server_connection(hostname, port)
    )

    pledge_private_key = load_private_key_from_path(
        pledge_private_key_path, pledge_passphrase
    )
    idevid = load_certificate_bytes_from_path(idevid_cert_path)

    nonce = secrets.token_bytes(128)

    request = create_pledge_voucher_request(
        pledge_private_key=pledge_private_key,
        serial_number="02481632",
        assertion=Assertion.VERIFIED,
        nonce=nonce,
        idevid_issuer=idevid,
        validity_days=7,
    )

    print_descriptor("pledge request")
    request.print()

    headers = {"Content-Type": "application/json"}
    # Request Voucher from well-known URI
    response = conn.post_request(
        Config.get("REGISTRAR", "brskipath"), data=request.to_string(), headers=headers
    )

    if response.status != 200:
        print_error("Voucher request failed: " + response.read().decode())
        return None
    else:

        # Get the certificate of the server the response was sent to
        server_cert = conn.get_server_certificate_bytes()

        if server_cert == None:
            print_error("Server certificate could not be extracted")
            return None

        response_body = response.read()
        try:
            voucher = parse_voucher(response_body.decode())
            print_info("Voucher received, validating...")

            valid, error = validate_voucher(voucher, request, server_cert)

            if not valid:
                print_error("Voucher validation failed: " + error)
                return None

            return voucher
        except ValueError:
            print_error("No valid voucher received: " + response_body.decode())
            return None


def validate_voucher(
    voucher: Voucher, request: VoucherRequest, registrar_ra_cert: bytes
) -> tuple[bool, str]:
    """
    Validates a voucher received from the MASA server.

    Args:
        voucher (Voucher): The voucher to be validated.
        request (VoucherRequest): The voucher request the voucher was issued for.
        registrar_ra_cert (bytes): The certificate of the registrar RA.

    Returns:
        bool: True if the voucher is valid, False otherwise.
        str: The error message if the voucher is invalid.
    """
    masa_public_key = request_masa_public_key()

    if masa_public_key is None:
        return False, "MASA public key could not be extracted"

    if not voucher.verify(masa_public_key):
        return False, "Voucher signature invalid"

    if voucher.serial_number != request.serial_number:
        return False, "Serial number mismatch"

    if voucher.nonce != request.nonce:
        return False, "Nonce mismatch"

    if voucher.pinned_domain_cert == None:
        return False, "Pinned domain certificate missing"
    else:
        if base64.b64decode(voucher.pinned_domain_cert) != base64.b64decode(
            registrar_ra_cert
        ):
            return False, "Registrar RA certificate mismatch"

    # TODO: Implement any further validation and check of voucher

    return True, ""


def server_connection(
    hostname: str, port: int
) -> tuple[SSLConnection, str, str, bytes]:
    """
    Establishes a server connection using the pledges idevid identity

    Args:
        hostname (str): The hostname of the server.
        port (int): The port number of the server.

    Returns:
        SSLConnection: The SSL connection object.
        str: The path to the pledge's identity certificate
        str: The path to the pledge's private key.
        bytes: The passphrase of the pledge's private key.
    """

    idevid_cert_path = os.path.join(script_dir, "certs/cert_pledge.crt")
    pledge_private_key_path = os.path.join(script_dir, "certs/cert_private_pledge.key")
    pledge_passphrase_path = os.path.join(script_dir, "certs/passphrase_pledge.txt")
    pledge_passphrase = load_passphrase_from_path(pledge_passphrase_path)
    local_cas = Config.get_values_from_section("CAS")

    return (
        SSLConnection(
            host=hostname,
            port=port,
            cert=idevid_cert_path,
            private_key=pledge_private_key_path,
            passphrase=pledge_passphrase,
            local_cas=local_cas,
        ),
        idevid_cert_path,
        pledge_private_key_path,
        pledge_passphrase,
    )


def request_masa_public_key() -> PublicKeyTypes | None:
    """
    Requests the public key of the MASA server.

    Args:
        hostname (str): The hostname of the MASA server.
        port (int): The port number of the MASA server.

    Returns:
        bytes: The public key of the MASA server.
    """

    conn, _, _, _ = server_connection(
        Config.get("MASA", "hostname"), int(Config.get("MASA", "port"))
    )

    response = conn.post_request(Config.get("MASA", "publickeypath"))

    if response.status != 200:
        print_error(
            "MASA public key could not be extracted: " + response.read().decode()
        )
        return None
    else:
        try:
            public_key = load_public_key_from_bytes(response.read())
            return public_key
        except Exception:
            print_error("MASA public key could not be extracted")
            return None


if __name__ == "__main__":
    main()
