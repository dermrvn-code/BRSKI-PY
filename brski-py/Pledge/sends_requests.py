import secrets

from paths import *
from validation import *

script_dir, parent_dir = set_parent_dir(__file__)


from Certificates.Certificate import load_certificate_bytes_from_path
from Certificates.Keys import (
    load_passphrase_from_path,
    load_private_key_from_path,
    load_public_key_from_bytes,
)
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from Utils.Config import Config
from Utils.HTTPS import SSLConnection, SSLSocketClient
from Utils.Printer import *
from Voucher.Voucher import Voucher, parse_voucher
from Voucher.VoucherBase import Assertion
from Voucher.VoucherRequest import create_pledge_voucher_request


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
        server_cert = conn.server_certificate_bytes

        if server_cert == None:
            print_error("Server certificate could not be extracted")
            return None

        response_body = response.read()
        try:
            voucher = parse_voucher(response_body.decode())
            print_info("Voucher received, validating...")

            masa_public_key = request_masa_public_key()
            valid, error = validate_voucher(
                voucher, request, server_cert, masa_public_key
            )

            if not valid:
                send_voucher_status(False, reason=error)
                print_error("Voucher validation failed: " + error)
                return None

            send_voucher_status(True)
            return voucher
        except ValueError:
            print_error("No valid voucher received: " + response_body.decode())
            return None


def open_socket_connection(
    hostname: str,
    port: int,
    cert_file_path: str,
    key_file_path: str,
    passphrase_file_path: str,
) -> None:
    """
    Opens a socket connection to the specified hostname and port.

    Args:
        hostname (str): The hostname of the server.
        port (int): The port number of the server.
        cert_file_path (str): The path to the certificate file.
        key_file_path (str): The path to the private key file.
        passphrase_file_path (str): The path to the passphrase file.
    """

    local_cas = Config.get_values_from_section("CAS")
    socket = SSLSocketClient(
        host=hostname,
        port=port,
        cert=cert_file_path,
        private_key=key_file_path,
        passphrasefile=passphrase_file_path,
        local_cas=local_cas,
    )

    socket.connect()

    while True:
        try:
            data = input("Enter data to send: ")
            socket.send_message(data)
            response = socket.receive_message()
            print("Received: " + response)
        except KeyboardInterrupt:
            break


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

    serialnumber = Config.get("PLEDGE", "serialnumber")
    cert_file_path = f"certs/cert_pledge-{serialnumber}.crt"
    key_file_path = f"certs/cert_private_pledge-{serialnumber}.key"
    passphrase_file_path = f"certs/passphrase_pledge-{serialnumber}.txt"

    idevid_cert_path = os.path.join(script_dir, cert_file_path)
    pledge_private_key_path = os.path.join(script_dir, key_file_path)
    pledge_passphrase_path = os.path.join(script_dir, passphrase_file_path)
    pledge_passphrase = load_passphrase_from_path(pledge_passphrase_path)
    local_cas = Config.get_values_from_section("CAS")

    return (
        SSLConnection(
            host=hostname,
            port=port,
            cert=idevid_cert_path,
            private_key=pledge_private_key_path,
            passphrasefile=pledge_passphrase_path,
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


def send_voucher_status(
    status: bool, version: str = "1", reason: str = "", reason_context: str = ""
) -> None:
    """
    Sends the status of the voucher to the MASA server.

    Args:
        version (str): The version of the voucher.
        status (bool): The status of the voucher.
        reason (str): The reason for the status.
        reason_context (str): The context of the reason.

    Raises:
        ValueError: If the status is False and no reason is provided.
    """
    if not status and reason == "":
        raise ValueError("Reason must be provided if status is False")

    voucher_status = {
        "version": version,
        "status": status,
        "reason": reason,
        "reason_context": reason_context,
    }

    conn, _, _, _ = server_connection(
        Config.get("REGISTRAR", "hostname"), int(Config.get("REGISTRAR", "port"))
    )

    conn.post_request(
        Config.get("REGISTRAR", "voucherstatuspath"), data=json.dumps(voucher_status)
    )
