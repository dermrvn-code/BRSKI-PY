import base64
import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

import json

from Certificates.Certificate import (
    load_certificate_from_bytes,
    load_certificate_from_path,
)
from Certificates.Keys import load_passphrase_from_path, load_private_key_from_path
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from Utils.Config import Config
from Utils.Dicts import array_to_dict
from Utils.HTTPS import HTTPSServer, SSLConnection, send_404, send_406
from Utils.Logger import Logger
from Utils.Printer import *
from Voucher.Voucher import Voucher, parse_voucher
from Voucher.VoucherRequest import (
    VoucherRequest,
    create_registrar_voucher_request,
    parse_voucher_request,
)


def handle_request_voucher(self):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)

    voucher_request_json = json.loads(post_data)
    voucher_request = parse_voucher_request(voucher_request_json)
    logger.log(f"Received voucher request: {voucher_request.to_string()}")

    pledge_cert_dict = self.request.getpeercert()

    request_valid, message = validate_voucher_request(voucher_request, pledge_cert_dict)

    if request_valid == 1:
        send_406(self, "Wrong Request Format")
        return
    elif request_valid == 3:
        print_success("Voucher request is valid")
    else:
        send_404(self, "Authentication failed")
        return

    logger.log(
        f"Voucher request forwarded for serial number {voucher_request.serial_number}"
    )
    voucher, message = request_voucher_from_masa(voucher_request)

    voucher_valid = False
    if voucher is None:
        send_404(self, message)
        log_error(logger, voucher_request.serial_number, message, False)
        return

    voucher_valid, message = validate_voucher(voucher)

    if not voucher_valid:
        send_404(self, message)
        log_error(logger, voucher_request.serial_number, message, False)
    else:
        print_success("Voucher is valid")
        logger.log(f"Voucher issued and forwarded: {voucher.to_string()}")

        # if voucher is valid, send it to the pledge
        self.send_response(200)
        self.send_header("Content-type", "text/json")
        self.end_headers()
        self.wfile.write(str.encode(voucher.to_string()))  # type: ignore


def request_voucher_from_masa(
    voucher_request: VoucherRequest,
) -> tuple[Voucher | None, str]:
    """
    Sends a voucher request to the MASA and retrieves a voucher.

    Args:
        voucher_request (VoucherRequest): The voucher request object containing the necessary information.

    Returns:
        Voucher: The voucher issued by the MASA server, or None if the server did not issue a voucher.
        str: The error message if the server did not issue a voucher.
    """

    conn = SSLConnection(
        host="localhost",
        port=8888,
        cert=os.path.join(script_dir, "certs/client/cert_registrar_client.crt"),
        private_key=os.path.join(
            script_dir, "certs/client/cert_private_registrar_client.key"
        ),
        passphrase=load_passphrase_from_path(
            os.path.join(script_dir, "certs/client/passphrase_registrar_client.txt")
        ),
        local_cas=Config.get_values_from_section("CAS"),
    )
    private_key = load_private_key_from_path(
        os.path.join(script_dir, "certs/server/cert_private_registrar_server.key"),
        load_passphrase_from_path(
            os.path.join(script_dir, "certs/server/passphrase_registrar_server.txt")
        ),
    )
    ra_cert = load_certificate_from_path(
        os.path.join(script_dir, "certs/server/cert_registrar_server.crt")
    )

    registrar_request = create_registrar_voucher_request(private_key, voucher_request)

    print_descriptor("registrar request")
    registrar_request.print()

    headers = {
        "Content-Type": "application/json",
        "X-RA-Cert": base64.b64encode(ra_cert.public_bytes(Encoding.DER)).decode(),
    }
    response = conn.post_request(
        "/.wellknown/brski",
        data=registrar_request.to_string(),
        headers=headers,
    )

    if response.status != 200:
        return None, response.read().decode()
    else:
        return parse_voucher(response.read().decode()), ""


def validate_voucher_request(
    voucher_request: VoucherRequest, pledge_cert_dict: dict
) -> tuple[int, str]:
    """
    Validates a voucher request send by the pledge.
    Checks if the peer certificate matches the idev issuer certificate and if the serial numbers match.

    Args:
        voucher_request (VoucherRequest): The voucher request to be validated.
        pledge_cert_dict (dict): The dictionary representation of the pledge certificate.

    Returns:
        int: 1 if the request is in wrong format, 2 if authentication fails, 3 if the request is valid.
        str: The error message if the request is invalid.
    """

    try:
        voucher_request_dict = voucher_request.to_dict()
    except ValueError:
        msg = "Voucher request in wrong format"
        log_error(logger, voucher_request.serial_number, msg)
        return 1, msg

    # Get the idevid issuer certificate from the request
    idevid_cert_bytes = voucher_request.idevid_issuer
    if idevid_cert_bytes is None:
        msg = "No idevid issuer in voucher request"
        log_error(logger, voucher_request.serial_number, msg)
        return 1, msg
    idevid_cert = load_certificate_from_bytes(idevid_cert_bytes)

    # Verify the signature of the voucher request
    if not voucher_request.verify(idevid_cert.public_key()):
        msg = "Voucher request signature invalid"
        log_error(logger, voucher_request.serial_number, msg)
        return 2, msg
    else:
        print_success("Voucher request signature valid")

    # Check if peer certificate matches idev issuer
    serial_number = int(
        pledge_cert_dict.get("serialNumber", ""), 16
    )  # parse string as hexadecimal integer

    if serial_number != idevid_cert.serial_number:
        msg = f"Serial numbers of idev certificates do not match: {serial_number} != {idevid_cert.serial_number}"
        log_error(
            logger,
            voucher_request.serial_number,
            msg,
        )
        return 2, msg
    else:
        print_success("Peer certificate matches idev issuer")

    # Get the subjects serial number from the idevid certificate
    idev_subject = idevid_cert.subject
    idev_subject_serial_number = idev_subject.get_attributes_for_oid(
        NameOID.SERIAL_NUMBER
    )[0].value

    # Get the subjects serial number from the peer certificate
    peer_subject = array_to_dict(pledge_cert_dict.get("subject"))
    peer_subject_serial_number = peer_subject.get("serialNumber", "")

    # Get voucher request serial number
    voucher_serial_number = voucher_request_dict.get("serial-number")

    print_info("Checking in with pledge with serial number", voucher_serial_number)

    # Check if serial numbers across all certs and requests match
    if (
        not idev_subject_serial_number
        == peer_subject_serial_number
        == voucher_serial_number
    ):
        msg = f"Serial numbers do not match: {idev_subject_serial_number} != {peer_subject_serial_number} != {voucher_serial_number}"
        log_error(
            logger,
            voucher_request.serial_number,
            msg,
        )
        return 2, msg
    else:
        print_success("Serial numbers match")

    return 3, ""


def log_error(logger: Logger, serialNumber: str, msg: str, is_request: bool = True):
    prefix = (
        "No voucher request was forwarded " if is_request else "No voucher was issued "
    )
    print_error(msg)
    logger.log(f"{prefix} for serial number {serialNumber}: {msg}")


def validate_voucher(voucher: Voucher | None) -> tuple[bool, str]:
    """
    Validates the voucher received from the MASA.

    Args:
        voucher (Voucher): The voucher to be validated.

    Returns:
        bool: True if the voucher is valid, False otherwise.
        str: The error message if the voucher is invalid.
    """
    if voucher is None:
        return False, "MASA did not issue a voucher"
    return True, ""

    # TODO: Implement any further validation and check of voucher


logger = Logger(os.path.join(script_dir, "registrar.log"))


def main() -> None:
    print_title("Registrar")
    routes = {"/.wellknown/brski": handle_request_voucher}

    certfile = os.path.join(script_dir, "certs/server/cert_registrar_server.crt")
    keyfile = os.path.join(script_dir, "certs/server/cert_private_registrar_server.key")
    passphrasefile = os.path.join(
        script_dir, "certs/server/passphrase_registrar_server.txt"
    )
    local_cas = Config.get_values_from_section("CAS")

    server = HTTPSServer(
        address="localhost",
        port=Config.get("REGISTRAR", "port"),
        routes_post=routes,
        certfile=certfile,
        keyfile=keyfile,
        passphrasefile=passphrasefile,
        local_cas=local_cas,
    )
    server.start()


if __name__ == "__main__":
    main()
