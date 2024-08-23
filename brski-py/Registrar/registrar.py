import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

import json

from Certificates.Certificate import load_certificate_from_bytes
from Certificates.Keys import load_passphrase_from_path, load_private_key_from_path
from cryptography.x509.oid import NameOID
from Utils.Config import Config
from Utils.Dicts import array_to_dict
from Utils.HTTPS import HTTPSServer, SSLConnection, send_404
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

    pledge_cert_dict = self.request.getpeercert()

    request_valid = validate_voucher_request(voucher_request, pledge_cert_dict)

    # error 406 if request in wrong format, 404 if validation fails
    if request_valid == 1:
        send_404(self, "Wrong Request Format")
        return
    elif request_valid == 3:
        print_success("Voucher request is valid")
    else:
        send_404(self, "Authentication failed")
        return

    voucher = request_voucher_from_masa(voucher_request)

    voucher_valid = False
    if voucher is not None:
        voucher_valid = validate_voucher(voucher)

    if not voucher_valid:
        send_404(self, "Authentication failed")
    else:
        print_success("Voucher is valid")

        # if voucher is valid, send it to the pledge
        self.send_response(200)
        self.send_header("Content-type", "text/json")
        self.end_headers()
        self.wfile.write(str.encode(voucher.to_string()))  # type: ignore


def request_voucher_from_masa(voucher_request: VoucherRequest):
    """
    Sends a voucher request to the MASA and retrieves a voucher.

    Args:
        voucher_request (VoucherRequest): The voucher request object containing the necessary information.

    Returns:
        Voucher: The voucher issued by the MASA server, or None if the server did not issue a voucher.
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

    registrar_request = create_registrar_voucher_request(private_key, voucher_request)

    print_descriptor("registrar request")
    registrar_request.print()

    response = conn.post_request(
        "/.wellknown/brski", json.dumps(registrar_request.to_dict())
    )

    if response.status != 200:
        print_error("MASA did not issue a voucher")
        return None
    else:
        return parse_voucher(response.read().decode())


def validate_voucher_request(
    voucher_request: VoucherRequest, pledge_cert_dict: dict
) -> int:
    """
    Validates a voucher request send by the pledge.
    Checks if the peer certificate matches the idev issuer certificate and if the serial numbers match.

    Args:
        voucher_request (VoucherRequest): The voucher request to be validated.
        pledge_cert_dict (dict): The dictionary representation of the pledge certificate.

    Returns:
        int: 1 if the request is in wrong format, 2 if authentication fails, 3 if the request is valid.
    """

    try:
        voucher_request_dict = voucher_request.to_dict()
    except AttributeError:
        print_error("Voucher request in wrong format")
        return 1

    # Get the idevid issuer certificate from the request
    idevid_cert_bytes = voucher_request.idevid_issuer
    if idevid_cert_bytes is None:
        print_error("No idevid issuer in voucher request")
        return 1
    idevid_cert = load_certificate_from_bytes(idevid_cert_bytes)

    # Verify the signature of the voucher request
    if not voucher_request.verify(idevid_cert.public_key()):
        print_error("Voucher request signature invalid")
        return 2
    else:
        print_success("Voucher request signature valid")

    # Check if peer certificate matches idev issuer
    serial_number = int(
        pledge_cert_dict.get("serialNumber", ""), 16
    )  # parse string as hexadecimal integer

    if serial_number != idevid_cert.serial_number:
        print_error(
            f"Serial numbers of idev certificates do not match: {serial_number} != {idevid_cert.serial_number}"
        )
        return 2
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
        print_error(
            f"Serial numbers do not match: {idev_subject_serial_number} != {peer_subject_serial_number} != {voucher_serial_number}"
        )
        return 2
    else:
        print_success("Serial numbers match")

    return 3


def validate_voucher(voucher: Voucher | None) -> bool:
    """
    Validates the voucher received from the MASA.

    Args:
        voucher (Voucher | None): The voucher to be validated.

    Returns:
        bool: True if the voucher is valid, False otherwise.
    """
    if voucher is None:
        return False
    return True

    # TODO: Implement validation of voucher


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
