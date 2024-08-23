import base64
import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

import json

from Certificates.Certificate import load_certificate_from_bytes
from Certificates.Keys import (
    load_passphrase_from_path,
    load_private_key_from_path,
    load_public_key_from_path,
)
from cryptography.hazmat.primitives import serialization
from Utils.Config import Config
from Utils.HTTPS import HTTPSServer, send_404
from Utils.Interface import yes_or_no
from Utils.Printer import *
from Voucher.Voucher import Voucher, create_voucher_from_request
from Voucher.VoucherRequest import VoucherRequest, parse_voucher_request


def handle_request_voucher(self):
    content_length = int(self.headers["Content-Length"])
    x_ra_cert = self.headers["X-RA-Cert"]
    post_data = self.rfile.read(content_length)
    voucher_request_dict = json.loads(post_data)

    voucher_request = parse_voucher_request(voucher_request_dict)

    registrar_cert_bytes = base64.b64decode(x_ra_cert)

    # Validate client and voucher here
    request_valid = validate_voucher_request(voucher_request, registrar_cert_bytes)

    if request_valid == 1:
        send_404(self, "Wrong Request Format")
        return
    elif request_valid == 3:
        print_success("Voucher is issued")
    else:
        send_404(self, "Authentication failed")
        return

    voucher = create_voucher(voucher_request, registrar_cert_bytes)
    voucher_json = json.dumps(voucher.to_dict())

    print_descriptor("masa issued voucher:")
    prettyprint_json(voucher_json, True)

    # Send response
    self.send_response(200)
    self.send_header("Content-type", "text/json")
    self.end_headers()
    self.wfile.write(str.encode(voucher_json))


def handle_public_key(self):
    client_cert_dict = self.request.getpeercert()

    print_descriptor("Client certificate")
    prettyprint_json(client_cert_dict, True)

    public_key = load_public_key_from_path(
        os.path.join(script_dir, "certs/cert_public_masa.key")
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    self.send_response(200)
    self.send_header("Content-type", "text/plain")
    self.end_headers()
    self.wfile.write(public_key_bytes)


def validate_voucher_request(
    voucher_request: VoucherRequest, registrar_cert_bytes: bytes | None
) -> int:
    """
    Validates a voucher request send by the registrar.

    Args:
        voucher_request (VoucherRequest): The voucher request to be validated.
        registrar_cert (bytes): The certificate of the registrar.

    Returns:
        int: 1 if the request is in wrong format, 2 if authentication fails, 3 if the request is valid.
    """

    try:
        voucher_request_dict = voucher_request.to_dict()
    except AttributeError:
        print_error("Voucher request in wrong format")
        return 1

    # Get the idevid issuer certificate from the request
    if registrar_cert_bytes is None:
        print_error("No idevid issuer in voucher request")
        return 1
    registrar_cert = load_certificate_from_bytes(registrar_cert_bytes)

    # Verify the signature of the voucher request
    if not voucher_request.verify(registrar_cert.public_key()):
        print_error("Voucher request signature invalid")
        return 2
    else:
        print_success("Voucher request signature valid")

    serial_number = voucher_request_dict.get("serial-number")

    if yes_or_no(
        f"Can you validate the voucher request with serial number {serial_number}?"
    ):
        return 3
    else:
        return 2

    # TODO: Implement validation of voucher request


def create_voucher(
    voucher_request: VoucherRequest, registrar_cert_bytes: bytes
) -> Voucher:
    """
    Create a voucher using the given voucher request and registrar certificate bytes.

    Args:
        voucher_request (VoucherRequest): The voucher request object.
        registrar_cert_bytes (bytes): The registrar certificate bytes.

    Returns:
        voucher (Voucher): The created voucher object.
    """
    masa_passphrase_path = os.path.join(script_dir, "certs/passphrase_masa.txt")
    private_key_path = os.path.join(script_dir, "certs/cert_private_masa.key")

    masa_passphrase = load_passphrase_from_path(masa_passphrase_path)
    private_key = load_private_key_from_path(private_key_path, masa_passphrase)
    voucher = create_voucher_from_request(
        voucher_request, registrar_cert_bytes, private_key
    )
    return voucher


def main() -> None:

    print_title("MASA")
    routes = {
        "/.wellknown/brski": handle_request_voucher,
        "/publickey": handle_public_key,
    }
    certfile = os.path.join(script_dir, "certs/cert_masa.crt")
    keyfile = os.path.join(script_dir, "certs/cert_private_masa.key")
    passphrasefile = os.path.join(script_dir, "certs/passphrase_masa.txt")
    local_cas = Config.get_values_from_section("CAS")

    server = HTTPSServer(
        address="localhost",
        port=Config.get("MASA", "port"),
        routes_post=routes,
        certfile=certfile,
        keyfile=keyfile,
        passphrasefile=passphrasefile,
        local_cas=local_cas,
    )
    server.start()


if __name__ == "__main__":

    main()
