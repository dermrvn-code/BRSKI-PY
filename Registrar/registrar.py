import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

import json

from Certificates.Keys import load_passphrase_from_path, load_private_key_from_path
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
    if not request_valid:
        send_404(self, "Authentication failed")
        return
    else:
        print_success("Voucher request is valid")

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
) -> bool:
    """
    Validates a voucher request send by the pledge.

    Args:
        voucher_request (VoucherRequest): The voucher request to be validated.
        pledge_cert_dict (dict): The dictionary representation of the pledge certificate.

    Returns:
        bool: True if the serial numbers match, False otherwise.
    """

    voucher_request_dict = voucher_request.to_dict()

    subject = array_to_dict(pledge_cert_dict.get("subject"))
    subject_serial_number = subject.get("serialNumber", "")
    voucher_serial_number = voucher_request_dict.get("serial-number")

    print_info("Checking in with pledge with serial number", subject_serial_number)

    if subject_serial_number != voucher_serial_number:
        print_error(
            f"Serial numbers do not match: {subject_serial_number} != {voucher_serial_number}"
        )
        return False
    else:
        print_success("Serial numbers match")

    return True

    # TODO: Implement validation of voucher request


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
