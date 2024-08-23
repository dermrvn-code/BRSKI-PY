import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

import json
import secrets

from Certificates.Certificate import load_certificate_bytes_from_path
from Certificates.Keys import load_passphrase_from_path, load_private_key_from_path
from Utils.Config import Config
from Utils.HTTPS import SSLConnection
from Utils.Printer import *
from Voucher.Voucher import Voucher, parse_voucher
from Voucher.VoucherBase import Assertion
from Voucher.VoucherRequest import create_pledge_voucher_request


def main() -> None:
    print_title("Pledge")

    while True:
        try:
            input("Press enter to request a voucher...")
            print_info("Requesting voucher...")
            voucher = request_voucher("localhost", 8000)

            if voucher:
                print_descriptor("voucher")
                voucher.print()
                print_success("Voucher request successful")

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
        None

    Raises:
        Exception: If no valid voucher is received.
    """
    idevid_cert_path = os.path.join(script_dir, "certs/cert_pledge.crt")
    pledge_private_key_path = os.path.join(script_dir, "certs/cert_private_pledge.key")
    pledge_passphrase_path = os.path.join(script_dir, "certs/passphrase_pledge.txt")
    pledge_passphrase = load_passphrase_from_path(pledge_passphrase_path)
    local_cas = Config.get_values_from_section("CAS")

    conn = SSLConnection(
        host="localhost",
        port=8000,
        cert=idevid_cert_path,
        private_key=pledge_private_key_path,
        passphrase=pledge_passphrase,
        local_cas=local_cas,
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

    # Request Voucher from well-known URI
    response = conn.post_request("/.wellknown/brski", json.dumps(request.to_dict()))

    if response.status != 200:
        print_error("Voucher request failed")
        return
    else:
        response_body = response.read()
        try:
            voucher = parse_voucher(response_body.decode())
            return voucher
        except ValueError:
            print_error("No valid voucher received: " + response_body.decode())
            return None


if __name__ == "__main__":
    main()
