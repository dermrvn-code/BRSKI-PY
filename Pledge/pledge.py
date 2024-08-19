import os
import sys
# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

import secrets
import json

from Certificates.Certificate import load_certificate_bytes_from_path
from Certificates.Keys import load_passphrase_from_path, load_private_key_from_path
from Voucher.VoucherRequest import create_pledge_voucher_request
from Voucher.Voucher import parse_voucher
from Voucher.VoucherBase import Assertion
from Utils.HTTPS import SSLConnection
from Utils.Printer import *


def main() -> None:
    print_title("Pledge")

    idevid_cert_path = "certs/cert_pledge.crt"
    pledge_private_key_path = "certs/cert_private_pledge.key"
    pledge_passphrase_path = "certs/passphrase_pledge.txt"
    pledge_passphrase = load_passphrase_from_path(pledge_passphrase_path)

    conn = SSLConnection("localhost", 8000, idevid_cert_path, pledge_private_key_path, pledge_passphrase)

    pledge_private_key = load_private_key_from_path(pledge_private_key_path, pledge_passphrase)
    idevid = load_certificate_bytes_from_path(idevid_cert_path)

    nonce = secrets.token_bytes(128)

    request = create_pledge_voucher_request(
        pledge_private_key=pledge_private_key,
        serial_number='02481632',
        assertion=Assertion.VERIFIED,
        nonce=nonce,
        idevid_issuer=idevid,
        validity_days=7
    )

    print_descriptor("pledge request")
    request.print()

    # Request Voucher from well-known URI
    response = conn.post_request("/.wellknown/brski", json.dumps(request.to_dict()))

    if(response.status != 200):
        print_error("Voucher request failed")
        return
    else:
        response_body = response.read()
        try:
            voucher = parse_voucher(response_body.decode())
            print_descriptor("voucher")
            voucher.print()
            print_success("Voucher request successful")
        except Exception as e:
            print_error("No valid voucher received: " + response_body.decode())
            print(e)

if __name__ == "__main__":
    main()