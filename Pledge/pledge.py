import secrets
import json

import sys
sys.path.append("../") 
from Certificates.CertificateTools import load_passphrase_from_path, load_private_key_from_path, load_certificate_bytes_from_path
from Voucher.VoucherRequest import create_pledge_voucher_request
from Voucher.Voucher import parse_voucher
from Voucher.VoucherBase import Assertion
from Utils.HTTPS import SSLConnection


idevid_cert_path = "certs/idevid_cert_pledge.crt"
pledge_private_key_path = "certs/cert_private_pledge.key"
pledge_passphrase_path = "certs/passphrase_pledge.txt"
pledge_passphrase = load_passphrase_from_path(pledge_passphrase_path)

conn = SSLConnection("localhost", 8000, idevid_cert_path, pledge_private_key_path, pledge_passphrase)

pledge_private_key = load_private_key_from_path(pledge_private_key_path, pledge_passphrase)
idevid = load_certificate_bytes_from_path(idevid_cert_path)

nonce = secrets.token_bytes(128)

request = create_pledge_voucher_request(
    pledge_private_key=pledge_private_key,
    serial_number='1234',
    assertion=Assertion.VERIFIED,
    nonce=nonce,
    idevid_issuer=idevid,
    validity_days=7
)

print ("pledge request:")
request.print()

response = conn.post_request("/requestvoucher", json.dumps(request.to_dict()))

try:
    voucher = parse_voucher(response.decode())
    print("voucher:")
    voucher.print()
except Exception as e:
    print("No voucher received: " + response.decode())
    print(e)


