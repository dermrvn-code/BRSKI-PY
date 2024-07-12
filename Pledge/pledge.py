import secrets

import sys
sys.path.append("../") 
from Certificates.CertificateTools import load_passphrase, load_private_keyfile, load_certificatefile_bytes_path
from Voucher.VoucherRequest import VoucherRequest, create_pledge_voucher_request, create_registrar_voucher_request
from Voucher.Assertion import Assertion

pledge_passphrase = load_passphrase("certs/passphrase_pledge.txt")
pledge_private_key = load_private_keyfile("certs/cert_private_pledge.key", pledge_passphrase)

idevid = load_certificatefile_bytes_path("certs/idevid_cert_pledge.crt")
nonce = secrets.token_bytes(128)

request = create_pledge_voucher_request(
    pledge_private_key=pledge_private_key,
    serial_number='1234',
    assertion=Assertion.VERIFIED,
    nonce=nonce,
    idevid_issuer=idevid,
    validity_days=7
)
print(type(request))
print (f"pledge request: {request.to_dict()}")

registrar_passphrase = load_passphrase("../Registrar/certs/server/passphrase_registrar_server.txt")
registrar_private_key = load_private_keyfile("../Registrar/certs/server/cert_private_registrar_server.key", registrar_passphrase)
registrar_request = create_registrar_voucher_request(registrar_private_key, request)
print(f"registrar request: {registrar_request.to_dict()}")