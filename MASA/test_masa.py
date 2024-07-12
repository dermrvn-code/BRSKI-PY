import http.client
import json
import ssl
from pprint import pprint

import sys
sys.path.append("../") 
from Voucher.Voucher import parse_voucher
from Certificates.CertificateTools import load_certificate_from_path, load_passphrase_from_path
from Utils.HTTPS import ssl_connect, ssl_post_request

from cryptography.hazmat.primitives.serialization import load_pem_public_key





def request_voucher(cert,private_key,passphrase,serialnumber):
    conn = ssl_connect("localhost", 8888, cert, private_key, passphrase)
    # data = {
    #     "serialnumber" : serialnumber
    # }
    # response_data = ssl_post_request(conn, "/requestvoucher", json.dumps(data))
    # return parse_voucher(response_data)


def get_masa_public_key(cert,private_key,passphrase):
    conn = ssl_connect("localhost", 8888, cert, private_key, passphrase)
    response_data = ssl_post_request(conn, "/publickey")
    return load_pem_public_key(response_data)


cert = "../Registrar/certs/client/cert_registrar_client.crt"
private_key = "../Registrar/certs/client/cert_private_registrar_client.key"    
passphrase = load_passphrase_from_path("../Registrar/certs/client/passphrase_registrar_client.txt")

voucher = request_voucher(cert,private_key,passphrase,"123456")

# pprint(voucher.to_dict(), compact=True)

# masa_public_key = get_masa_public_key(cert,private_key,passphrase)

# if(voucher.verify(masa_public_key)):
#     print("Voucher is valid")