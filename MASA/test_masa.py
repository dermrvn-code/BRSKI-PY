import http.client
import json
import ssl
from pprint import pprint

import sys
sys.path.append("../") 
from Voucher.Voucher import parse_voucher
from Certificates.CertificateTools import load_certificatefile, load_passphrase

from cryptography.hazmat.primitives.serialization import load_pem_public_key



def ssl_post_request(host, port, url, data, cert, private_key, passphrase):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="../MASA/ca/CA_masa_ca.pem")
    context.load_cert_chain(certfile=cert, keyfile=private_key, password=passphrase)

    connection = http.client.HTTPSConnection(host, port=port, context=context)
    connection.request(method="POST", url=url, body=data)

    response = connection.getresponse()
    return response.read()

def request_voucher(cert,private_key,passphrase,serialnumber):
    data = {
        "serialnumber" : serialnumber
    }
    response_data = ssl_post_request("localhost", 8888, "/requestvoucher", json.dumps(data), cert, private_key, passphrase)
    return parse_voucher(response_data)


def get_masa_public_key(cert,private_key,passphrase):
    response_data = ssl_post_request("localhost", 8888, "/publickey", "", cert, private_key, passphrase)
    return load_pem_public_key(response_data)


cert = "../Registrar/certs/client/cert_registrar_client.crt"
private_key = "../Registrar/certs/client/cert_private_registrar_client.key"    
passphrase = load_passphrase("../Registrar/certs/client/passphrase_registrar_client.txt")

voucher = request_voucher(cert,private_key,passphrase,"123456")

pprint(voucher.to_dict(), compact=True)

masa_public_key = get_masa_public_key(cert,private_key,passphrase)

if(voucher.verify(masa_public_key)):
    print("Voucher is valid")