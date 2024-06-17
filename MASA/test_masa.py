import requests
import json

import sys
sys.path.append("../") 
from Voucher.voucher import Voucher, parse_voucher, load_certificatefile

from cryptography.hazmat.primitives.serialization import load_pem_public_key


def request_voucher(cert,private_key,domain,serialnumber):
    data = {
        "domain" : domain,
        "serialnumber" : serialnumber
    }
    response  = requests.post(
        'https://localhost:8888/request-voucher', 
        data=json.dumps(data), 
        verify=False, # set to True in production
        cert=(cert, private_key)
    )
    voucher_json = response.content
    return parse_voucher(voucher_json)


def get_masa_public_key(cert,private_key):
    response  = requests.post(
        'https://localhost:8888/publickey', 
        verify=False, # set to True in production
        cert=(cert, private_key)
    )
    return load_pem_public_key(response.content)


cert = "../Registrar/certs/registrar.crt"
private_key = "../Registrar/certs/registrar_priv.key"

voucher = request_voucher(cert,private_key,"example.com","123456")
masa_public_key = get_masa_public_key(cert,private_key)


registrar_cert = load_certificatefile("../Registrar/certs/registrar.crt")

if(voucher.verify(masa_public_key,"example.com", registrar_cert)):
    print("Voucher is valid")