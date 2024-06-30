import http.client
import json
import ssl

import sys
sys.path.append("../") 
from Voucher.voucher import Voucher, parse_voucher
from Certificates.Certificates import load_certificatefile, load_passphrase

from cryptography.hazmat.primitives.serialization import load_pem_public_key


def ssl_post_request(host, port, url, data, cert, private_key, passphrase):
    # Define the client certificate settings for https connection
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Load the CA certificate
    context.load_verify_locations(cafile="../MASA/ca/CA_masa_ca.pem")

    # Load the client certificate and private key
    context.load_cert_chain(certfile=cert, keyfile=private_key, password=passphrase)

    # Create a connection to submit HTTP requests
    connection = http.client.HTTPSConnection(host, port=port, context=context)

    # Use connection to submit a HTTP POST request
    connection.request(method="POST", url=url, body=data)

    # Print the HTTP response from the IOT service endpoint
    response = connection.getresponse()
    return response.read()

def request_voucher(cert,private_key,passphrase,domain,serialnumber):
    data = {
        "domain" : domain,
        "serialnumber" : serialnumber
    }
    response_data = ssl_post_request("localhost", 8888, "/request-voucher", json.dumps(data), cert, private_key, passphrase)
    return parse_voucher(response_data)


def get_masa_public_key(cert,private_key,passphrase):
    response_data = ssl_post_request("localhost", 8888, "/publickey", "", cert, private_key, passphrase)
    return load_pem_public_key(response_data)


cert = "../Registrar/certs/cert_registar.crt"
private_key = "../Registrar/certs/CA_private_registar.key"    
passphrase = load_passphrase("../Registrar/certs/passphrase_registar.txt")

voucher = request_voucher(cert,private_key,passphrase,"example.com","123456")
masa_public_key = get_masa_public_key(cert,private_key,passphrase)


registrar_cert = load_certificatefile(cert)

if(voucher.verify(masa_public_key,"example.com", registrar_cert)):
    print("Voucher is valid")