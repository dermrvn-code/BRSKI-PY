from cryptography.hazmat.primitives import serialization
import json


import sys
sys.path.append("../") 
from Voucher.Voucher import Voucher, create_voucher, Assertion
from Certificates.CertificateTools import load_private_keyfile, load_public_keyfile, load_passphrase, load_certificatefile
from Utils.HTTPSServer import SimpleHTTPSServer


def handle_request_voucher(self):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)
    post_data_dict = json.loads(post_data)

    client_cert_bytes = self.request.getpeercert(True)
    client_cert_json = self.request.getpeercert()

    print("Client certificate: ", json.dumps(client_cert_json))
    print("POST request payload: ", json.dumps(post_data_dict))

    # Validate client certificate here

    serial_number = post_data_dict["serialnumber"]

    masa_passphrase = load_passphrase("certs/passphrase_masa.txt")
    private_key = load_private_keyfile("certs/cert_private_masa.key", masa_passphrase)
    voucher = create_voucher(private_key, client_cert_bytes, Assertion.VERIFIED, serial_number, idevid_issuer=client_cert_bytes)
    voucher_json = json.dumps(voucher.to_dict());

    # Send response
    self.send_response(200)
    self.send_header("Content-type", "text/json")
    self.end_headers()
    self.wfile.write(str.encode(voucher_json))

def handle_public_key(self):
    client_cert_json = self.request.getpeercert()

    print("Client certificate: ", json.dumps(client_cert_json))

    public_key = load_public_keyfile("certs/cert_public_masa.key")
    public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    self.send_response(200)
    self.send_header("Content-type", "text/plain")
    self.end_headers()
    self.wfile.write(public_key_bytes)


routes = {
    "/requestvoucher": handle_request_voucher,
    "/publickey": handle_public_key,
}
certfile = "certs/cert_masa.crt"
keyfile = "certs/cert_private_masa.key"
passphrasefile = "certs/passphrase_masa.txt"
cafile = "../Registrar/ca/CA_registrar_ca.pem"

server = SimpleHTTPSServer(address="localhost", port=8888, routes=routes,
                           certfile=certfile, keyfile=keyfile,
                           passphrasefile=passphrasefile, cafile=cafile)
server.start()
