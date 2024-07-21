from cryptography.hazmat.primitives import serialization
import json


import sys
sys.path.append("../") 
from Voucher.Voucher import create_voucher_from_request
from Voucher.VoucherRequest import parse_voucher_request
from Certificates.Certificate import load_certificate_from_path
from Certificates.Keys import load_private_key_from_path, load_public_key_from_path, load_passphrase_from_path
from Utils.HTTPS import HTTPSServer


def handle_request_voucher(self):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)
    voucher_request_dict = json.loads(post_data)

    client_cert_bytes = self.request.getpeercert(True)
    client_cert_json = self.request.getpeercert()

    voucher_request = parse_voucher_request(voucher_request_dict)

    # Validate client certificate here

    masa_passphrase = load_passphrase_from_path("certs/passphrase_masa.txt")
    private_key = load_private_key_from_path("certs/cert_private_masa.key", masa_passphrase)
    voucher = create_voucher_from_request(voucher_request, client_cert_bytes, private_key)
    voucher_json = json.dumps(voucher.to_dict());

    print("Voucher:")
    voucher.print()

    # Send response
    self.send_response(200)
    self.send_header("Content-type", "text/json")
    self.end_headers()
    self.wfile.write(str.encode(voucher_json))

def handle_public_key(self):
    client_cert_json = self.request.getpeercert()

    print("Client certificate: ", json.dumps(client_cert_json))

    public_key = load_public_key_from_path("certs/cert_public_masa.key")
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

server = HTTPSServer(address="localhost", port=8888, routes=routes,
                           certfile=certfile, keyfile=keyfile,
                           passphrasefile=passphrasefile)
server.start()
