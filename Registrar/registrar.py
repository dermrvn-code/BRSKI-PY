import ssl
import json


import sys
sys.path.append("../") 
from Voucher.Voucher import Voucher
from Certificates.CertificateTools import load_passphrase_from_path
from Utils.HTTPS import HTTPSServer


def handle_request_voucher(self):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)
    post_data_dict = json.loads(post_data)

    client_cert_bytes = self.request.getpeercert(True)
    client_cert_json = self.request.getpeercert()

    print("Client certificate: ", json.dumps(client_cert_json))
    print("POST request payload: ", json.dumps(post_data_dict))

    registrar_domain = post_data_dict["domain"]
    serial_number = post_data_dict["serialnumber"]

    # masa_passphrase = load_passphrase("certs/passphrase_masa.txt")
    # private_key = load_private_keyfile("certs/cert_private_masa.key", masa_passphrase)
    # voucher = create_voucher(private_key, client_cert_bytes, registrar_domain, "verified", serial_number)
    # voucher_json = json.dumps(voucher.to_dict())

    self.send_response(200)
    self.send_header("Content-type", "application/voucher-cms+json")
    self.end_headers()
    # self.wfile.write(voucher_json.encode())


routes = {
    "/requestvoucher": handle_request_voucher
}

certfile = "certs/server/cert_registrar_server.crt"
keyfile = "certs/server/cert_private_registrar_server.key"
passphrasefile = "certs/server/passphrase_registrar_server.txt"
cafile = "../Pledge/ca/ca_manufacturer.pem"

server = HTTPSServer(address="localhost", port=8000, routes=routes,
                           certfile=certfile, keyfile=keyfile,
                           passphrasefile=passphrasefile, cafile=cafile)
server.start()
