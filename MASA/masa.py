import os
import sys
# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from cryptography.hazmat.primitives import serialization
import json

from Voucher.Voucher import create_voucher_from_request
from Voucher.VoucherRequest import parse_voucher_request
from Certificates.Keys import load_private_key_from_path, load_public_key_from_path, load_passphrase_from_path
from Utils.HTTPS import HTTPSServer, send_404
from Utils.Printer import *
from Utils.Interface import yes_or_no
from Utils.Config import Config


def handle_request_voucher(self):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)
    voucher_request_dict = json.loads(post_data)

    client_cert_bytes = self.request.getpeercert(True)
    client_cert_dict = self.request.getpeercert()

    voucher_request = parse_voucher_request(voucher_request_dict)

    # Validate client and voucher here

    request_valid = validate_voucher_request(voucher_request)

    if(not request_valid):
        send_404(self)
        return
    else:
        print_success("Voucher is issued")

    # GET Registrar RA Certificate ???
    registrar_cert_bytes = client_cert_bytes

    voucher = create_voucher(voucher_request, registrar_cert_bytes)
    voucher_json = json.dumps(voucher.to_dict());

    print_descriptor("masa issued voucher:")
    prettyprint_json(voucher_json, True)

    # Send response
    self.send_response(200)
    self.send_header("Content-type", "text/json")
    self.end_headers()
    self.wfile.write(str.encode(voucher_json))

def handle_public_key(self):
    client_cert_dict = self.request.getpeercert()

    print_descriptor("Client certificate")
    prettyprint_json(client_cert_dict, True)

    public_key = load_public_key_from_path(os.path.join(script_dir,"certs/cert_public_masa.key"))
    public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    self.send_response(200)
    self.send_header("Content-type", "text/plain")
    self.end_headers()
    self.wfile.write(public_key_bytes)

def validate_voucher_request(voucher_request : dict) -> bool:
    voucher_request_dict = voucher_request.to_dict()
    serial_number = voucher_request_dict.get("serial-number")

    return yes_or_no("Can you validate the voucher request with serial number " + serial_number + "?")

def create_voucher(voucher_request, registrar_cert_bytes):
    masa_passphrase = load_passphrase_from_path("certs/passphrase_masa.txt")
    private_key = load_private_key_from_path("certs/cert_private_masa.key", masa_passphrase)
    voucher = create_voucher_from_request(voucher_request, registrar_cert_bytes, private_key)
    return voucher

def main() -> None:

    print_title("MASA")
    routes = {
        "/.wellknown/brski": handle_request_voucher,
        "/publickey": handle_public_key,
    }
    certfile = os.path.join(script_dir, "certs/cert_masa.crt")
    keyfile = os.path.join(script_dir, "certs/cert_private_masa.key")
    passphrasefile = os.path.join(script_dir, "certs/passphrase_masa.txt")

    server = HTTPSServer(address="localhost", port=Config.get("MASA","port"), routes_post=routes,
                            certfile=certfile, keyfile=keyfile,
                            passphrasefile=passphrasefile)
    server.start()

if __name__ == "__main__":

    main()
