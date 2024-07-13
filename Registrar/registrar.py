import json


import sys
sys.path.append("../") 
from Voucher.VoucherRequest import VoucherRequest, create_registrar_voucher_request, parse_voucher_request
from Certificates.CertificateTools import load_passphrase_from_path, load_private_key_from_path
from Utils.HTTPS import HTTPSServer, SSLConnection


def handle_request_voucher(self):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)

    voucher_request_json = json.loads(post_data)
    voucher_request = parse_voucher_request(voucher_request_json)

    client_cert_bytes = self.request.getpeercert(True)
    client_cert_json = self.request.getpeercert()


    voucher = request_voucher(voucher_request)
    

    # masa_passphrase = load_passphrase("certs/passphrase_masa.txt")
    # private_key = load_private_keyfile("certs/cert_private_masa.key", masa_passphrase)
    # voucher = create_voucher(private_key, client_cert_bytes, registrar_domain, "verified", serial_number)
    # voucher_json = json.dumps(voucher.to_dict())

    self.send_response(200)
    self.send_header("Content-type", "application/voucher-cms+json")
    self.end_headers()
    self.wfile.write(voucher)


def request_voucher(voucher_request : VoucherRequest):
    conn = SSLConnection(
        "localhost", 8888, 
        "certs/client/cert_registrar_client.crt", 
        "certs/client/cert_private_registrar_client.key", 
        load_passphrase_from_path("certs/client/passphrase_registrar_client.txt")
    )
    private_key = load_private_key_from_path(
        "certs/server/cert_private_registrar_server.key", 
        load_passphrase_from_path("certs/server/passphrase_registrar_server.txt"))
    
    registrar_request = create_registrar_voucher_request(private_key, voucher_request)

    print("registrar request:")
    registrar_request.print()

    response = conn.post_request("/requestvoucher", json.dumps(registrar_request.to_dict()))
    return response

routes = {
    "/requestvoucher": handle_request_voucher
}

certfile = "certs/server/cert_registrar_server.crt"
keyfile = "certs/server/cert_private_registrar_server.key"
passphrasefile = "certs/server/passphrase_registrar_server.txt"

server = HTTPSServer(address="localhost", port=8000, routes=routes,
                           certfile=certfile, keyfile=keyfile,
                           passphrasefile=passphrasefile)
server.start()
