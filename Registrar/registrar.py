

import json

from Voucher.VoucherRequest import VoucherRequest, create_registrar_voucher_request, parse_voucher_request
from Certificates.Keys import load_passphrase_from_path, load_private_key_from_path
from Utils.HTTPS import HTTPSServer, SSLConnection, send_404
from Utils.Printer import *
from Utils.Dicts import array_to_dict
from Utils.Config import Config


def handle_request_voucher(self):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)

    voucher_request_json = json.loads(post_data)
    voucher_request = parse_voucher_request(voucher_request_json)

    pledge_cert_bytes = self.request.getpeercert(True)
    pledge_cert_dict = self.request.getpeercert()
    
    request_valid = validate_voucher_request(voucher_request, pledge_cert_dict)
    
    # error 406 if request in wrong format, 404 if validation fails
    if(not request_valid):
        send_404(self, "Authentication failed")
        return
    else:
        print_success("Voucher request is valid")


    voucher = request_voucher_from_masa(voucher_request)
    
    voucher_valid = validate_voucher(voucher)

    if(not voucher_valid):
        send_404(self, "Authentication failed")
    else:
        print_success("Voucher is valid")


    # if voucher is valid, send it to the pledge
    self.send_response(200)
    self.send_header("Content-type", "text/json")
    self.end_headers()
    self.wfile.write(str.encode(voucher))


def request_voucher_from_masa(voucher_request : VoucherRequest):
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

    print_descriptor("registrar request")
    registrar_request.print()

    response = conn.post_request("/.wellknown/brski", json.dumps(registrar_request.to_dict()))

    if(response.status != 200):
        print_error("MASA did not issue a voucher")
        return None
    else:
        return response.read().decode()

def validate_voucher_request(voucher_request : VoucherRequest, pledge_cert_dict : dict) -> bool:
    voucher_request_dict = voucher_request.to_dict()

    subject = array_to_dict(pledge_cert_dict.get("subject"))
    subject_serial_number = subject.get("serialNumber")
    voucher_serial_number = voucher_request_dict.get("serial-number")

    print_info("Checking in with pledge with serial number", subject_serial_number)

    if(subject_serial_number != voucher_serial_number):
        print_error("Serial numbers do not match: " + subject_serial_number + " != " + voucher_serial_number)
        return False
    else:
        print_success("Serial numbers match")
    
    return True

def validate_voucher(voucher : dict) -> bool:
    if(voucher is None):
        return False
    return True

def main() -> None:
    print_title("Registrar")
    routes = {
        "/.wellknown/brski": handle_request_voucher
    }

    certfile = "certs/server/cert_registrar_server.crt"
    keyfile = "certs/server/cert_private_registrar_server.key"
    passphrasefile = "certs/server/passphrase_registrar_server.txt"

    server = HTTPSServer(address="localhost", port=get_config_value, routes_post=routes,
                            certfile=certfile, keyfile=keyfile,
                            passphrasefile=passphrasefile)
    server.start()

if __name__ == "__main__":
    main()
