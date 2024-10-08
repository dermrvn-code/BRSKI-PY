import os
import sys
from http.server import BaseHTTPRequestHandler

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from Utils.Config import Config
from Utils.HTTPS import HTTPSServer
from Utils.Printer import print_title

valid_crls = {
    "masa_ca": "/MASA/certs/ca/crl_masa_ca.crl",
    "registrar_ca": "/Registrar/certs/ca/crl_registrar_ca.crl",
    "manufacturer": "/Pledge/certs/ca/crl_manufacturer.crl",
    "caserver_ca": "/Authorities/certs/ca/crl_caserver_ca.crl",
}


def handle_crl(request_handler: BaseHTTPRequestHandler, query_string):

    if query_string is None:
        request_handler.send_response(400)
        request_handler.end_headers()
        request_handler.wfile.write(b"Missing query string")
        return

    query_params = {}
    query_pairs = query_string.split("&")
    for pair in query_pairs:
        key, value = pair.split("=")
        query_params[key] = value

    crl_name = query_params.get("from")

    if crl_name is None:
        request_handler.send_response(400)
        request_handler.end_headers()
        request_handler.wfile.write(b"Missing 'from' field")
        return

    if crl_name in valid_crls.keys():
        crl_path = valid_crls[crl_name]
        with open(crl_path, "rb") as f:
            crl = f.read()

        request_handler.send_response(200)
        request_handler.send_header("Content-type", "application/pkix-crl")
        request_handler.end_headers()
        request_handler.wfile.write(crl)
    else:
        request_handler.send_response(404)
        request_handler.end_headers()
        request_handler.wfile.write(b"CRL not found")


def main() -> None:

    print_title("Authority")

    routes = {"/crl": handle_crl}
    certfile = os.path.join(script_dir, "certs/cert_authorities.crt")
    keyfile = os.path.join(script_dir, "certs/cert_private_authorities.key")
    passphrasefile = os.path.join(script_dir, "certs/passphrase_authorities.txt")
    local_cas = Config.get_values_from_section("CAS")

    server = HTTPSServer(
        address=Config.get("AUTHORITIES", "hostname"),
        port=Config.get("AUTHORITIES", "port"),
        routes_get=routes,
        certfile=certfile,
        keyfile=keyfile,
        passphrasefile=passphrasefile,
        local_cas=local_cas,
    )
    server.start()


if __name__ == "__main__":
    main()
