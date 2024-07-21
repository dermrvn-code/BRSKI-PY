from cryptography.hazmat.primitives import serialization
import json

import sys
sys.path.append("../") 
from Utils.HTTPS import HTTPSServer


valid_crls = {
    "masa" : "../MASA/ca/crl_masa_ca.crl",
    "registrar" : "../Registrar/ca/crl_registrar_ca.crl",
    "manufacturer" : "../Pledge/ca/crl_manufacturer.crl",
    "caserver" : "../CAServer/ca/crl_caserver_ca.crl"
}


def handle_crl(self, query_string):
    
    if query_string is None:
        self.send_response(400)
        self.end_headers()
        self.wfile.write(b"Missing query string")
        return

    query_params = {}
    query_pairs = query_string.split("&")
    for pair in query_pairs:
        key, value = pair.split("=")
        query_params[key] = value
    
    crl_name = query_params.get("from")

    if crl_name is None:
        self.send_response(400)
        self.end_headers()
        self.wfile.write(b"Missing 'from' field")
        return
    
    if crl_name in valid_crls.keys():
        crl_path = valid_crls[crl_name]
        with open(crl_path, "rb") as f:
            crl = f.read()

        self.send_response(200)
        self.send_header("Content-type", "application/pkix-crl")
        self.end_headers()
        self.wfile.write(crl)
    else:
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"CRL not found")



routes = {
    "/crl": handle_crl
}
certfile = "certs/cert_caserver.crt"
keyfile = "certs/cert_private_caserver.key"
passphrasefile = "certs/passphrase_caserver.txt"

server = HTTPSServer(address="localhost", port=8008, routes_get=routes,
                           certfile=certfile, keyfile=keyfile,
                           passphrasefile=passphrasefile)
server.start()
