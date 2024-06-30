import ssl
import json
import base64


import sys
sys.path.append("../") 
from Voucher.voucher import Voucher, create_voucher
from Certificates.Certificates import load_private_keyfile, load_public_keyfile, load_passphrase

from cryptography.hazmat.primitives import serialization


import http.server

class MyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/request-voucher":
                        
            # Extract the POST request payload
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            post_data_dict = json.loads(post_data)
            
            # Extract the client"s certificate
            client_cert_bytes = self.request.getpeercert(True)
            client_cert_json = self.request.getpeercert()
            
            print("Client certificate: ", json.dumps(client_cert_json))
            print("POST request payload: ", json.dumps(post_data_dict))

            
            # Validate client certificate here

            registrar_domain = post_data_dict["domain"]
            serial_number = post_data_dict["serialnumber"]

            masa_passphrase = load_passphrase("certs/passphrase_masa.txt")
            private_key = load_private_keyfile("certs/CA_private_masa.key", masa_passphrase)
            voucher = create_voucher(private_key, client_cert_bytes, registrar_domain, "verified", serial_number)
            voucher_json = json.dumps(voucher.to_dict());

            # Send response
            self.send_response(200)
            self.send_header("Content-type", "text/json")
            self.end_headers()
            self.wfile.write(str.encode(voucher_json))

        elif self.path == "/publickey":
                        
            # Extract the POST request payload
            content_length = int(self.headers["Content-Length"])
            # post_data = self.rfile.read(content_length)
            # post_data_dict = json.loads(post_data)
            
            # Extract the client"s certificate
            client_cert_bytes = self.request.getpeercert(True)
            client_cert_json = self.request.getpeercert()
            
            print("Client certificate: ", json.dumps(client_cert_json))
            # print("POST request payload: ", json.dumps(post_data_dict))

            
            # Validate client certificate here

            public_key = load_public_keyfile("certs/CA_public_masa.key")
            public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

            # Send response
            self.send_response(200)
            self.send_header("Content-type", "application/voucher-cms+json")
            self.end_headers()
            self.wfile.write(public_key_bytes)
        
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Page not found")


server_address = ("localhost", 8888)  # Change the port number if needed
httpd = http.server.HTTPServer(server_address, MyHTTPRequestHandler)

password = load_passphrase("certs/passphrase_masa.txt")

# Enable HTTPS by providing the path to your SSL certificate and key files
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(certfile="certs/cert_masa.crt", keyfile="certs/CA_private_masa.key",password=password)
context.load_verify_locations(cafile="../Registrar/ca/CA_registrar_ca.pem")
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Server running on port https://localhost:8888 ...")
httpd.serve_forever()