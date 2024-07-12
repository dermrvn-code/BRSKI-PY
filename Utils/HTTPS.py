import http.server
import ssl
import socket

import sys
sys.path.append("../") 
from Certificates.CertificateTools import load_passphrase_from_path, load_certificate_from_bytes

from cryptography.x509 import Certificate


class HTTPSServer:
    def __init__(self, 
                 address : str, 
                 port : int, 
                 routes : dict, 
                 certfile : str, 
                 keyfile : str, 
                 passphrasefile : str, 
                 cafile : str
        ):
        self.address = address
        self.port = port
        self.routes = routes
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile

        passphrase = load_passphrase_from_path(passphrasefile)
        self.passphrase = passphrase

    def start(self):
        handler = self.create_handler(self.routes)
        server_address = (self.address, self.port) 
        httpd = http.server.HTTPServer(server_address, handler)


        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile,password=self.passphrase)
        context.load_verify_locations(cafile=self.cafile)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        print(f"Server running on port https://{self.address}:{str(self.port)}...")
        httpd.serve_forever()

    def create_handler(self, routes : dict):
        class CustomHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                handler = routes.get(self.path, self.handle_404)
                print(self)
                handler(self)

            def handle_404(self, optionalself=None):
                self.send_response(404)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"Page not found")
        
        return CustomHTTPRequestHandler

def load_local_cas(context : ssl.SSLContext):
    context.load_verify_locations(cafile="../MASA/ca/CA_masa_ca.pem")
    context.load_verify_locations(cafile="../Registrar/ca/ca_registrar_ca.pem")
    context.load_verify_locations(cafile="../Pledge/ca/ca_manufacturer.pem")

def ssl_connect(
        host : str, 
        port : int, 
        cert : str, 
        private_key : str, 
        passphrase : str
    ):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile=cert, keyfile=private_key, password=passphrase)
    load_local_cas(context)

    connection = http.client.HTTPSConnection(host, port=port, context=context)
    
    return connection

def get_server_certificate(host, port, context) -> Certificate:
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            server_cert_bytes = ssock.getpeercert(True)
    return load_certificate_from_bytes(server_cert_bytes)

def ssl_post_request(connection : http.client.HTTPSConnection, url : str, data : dict = None):
    connection.request(method="POST", url=url, body=data)

    response = connection.getresponse()
    return response.read()
