import ssl
import socket
import tempfile
import sys
from Certificates.CertificateTools import load_passphrase_from_path, load_certificate_from_bytes
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

import http.server
import http.client

sys.path.append("../") 


def load_local_cas(context) -> ssl.SSLContext:
    """
    Load local Certificate Authorities (CAs) into the SSL context.

    Parameters:
        context (ssl.SSLContext): The SSL context.

    Returns:
        ssl.SSLContext: The SSL context with loaded CAs.
    """
    ca_files = [
        "../MASA/ca/ca_masa_ca.crt",
        "../Registrar/ca/ca_registrar_ca.crt",
        "../Pledge/ca/ca_manufacturer.crt"
    ]

    combined_cas = ""
    for ca_file in ca_files:
        with open(ca_file, "r") as file:
            combined_cas += file.read()

    # Load the combined CAs
    context.load_verify_locations(cadata=combined_cas)

    return context

class HTTPSServer:
    def __init__(self, 
                 address : str, 
                 port : int, 
                 routes : dict, 
                 certfile : str, 
                 keyfile : str, 
                 passphrasefile : str
        ):
        """
        Initialize an HTTPS server.

        Parameters:
            address (str): The server address.
            port (int): The server port.
            routes (dict): A dictionary of routes and their corresponding handlers.
            certfile (str): The path to the server certificate file.
            keyfile (str): The path to the server private key file.
            passphrasefile (str): The path to the file containing the passphrase for the private key.
        """
        self.address = address
        self.port = port
        self.routes = routes
        self.certfile = certfile
        self.keyfile = keyfile

        passphrase = load_passphrase_from_path(passphrasefile)
        self.passphrase = passphrase

    def start(self):
        """
        Start the HTTPS server.
        """
        handler = self.create_handler(self.routes)
        server_address = (self.address, self.port) 
        httpd = http.server.HTTPServer(server_address, handler)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile, password=self.passphrase)
        context = load_local_cas(context)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        print(f"Server running on port https://{self.address}:{str(self.port)}...")
        httpd.serve_forever()

    def create_handler(self, routes : dict):
        """
        Create a custom HTTP request handler.

        Parameters:
            routes (dict): A dictionary of routes and their corresponding handlers.

        Returns:
            CustomHTTPRequestHandler: The custom HTTP request handler.
        """
        class CustomHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                handler = routes.get(self.path, self.handle_404)
                handler(self)

            def handle_404(self, optionalself=None):
                self.send_response(404)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"Page not found")
        
        return CustomHTTPRequestHandler

class SSLConnection:
    def __init__(
        self,
        host : str, 
        port : int, 
        cert : Certificate, 
        private_key : PrivateKeyTypes, 
        passphrase : str
    ):
        """
        Initialize an SSL connection.

        Parameters:
            host (str): The host to connect to.
            port (int): The port to connect to.
            cert (Certificate): The client certificate.
            private_key (PrivateKeyTypes): The client private key.
            passphrase (str): The passphrase for the private key.
        """
        self.host = host
        self.port = port
        self.cert = cert
        self.private_key = private_key
        self.passphrase = passphrase

        self.create_context()
        self.get_server_certificate()
        self.connect()

    def create_context(self):
        """
        Create the SSL context for the connection.
        """
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.load_verify_locations(cafile="../MASA/ca/CA_masa_ca.crt")
        self.context = load_local_cas(self.context)
        self.context.load_cert_chain(certfile=self.cert, keyfile=self.private_key, password=self.passphrase)

    def connect(self):
        """
        Connect to the server.
        """
        self.connection = http.client.HTTPSConnection(self.host, port=self.port, context=self.context)

    def get_server_certificate(self) -> Certificate:
        """
        Get the server certificate.

        Returns:
            Certificate: The server certificate.
        """
        with socket.create_connection((self.host, self.port)) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.host) as ssock:
                server_cert_bytes = ssock.getpeercert(True)
        self.server_cert = load_certificate_from_bytes(server_cert_bytes)

    def post_request(self, url : str, data : str = None):
        """
        Send a POST request to the server.

        Parameters:
            url (str): The URL to send the request to.
            data (str): The data to include in the request body.

        Returns:
            bytes: The response body.
        """
        self.connection.request(method="POST", url=url, body=data)

        response = self.connection.getresponse()
        return response.read()
