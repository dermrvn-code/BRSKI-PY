import http.client
import http.server
import os
import socket
import ssl

from Certificates.Keys import load_passphrase_from_path


def load_local_cas(context: ssl.SSLContext, ca_files: list) -> ssl.SSLContext:
    """
    Load local Certificate Authorities (CAs) into the SSL context.

    Args:
        context (SSLContext): The SSL context.
        ca_files (list): A list of file paths to the CAs.

    Returns:
        SSLContext: The SSL context with loaded CAs.
    """
    if len(ca_files) == 0:
        return context

    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))

    combined_cas = ""
    for ca_file in ca_files:
        ca_file_path = os.path.join(parent_dir, ca_file)

        with open(ca_file_path, "r") as file:
            combined_cas += file.read()

    # Load the combined CAs
    context.load_verify_locations(cadata=combined_cas)
    return context


class HTTPSServer:
    def __init__(
        self,
        *,
        address: str,
        port: str | int,
        certfile: str,
        keyfile: str,
        passphrasefile: str,
        local_cas: list[str] = [],
        routes_post: dict = {},
        routes_get: dict = {},
    ):
        """
        Initialize an HTTPS server.

        Args:
            address (str): The server address.
            port (str | int): The server port.
            certfile (str): The path to the server certificate file.
            keyfile (str): The path to the server private key file.
            passphrasefile (str): The path to the file containing the passphrase for the private key.
            local_cas (list): A list of file paths to the local Certificate Authorities (CAs).
            routes_post (dict): A dictionary of POST routes and their corresponding handlers.
            routes_get (dict): A dictionary of GET routes and their corresponding handlers.

        Raises:
            ValueError: If no routes are provided.
            ValueError: If the port is not a string or an integer.
        """
        if routes_post is {} and routes_get is {}:
            raise ValueError("No routes provided")

        if not isinstance(port, (str, int)):
            raise ValueError("Port must be a string or an integer")

        # Parse port if entered as string
        if isinstance(port, str):
            port = int(port)

        self.address = address
        self.port = port
        self.local_cas = local_cas
        self.routes_post = routes_post
        self.routes_get = routes_get
        self.certfile = certfile
        self.keyfile = keyfile

        passphrase = load_passphrase_from_path(passphrasefile)
        self.passphrase = passphrase

    def start(self):
        """
        Start the HTTPS server.
        """
        try:
            handler = self.create_handler(self.routes_post, self.routes_get)
            server_address = (self.address, self.port)
            self.httpd = http.server.HTTPServer(server_address, handler)

            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(
                certfile=self.certfile, keyfile=self.keyfile, password=self.passphrase
            )
            context = load_local_cas(context, self.local_cas)
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)

            print(f"Server running on port https://{self.address}:{str(self.port)}...")
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopping server...")
            self.stop()
            print("Server stopped.")

    def stop(self):
        """
        Stop the HTTPS server.
        """
        self.httpd.shutdown()

    def create_handler(self, routes_post: dict, routes_get: dict):
        """
        Create a custom HTTP request handler.

        Args:
            routes (dict): A dictionary of routes and their corresponding handlers.

        Returns:
            CustomHTTPRequestHandler: The custom HTTP request handler.
        """

        class CustomHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                handler = routes_post.get(self.path, self.handle_404)
                handler(self)

            def do_GET(self):
                data = self.path.split("?")
                handler = routes_get.get(data[0], self.handle_404)
                handler(self, data[1] if len(data) > 1 else None)

            def handle_404(self=None):
                self.send_response(404)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"Page not found")

        return CustomHTTPRequestHandler


def send_404(self, message: str = "Error 404"):
    self.send_response(404)
    self.send_header("Content-type", "text/plain")
    self.end_headers()
    self.wfile.write(message.encode())


def send_406(self, message: str = "Error 406"):
    self.send_response(406)
    self.send_header("Content-type", "text/plain")
    self.end_headers()
    self.wfile.write(message.encode())


class SSLConnection:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        cert: str,
        private_key: str,
        passphrase: bytes,
        local_cas: list[str] = [],
    ):
        """
        Initialize an SSL connection.

        Args:
            host (str): The host to connect to.
            port (int): The port to connect to.
            cert (str): The path to the client certificate.
            private_key (str): The path to the client private key.
            passphrase (bytes): The passphrase for the private key.
            local_cas (list): A list of file paths to the local Certificate Authorities (CAs).
        """
        self.host = host
        self.port = port
        self.cert = cert
        self.private_key = private_key
        self.passphrase = passphrase
        self.local_cas = local_cas

        self.create_context()
        self.get_server_certificate_bytes()
        self.connect()

    def create_context(self):
        """
        Create the SSL context for the connection.
        """
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context = load_local_cas(self.context, self.local_cas)
        self.context.load_cert_chain(
            certfile=self.cert,
            keyfile=self.private_key,
            password=self.passphrase,
        )

    def connect(self):
        """
        Connect to the server.
        """
        self.connection = http.client.HTTPSConnection(
            self.host, port=self.port, context=self.context
        )

    def get_server_certificate_bytes(self) -> bytes | None:
        """
        Get the server certificate.

        Returns:
            bytes : The server certificate if it exists, otherwise None.
        """
        with socket.create_connection((self.host, self.port)) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.host) as ssock:
                server_cert_bytes = ssock.getpeercert(True)

        if server_cert_bytes is None:
            return None

        return server_cert_bytes

    def post_request(
        self, url: str, *, data: str = "", headers: dict = {}
    ) -> http.client.HTTPResponse:
        """
        Send a POST request to the server.

        Args:
            url (str): The URL to send the request to.
            data (str): The data to include in the request body.

        Returns:
            HTTPResponse: The response
        """
        self.connection.request(method="POST", url=url, body=data, headers=headers)

        response = self.connection.getresponse()
        return response

    def get_request(self, url: str) -> http.client.HTTPResponse:
        """
        Send a POST request to the server.

        Args:
            url (str): The URL to send the request to.
            data (str): The data to include in the request body.

        Returns:
            HTTPResponse: The response body.
        """
        self.connection.request(method="GET", url=url)

        response = self.connection.getresponse()
        return response
