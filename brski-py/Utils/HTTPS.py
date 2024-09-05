import http.client
import http.server
import os
import socket
import ssl
import threading
import time

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
        enable_socket: bool = False,
        socket_port: str | int | None = None,
    ):
        """
        Initialize an HTTPS server with optional socket communication.

        Args:
            address (str): The server address.
            port (str | int): The server port.
            certfile (str): The path to the server certificate file.
            keyfile (str): The path to the server private key file.
            passphrasefile (str): The path to the file containing the passphrase for the private key.
            local_cas (list): A list of file paths to the local Certificate Authorities (CAs).
            routes_post (dict): A dictionary with the routes as the keys and the values
                                either being the handler or a tuple with the handler
                                and its additional arguments.
            routes_get (dict): A dictionary with the routes as the keys and the values
                                either being the handler or a tuple with the handler
                                and its additional arguments.
            enable_socket (bool): Whether to enable socket communication.
            socket_port (str | int): The port to use for socket communication.

        Raises:
            ValueError: If no routes are provided or if socket communication is enabled but no socket port is provided.

        """
        if routes_post == {} and routes_get == {}:
            raise ValueError("No routes provided")

        if enable_socket and socket_port is None:
            raise ValueError(
                "Socket port must be provided if socket communication is enabled"
            )

        # Parse port if entered as string
        if isinstance(port, str):
            port = int(port)

        if isinstance(socket_port, str):
            socket_port = int(socket_port)

        self.address = address
        self.port = port
        self.local_cas = local_cas
        self.routes_post = routes_post
        self.routes_get = routes_get
        self.certfile = certfile
        self.keyfile = keyfile
        self.enable_socket = enable_socket
        self.socket_port = socket_port

        passphrase = load_passphrase_from_path(passphrasefile)
        self.passphrase = passphrase

    def start(self):
        """
        Start the HTTPS server and optionally the socket server.
        """
        try:
            handler = self.create_handler(self.routes_post, self.routes_get)
            server_address = (self.address, self.port)
            self.httpd = http.server.HTTPServer(server_address, handler)

            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.load_cert_chain(
                certfile=self.certfile, keyfile=self.keyfile, password=self.passphrase
            )
            context = load_local_cas(self.context, self.local_cas)
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)

            # Start the HTTP server in a separate thread
            http_thread = threading.Thread(target=self.httpd.serve_forever)
            http_thread.daemon = True  # terminate the thread when the main thread ends
            http_thread.start()
            print(f"HTTPS server running on https://{self.address}:{self.port}...")

            if self.enable_socket:
                # Start the socket server in a separate thread if enabled
                socket_thread = threading.Thread(target=self.start_socket_server)
                socket_thread.daemon = (
                    True  # terminate the thread when the main thread ends
                )
                socket_thread.start()

            while True:
                time.sleep(1)
                if not http_thread.is_alive():
                    break

        except (KeyboardInterrupt, SystemExit):
            print("\nStopping server...")
            self.stop()
            os.system("taskkill /F /IM cmd.exe")
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
            routes_post (dict): A dictionary with the POST routes.
            routes_get (dict): A dictionary with the GET routes.

        Returns:
            CustomHTTPRequestHandler: The custom HTTP request handler.
        """

        class CustomHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                handler = routes_post.get(self.path, self.handle_404)

                if isinstance(handler, tuple):
                    handler_func, *handler_args = handler
                    handler_func(self, *handler_args)
                else:
                    handler(self)

            def do_GET(self):
                data = self.path.split("?")
                handler = routes_get.get(data[0], self.handle_404)

                if isinstance(handler, tuple):
                    handler_func, *handler_args = handler
                    handler_func(
                        self, data[1] if len(data) > 1 else None, *handler_args
                    )
                else:
                    handler(self, data[1] if len(data) > 1 else None)

            def handle_404(self=None, *args):
                self.send_response(404)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"Page not found")

        return CustomHTTPRequestHandler

    def start_socket_server(self):
        """
        Start the SSL socket server to accept and handle client connections.
        """
        try:
            # Create a socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind the socket to the address and port
            server_socket.bind((self.address, self.socket_port))

            # Start listening for incoming connections
            server_socket.listen(5)
            print(
                f"Socket server listening on https://{self.address}:{self.socket_port}..."
            )

            while True:
                # Accept a new client connection
                client_socket, client_address = server_socket.accept()

                # Wrap the client socket with SSL
                ssl_client_socket = self.context.wrap_socket(
                    client_socket, server_side=True
                )

                # Handle the new client connection in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_socket_client,
                    args=(ssl_client_socket, client_address),
                    daemon=True,
                )
                client_thread.start()

        except Exception as e:
            print(f"Socket server error: {e}")
        finally:
            server_socket.close()

    def handle_socket_client(self, client_socket, client_address):
        """
        Handle communication with a connected socket client.

        Args:
            client_socket (socket.socket): The client's socket.
            client_address (tuple): The client's address (host, port).
        """
        print(f"New connection from {client_address}")

        def chat_window():
            """
            Open a new console chat window for communicating with the client.
            """
            while True:
                try:
                    # Receive message from the client
                    message = client_socket.recv(4096).decode()
                    if not message:
                        print(f"Connection with {client_address} closed.")
                        break
                    print(f"Client ({client_address}): {message}")

                    # Input response from server user
                    response = input("You: ")
                    client_socket.sendall(response.encode())

                except ConnectionResetError:
                    print(f"Connection with {client_address} was reset.")
                    break
                except Exception as e:
                    print(f"Error: {e}")
                    break

            client_socket.close()

        chat_thread = threading.Thread(target=chat_window, daemon=True)
        chat_thread.start()


def send_404(handler: http.server.BaseHTTPRequestHandler, message: str = "Error 404"):
    """
    Sends a 404 response with the specified message.

    Args:
        handler (BaseHTTPRequestHandler): The request handler.
        message (str): The error message to be sent. Default is "Error 404".
    """
    handler.send_response(404)
    handler.send_header("Content-type", "text/plain")
    handler.end_headers()
    handler.wfile.write(message.encode())


def send_406(handler: http.server.BaseHTTPRequestHandler, message: str = "Error 406"):
    """
    Sends a 406 response with the specified message.

    Args:
        BaseHTTPRequestHandler: The request handler.
        str: The error message to be sent. Default is "Error 406".
    """
    handler.send_response(406)
    handler.send_header("Content-type", "text/plain")
    handler.end_headers()
    handler.wfile.write(message.encode())


class SSLConnection:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        cert: str,
        private_key: str,
        passphrasefile: str,
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
        self.local_cas = local_cas

        passphrase = load_passphrase_from_path(passphrasefile)
        self.passphrase = passphrase

        self.create_context()
        self.server_certificate_bytes = self.get_server_certificate_bytes()
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

    def get_request(
        self, url: str, *, body: dict = {}, headers: dict = {}
    ) -> http.client.HTTPResponse:
        """
        Send a POST request to the server.

        Args:
            url (str): The URL to send the request to.
            data (str): The data to include in the request body.

        Returns:
            HTTPResponse: The response body.
        """
        self.connection.request(method="GET", url=url, body=body, headers=headers)

        response = self.connection.getresponse()
        return response


class SSLSocketClient:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        cert: str,
        private_key: str,
        passphrasefile: str,
        local_cas: list[str] = [],
    ):
        """
        Initialize an SSL socket client.

        Args:
            host (str): The server's hostname or IP address.
            port (int): The port to connect to.
            cert (str): The path to the client certificate.
            private_key (str): The path to the client private key.
            passphrasefile (str): The path to the file containing the passphrase for the private key.
            local_cas (list): A list of file paths to the local Certificate Authorities (CAs).
        """
        self.host = host
        self.port = port
        self.cert = cert
        self.private_key = private_key

        self.passphrase = load_passphrase_from_path(passphrasefile)
        self.local_cas = local_cas

        self.context = self.create_context()
        self.connection = None

    def create_context(self) -> ssl.SSLContext:
        """
        Create the SSL context for the socket connection.

        Returns:
            SSLContext: The configured SSL context.
        """
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(
            certfile=self.cert, keyfile=self.private_key, password=self.passphrase
        )
        context = load_local_cas(context, self.local_cas)
        return context

    def connect(self):
        """
        Establish a secure SSL connection to the server.
        """
        raw_socket = socket.create_connection((self.host, self.port))
        self.connection = self.context.wrap_socket(
            raw_socket, server_hostname=self.host
        )
        print(f"Connected to {self.host}:{self.port} over SSL")

    def send_message(self, message: str):
        """
        Send a message to the server.

        Args:
            message (str): The message to send.
        """
        if not self.connection:
            raise ConnectionError("Socket is not connected. Call connect() first.")

        self.connection.sendall(message.encode())
        print(f"Sent: {message}")

    def receive_message(self, buffer_size: int = 4096) -> str:
        """
        Receive a message from the server.

        Args:
            buffer_size (int): The maximum amount of data to be received at once.

        Returns:
            str: The received message.
        """
        if not self.connection:
            raise ConnectionError("Socket is not connected. Call connect() first.")

        data = self.connection.recv(buffer_size)
        message = data.decode()
        return message

    def close(self):
        """
        Close the SSL socket connection.
        """
        if self.connection:
            self.connection.close()
            print("Connection closed.")
        else:
            print("No connection to close.")
