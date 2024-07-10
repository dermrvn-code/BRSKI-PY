import http.server
import ssl

import sys
sys.path.append("../") 
from Certificates.CertificateTools import load_passphrase


class SimpleHTTPSServer:
    def __init__(self, address, port, routes, certfile, keyfile, passphrasefile, cafile):
        self.address = address
        self.port = port
        self.routes = routes
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile

        passphrase = load_passphrase(passphrasefile)
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

        print("Server running on port https://" + self.address + ":" + str(self.port) + "...")
        httpd.serve_forever()

    def create_handler(self, routes):
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