# app.py
import os
import sys

from request_handlers import (
    handle_public_key,
    handle_request_audit_log,
    handle_request_voucher,
)

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from Utils.Config import Config
from Utils.HTTPS import HTTPSServer
from Utils.Logger import Logger
from Utils.Printer import print_title

global_logger = Logger(os.path.join(script_dir, "masa.log"))


def main() -> None:
    print_title("MASA")
    routes = {
        Config.get("MASA", "brskipath"): (handle_request_voucher, global_logger),
        Config.get("MASA", "publickeypath"): handle_public_key,
        Config.get("MASA", "auditlogpath"): (handle_request_audit_log, global_logger),
    }
    certfile = os.path.join(script_dir, "certs/cert_masa.crt")
    keyfile = os.path.join(script_dir, "certs/cert_private_masa.key")
    passphrasefile = os.path.join(script_dir, "certs/passphrase_masa.txt")
    local_cas = Config.get_values_from_section("CAS")

    server = HTTPSServer(
        address=Config.get("MASA", "hostname"),
        port=Config.get("MASA", "port"),
        routes_post=routes,
        certfile=certfile,
        keyfile=keyfile,
        passphrasefile=passphrasefile,
        local_cas=local_cas,
    )
    server.start()


if __name__ == "__main__":
    main()
