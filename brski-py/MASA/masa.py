import base64
import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

import json

from Certificates.Certificate import load_certificate_from_bytes
from Certificates.Keys import (load_passphrase_from_path,
                               load_private_key_from_path,
                               load_public_key_from_path)
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ObjectIdentifier, oid
from Utils.Config import Config
from Utils.Dicts import array_to_dict
from Utils.HTTPS import HTTPSServer, send_404, send_406
from Utils.Interface import yes_or_no
from Utils.Logger import Logger
from Utils.Printer import *
from Voucher.Voucher import Voucher, create_voucher_from_request, parse_voucher
from Voucher.VoucherRequest import VoucherRequest, parse_voucher_request


def handle_request_voucher(self):
    content_length = int(self.headers["Content-Length"])
    x_ra_cert = self.headers["X-RA-Cert"]
    post_data = self.rfile.read(content_length)
    voucher_request_dict = json.loads(post_data)

    try:
        voucher_request = parse_voucher_request(voucher_request_dict)
    except ValueError:
        log_error(
            global_logger,
            "(not parsed)",
            "Voucher request format could not be parsed",
        )
        return

    idev_logger = Logger(os.path.join(script_dir, f"logs/{voucher_request.serial_number}.log"))
    audit_logger = Logger(os.path.join(script_dir, f"auditlogs/{voucher_request.serial_number}.log"))
    idev_logger.log(f"Received voucher request: {voucher_request.to_string()}")

    registrar_cert_bytes = base64.b64decode(x_ra_cert)

    # Validate client and voucher here
    request_valid, message = validate_voucher_request(
        voucher_request, registrar_cert_bytes
    )

    if request_valid == 1:
        send_406(self, message)
        log_error(idev_logger, voucher_request.serial_number, message)
        return
    elif request_valid == 3:
        print_success("Voucher is issued")
    else:
        send_404(self, message)
        log_error(idev_logger, voucher_request.serial_number, message)
        return

    voucher = create_voucher(voucher_request, registrar_cert_bytes)
    voucher_json = voucher.to_string()

    idev_logger.log(f"Issuing voucher: {voucher_json}")

    print_descriptor("MASA issued voucher:")
    voucher.print()

    audit_logger.log(voucher_json)

    # Send response
    self.send_response(200)
    self.send_header("Content-type", "text/json")
    self.end_headers()
    self.wfile.write(str.encode(voucher_json))

def handle_request_audit_log(self):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)
    voucher_request_dict = json.loads(post_data)

    try:
        voucher_request = parse_voucher_request(voucher_request_dict)
    except ValueError:
        log_error(
            global_logger,
            "(not parsed)",
            "Voucher request format could not be parsed",
        )
        return
    
    audit_logger = Logger(os.path.join(script_dir, f"auditlogs/{voucher_request.serial_number}.log"))

    logs = audit_logger.get_log_list()

    events = []

    for log in logs:
        time = log.get("time", "")
        voucher = log.get("message", "")
        
        try:
            voucher = parse_voucher(voucher)
        except ValueError:
            continue

        if(voucher.idevid_issuer is None):
            continue


        pinned_domain_cert = load_certificate_from_bytes(voucher.pinned_domain_cert)
        subject_key_identifier = pinned_domain_cert.extensions.get_extension_for_oid(
            oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        domain = subject_key_identifier.value.key_identifier # type: ignore

        event = {
            "date": time, 
            "domainID": base64.b64encode(domain).decode(), 
            "nonce": base64.b64encode(voucher.nonce).decode() if voucher.nonce is not None else "", 
            "assertion": voucher.assertion.value,
        }
        events.append(event)

    response = {
        "version": "1",
        "events": events
    }
    response_json = json.dumps((response))

    global_logger.log(f"Audit log requested for serial number {voucher_request.serial_number}")

    self.send_response(200)
    self.send_header("Content-type", "application/json")
    self.end_headers()
    self.wfile.write(response_json.encode())



    


def handle_public_key(self):
    client_cert_dict = self.request.getpeercert()
    subject = client_cert_dict.get("subject", "")
    subject = array_to_dict(subject)
    print_info(f"Client '{subject.get("commonName")}' with serialNumber '{subject.get("serialNumber")}' requested a public key")

    public_key = load_public_key_from_path(
        os.path.join(script_dir, "certs/cert_public_masa.key")
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    print_success("Public key sent")

    self.send_response(200)
    self.send_header("Content-type", "application/x-pem-file")
    self.end_headers()
    self.wfile.write(public_key_bytes)


def log_error(logger: Logger | None, serialNumber: str, msg: str):
    print_error(msg)
    if logger is not None:
        logger.log(f"No voucher was issued for serial number {serialNumber}: {msg}")


def validate_voucher_request(
    voucher_request: VoucherRequest, registrar_cert_bytes: bytes | None
) -> tuple[int, str]:
    """
    Validates a voucher request send by the registrar.

    Args:
        voucher_request (VoucherRequest): The voucher request to be validated.
        registrar_cert (bytes): The certificate of the registrar.

    Returns:
        int: 1 if the request is in wrong format, 2 if authentication fails, 3 if the request is valid.
        str: The message to be displayed in case of an error.
    """

    try:
        voucher_request_dict = voucher_request.to_dict()
    except ValueError:
        msg = "Voucher request format could not be parsed"
        print_error(msg)
        return 1, msg

    # Get the idevid issuer certificate from the request
    if registrar_cert_bytes is None:
        msg = "No registrar certificate given"
        print_error(msg)
        return 1, msg
    registrar_cert = load_certificate_from_bytes(registrar_cert_bytes)

    # Check if the registrar certificate is authorized to issue vouchers
    cmc_ra_oid = ObjectIdentifier("1.3.6.1.5.5.7.3.28")  # id-kp-cmcRA OID
    eku_extension = registrar_cert.extensions.get_extension_for_oid(
        oid.ExtensionOID.EXTENDED_KEY_USAGE
    ).value

    if cmc_ra_oid not in eku_extension:  # type: ignore
        msg = "Registrar certificate is not authorized to issue vouchers"
        print_error(msg)
        return 2, msg

    # Verify the signature of the voucher request
    if not voucher_request.verify(registrar_cert.public_key()):
        msg = "Voucher request signature invalid"
        print_error(msg)
        return 2, msg
    else:
        print_success("Voucher request signature valid")

    # Validate prior signature
    idevid_cert_bytes = voucher_request.idevid_issuer
    if idevid_cert_bytes is None:
        msg = "No idevid issuer in voucher request"
        print_error()
        return 1, msg
    idevid_cert = load_certificate_from_bytes(idevid_cert_bytes)

    if not voucher_request.verify_prior_signed(idevid_cert.public_key()):
        msg = "Voucher request prior signature invalid"
        print_error(msg)
        return 2, msg
    else:
        print_success("Voucher request prior signature valid")

    """ 
    Additional validation of the voucher request can be made here
    """

    serial_number = voucher_request_dict.get("serial-number")
    if not yes_or_no(
        f"Can you validate the voucher request with serial number {serial_number}?"
    ):
        return 2, "The MASA rejected the voucher request"

    return 3, ""


def create_voucher(
    voucher_request: VoucherRequest, registrar_cert_bytes: bytes
) -> Voucher:
    """
    Create a voucher using the given voucher request and registrar certificate bytes.

    Args:
        voucher_request (VoucherRequest): The voucher request object.
        registrar_cert_bytes (bytes): The registrar certificate bytes.

    Returns:
        voucher (Voucher): The created voucher object.
    """
    masa_passphrase_path = os.path.join(script_dir, "certs/passphrase_masa.txt")
    private_key_path = os.path.join(script_dir, "certs/cert_private_masa.key")

    masa_passphrase = load_passphrase_from_path(masa_passphrase_path)
    private_key = load_private_key_from_path(private_key_path, masa_passphrase)
    voucher = create_voucher_from_request(
        voucher_request, registrar_cert_bytes, private_key
    )
    return voucher

global_logger = Logger(os.path.join(script_dir, "masa.log"))
def main() -> None:

    print_title("MASA")
    routes = {
        Config.get("MASA", "brskipath"): handle_request_voucher,
        Config.get("MASA", "publickeypath"): handle_public_key,
        Config.get("MASA", "auditlogpath"): handle_request_audit_log,
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
