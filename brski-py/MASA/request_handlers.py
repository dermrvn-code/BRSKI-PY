# request_handlers.py
import base64
import json
import os

from creation import *
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import oid
from paths import *
from validation import *

script_dir, parent_dir = set_parent_dir(__file__)

from Certificates.Certificate import load_certificate_from_bytes
from Certificates.Keys import load_public_key_from_path
from Utils.Dicts import array_to_dict
from Utils.HTTPS import send_404, send_406
from Utils.Logger import Logger
from Utils.Printer import print_descriptor, print_error, print_info, print_success
from Voucher.Voucher import parse_voucher
from Voucher.VoucherRequest import parse_voucher_request


def handle_request_voucher(self, global_logger: Logger):
    content_length = int(self.headers["Content-Length"])
    x_ra_cert = self.headers["X-RA-Cert"]
    post_data = self.rfile.read(content_length)
    voucher_request_dict = json.loads(post_data)

    try:
        voucher_request = parse_voucher_request(voucher_request_dict)
    except ValueError:
        log_error(
            global_logger, "(not parsed)", "Voucher request format could not be parsed"
        )
        return

    idev_logger = Logger(
        os.path.join(script_dir, logs_folder, f"{voucher_request.serial_number}.log")
    )
    audit_logger = Logger(
        os.path.join(
            script_dir, auditlog_folder, f"{voucher_request.serial_number}.log"
        )
    )
    idev_logger.log(f"Received voucher request: {voucher_request.to_json()}")

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
    voucher_json = voucher.to_json()

    idev_logger.log(f"Issuing voucher: {voucher_json}")

    print_descriptor("MASA issued voucher:")
    voucher.print()

    audit_logger.log(voucher_json)

    # Send response
    self.send_response(200)
    self.send_header("Content-type", "text/json")
    self.end_headers()
    self.wfile.write(str.encode(voucher_json))


def handle_request_audit_log(self, global_logger: Logger):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)
    voucher_request_dict = json.loads(post_data)

    try:
        voucher_request = parse_voucher_request(voucher_request_dict)
    except ValueError:
        log_error(
            global_logger, "(not parsed)", "Voucher request format could not be parsed"
        )
        return

    audit_logger = Logger(
        os.path.join(
            script_dir, auditlog_folder, f"{voucher_request.serial_number}.log"
        )
    )

    logs = audit_logger.get_log_list()

    events = []

    for log in logs:
        time = log.get("time", "")
        voucher = log.get("message", "")

        try:
            voucher = parse_voucher(voucher)
        except ValueError:
            continue

        if voucher.idevid_issuer is None:
            continue

        pinned_domain_cert = load_certificate_from_bytes(voucher.pinned_domain_cert)
        subject_key_identifier = pinned_domain_cert.extensions.get_extension_for_oid(
            oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        domain = subject_key_identifier.value.key_identifier  # type: ignore

        event = {
            "date": time,
            "domainID": base64.b64encode(domain).decode(),
            "nonce": (
                base64.b64encode(voucher.nonce).decode()
                if voucher.nonce is not None
                else ""
            ),
            "assertion": voucher.assertion.value,
        }
        events.append(event)

    response = {"version": "1", "events": events}
    response_json = json.dumps((response))

    global_logger.log(
        f"Audit log requested for serial number {voucher_request.serial_number}"
    )

    self.send_response(200)
    self.send_header("Content-type", "application/json")
    self.end_headers()
    self.wfile.write(response_json.encode())


def handle_public_key(self):
    client_cert_dict = self.request.getpeercert()
    subject = client_cert_dict.get("subject", "")
    subject = array_to_dict(subject)
    print_info(
        f"Client '{subject.get('commonName')}' with serialNumber '{subject.get('serialNumber')}' requested a public key"
    )

    public_key = load_public_key_from_path(
        os.path.join(script_dir, public_key_file_path)
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
