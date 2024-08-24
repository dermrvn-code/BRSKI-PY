import json
import os

from log import log_error
from masa_communication import *
from paths import logs_folder, requestslog_folder, set_parent_dir

script_dir, parent_dir = set_parent_dir(__file__)

from Utils.Dicts import array_to_dict
from Utils.HTTPS import send_404, send_406
from Utils.Logger import Logger
from Utils.Printer import *
from validation import *
from Voucher.VoucherRequest import parse_voucher_request


def handle_voucher_status(self):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)
    pledge_cert_dict = self.request.getpeercert()
    subject = array_to_dict(pledge_cert_dict.get("subject"))

    idev_logger = Logger(os.path.join(script_dir, logs_folder, f"{subject.get('serialNumber', '')}.log"))

    if pledge_cert_dict is None:
        send_404(self, "No peer certificate found")
        return

    voucher_status = json.loads(post_data)

    # version = voucher_status.get("version", "")
    status = voucher_status.get("status", False)
    reason = voucher_status.get("reason", "")
    reason_context = voucher_status.get("reason_context", "")

    if status:
        print_success(
            "Voucher status is valid for pledge with serial number",
            subject.get("serialNumber", ""),
        )
    else:
        print_error(
            "Voucher status is invalid for pledge with serial number ",
            subject.get("serialNumber", ""),
        )
        print_info(f"Reason: {reason}")
        print_info(f"Reason context: {reason_context}")
        idev_logger.log(f"Voucher status for pledge with serialNumber {subject.get("serialNumber", "")} is invalid: {reason} - {reason_context}")

    idev_logger.log(f"Voucher is valid for pledge with serial number {subject.get('serialNumber', '')}")

    self.send_response(200)
    self.send_header("Content-type", "text/plain")
    self.end_headers()
    self.wfile.write(b"OK")

    # Request audit log from MASA
    audit_log = request_audit_log_from_masa(subject.get("serialNumber", ""))
    print_descriptor("Audit log received from MASA")
    prettyprint_json(audit_log, True)

    # TODO: Implement any further processing of the audit log
    


def handle_request_voucher(self):
    content_length = int(self.headers["Content-Length"])
    post_data = self.rfile.read(content_length)

    voucher_request_json = json.loads(post_data)
    voucher_request = parse_voucher_request(voucher_request_json)

    idev_logger = Logger(os.path.join(script_dir, logs_folder, f"{voucher_request.serial_number}.log"))
    request_logger = Logger(os.path.join(script_dir,requestslog_folder, f"{voucher_request.serial_number}.log"))
    idev_logger.log(f"Received voucher request: {voucher_request.to_string()}")

    pledge_cert_dict = self.request.getpeercert()
    pledge_cert_bytes = self.request.getpeercert(True)

    request_valid, message = validate_voucher_request(voucher_request, pledge_cert_dict, idev_logger=idev_logger)

    if request_valid == 1:
        send_406(self, "Wrong Request Format")
        return
    elif request_valid == 3:
        print_success("Voucher request is valid")
    else:
        send_404(self, "Authentication failed")
        return

    request_logger.log(f"{voucher_request.to_string()}")

    idev_logger.log(
        f"Voucher request forwarded for serial number {voucher_request.serial_number}"
    )
    hostname, port, path = get_masa_url(pledge_cert_bytes)
    
    if hostname == None or port == None or path == None:
        send_404(self, "No MASA URL found")
        return
    
    voucher, message = request_voucher_from_masa(voucher_request, hostname, port, path)

    voucher_valid = False
    if voucher is None:
        send_404(self, message)
        log_error(idev_logger, voucher_request.serial_number, message, False)
        return

    voucher_valid, message = validate_voucher(voucher)

    if not voucher_valid:
        send_404(self, message)
        log_error(idev_logger, voucher_request.serial_number, message, False)
    else:
        print_success("Voucher is valid")
        idev_logger.log(f"Voucher issued and forwarded: {voucher.to_string()}")

        # if voucher is valid, send it to the pledge
        self.send_response(200)
        self.send_header("Content-type", "text/json")
        self.end_headers()
        self.wfile.write(str.encode(voucher.to_string()))  
