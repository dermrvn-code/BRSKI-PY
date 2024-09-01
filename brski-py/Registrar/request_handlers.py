import json
import os
from http.server import BaseHTTPRequestHandler

from enroll import set_device_enrollment_status
from log import log_error
from masa_communication import *
from paths import logs_folder, requestslog_folder, set_parent_dir
from validation import validate_ldevid_cert_request

script_dir, parent_dir = set_parent_dir(__file__)

from Certificates.Certificate import (generate_ldevid_cert_from_request,
                                      load_request_from_bytes)
from Utils.Dicts import array_to_dict
from Utils.HTTPS import send_404, send_406
from Utils.Logger import Logger
from Utils.Printer import *
from validation import *
from Voucher.VoucherRequest import parse_voucher_request


def handle_request_voucher(request_handler : BaseHTTPRequestHandler):
    content_length = int(request_handler.headers["Content-Length"])
    post_data = request_handler.rfile.read(content_length)

    voucher_request_json = json.loads(post_data)
    voucher_request = parse_voucher_request(voucher_request_json)

    idev_logger = Logger(os.path.join(script_dir, logs_folder, f"{voucher_request.serial_number}.log"))
    request_logger = Logger(os.path.join(script_dir,requestslog_folder, f"{voucher_request.serial_number}.log"))
    idev_logger.log(f"Received voucher request: {voucher_request.to_json()}")

    pledge_cert_dict = request_handler.request.getpeercert()
    pledge_cert_bytes = request_handler.request.getpeercert(True)

    request_valid, message = validate_voucher_request(voucher_request, idevid_cert_bytes=pledge_cert_bytes, pledge_cert_dict=pledge_cert_dict, idev_logger=idev_logger)

    if request_valid == 1:
        send_406(request_handler, "Wrong Request Format")
        return
    elif request_valid == 3:
        print_success("Voucher request is valid")
    else:
        send_404(request_handler, "Authentication failed")
        return

    request_logger.log(f"{voucher_request.to_json()}")

    idev_logger.log(
        f"Voucher request forwarded for serial number {voucher_request.serial_number}"
    )
    hostname, port, path = get_masa_url(pledge_cert_bytes)
    
    if hostname == None or port == None or path == None:
        send_404(request_handler, "No MASA URL found")
        return
    
    voucher, message = request_voucher_from_masa(
        voucher_request, 
        idevid_cert_bytes=pledge_cert_bytes, 
        hostname=hostname, 
        port=port, path=path
    )

    voucher_valid = False
    if voucher is None:
        send_404(request_handler, message)
        log_error(idev_logger, voucher_request.serial_number, message, False)
        return

    voucher_valid, message = validate_voucher(voucher)

    if not voucher_valid:
        send_404(request_handler, message)
        log_error(idev_logger, voucher_request.serial_number, message, False)
    else:
        print_success("Voucher is valid")
        idev_logger.log(f"Voucher issued and forwarded: {voucher.to_json()}")

        # if voucher is valid, send it to the pledge
        request_handler.send_response(200)
        request_handler.send_header("Content-type", "text/json")
        request_handler.end_headers()
        request_handler.wfile.write(str.encode(voucher.to_json()))  

def handle_voucher_status(request_handler : BaseHTTPRequestHandler):
    content_length = int(request_handler.headers["Content-Length"])
    post_data = request_handler.rfile.read(content_length)
    pledge_cert_bytes = request_handler.request.getpeercert(True)
    pledge_cert_dict = request_handler.request.getpeercert()
    subject = array_to_dict(pledge_cert_dict.get("subject"))
    pledge_serialnumber = subject.get("serialNumber", "")

    idev_logger = Logger(os.path.join(script_dir, logs_folder, f"{pledge_serialnumber}.log"))

    if pledge_cert_dict is None:
        send_404(request_handler, "No peer certificate found")
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

    request_handler.send_response(200)
    request_handler.send_header("Content-type", "text/plain")
    request_handler.end_headers()
    request_handler.wfile.write(b"OK")

    # Request audit log from MASA
    audit_log = request_audit_log_from_masa(subject.get("serialNumber", ""), pledge_cert_bytes)
    print_descriptor("Audit log received from MASA")
    prettyprint_json(audit_log, True)

    # TODO: Implement any further processing and validation of the audit log

    print_success("Setting device enrollment status to allowed")
    set_device_enrollment_status(pledge_serialnumber, allowed=True)

def handle_request_ldevid_cert(request_handler : BaseHTTPRequestHandler):
    content_length = int(request_handler.headers["Content-Length"])
    request_data = request_handler.rfile.read(content_length)
    pledge_cert_dict = request_handler.request.getpeercert()

    subject = pledge_cert_dict.get("subject", "")
    subject = array_to_dict(subject)
    serialnumber = subject.get("serialNumber")

    if serialnumber is None:
        send_404(request_handler, "No serial number found in idevcert, could not issue ldevid cert")
        return
    


    request = load_request_from_bytes(request_data)

    idev_logger = Logger(os.path.join(script_dir, logs_folder, f"{serialnumber}.log"))
    idev_logger.log(f"Received ldevid cert request for pledge with serial number: {serialnumber}")

    request_valid, message = validate_ldevid_cert_request(request, serialnumber)

    if not request_valid:
        send_404(request_handler, message)
        msg = f"Request for ldevid cert for pledge with serial number: {serialnumber} is invalid: {message}"
        idev_logger.log(msg)
        print_error(msg)
        return

    dest_folder = os.path.join(script_dir, "issued_ldevid_certs")
    ca_cert_path = os.path.join(script_dir, "certs/ca/ca_registrar_ca.crt")
    ca_key_path = os.path.join(script_dir, "certs/ca/ca_private_registrar_ca.key")
    passphrase_path = os.path.join(script_dir, "certs/ca/passphrase_registrar_ca.txt")

    cert = generate_ldevid_cert_from_request(
            request, 
            ca_cert_path=ca_cert_path, 
            ca_key_path=ca_key_path, 
            ca_passphrase_path=passphrase_path, 
            dest_folder=dest_folder
        )

    set_device_enrollment_status(serialnumber, enrolled=True)

    msg = f"Certificate issued and enrollment completed for pledge with serial number: {serialnumber}"
    print_success(msg)
    idev_logger.log(msg)

    request_handler.send_response(200)
    request_handler.send_header("Content-type", "application/pkix-cert")
    request_handler.end_headers()
    request_handler.wfile.write(cert.public_bytes(Encoding.PEM))  
