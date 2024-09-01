from Certificates.Certificate import load_certificate_from_bytes
from cryptography.x509 import CertificateSigningRequest
from cryptography.x509.oid import NameOID
from enroll import get_device_enrollment_status
from log import log_error
from paths import set_parent_dir

script_dir, parent_dir = set_parent_dir(__file__)

from Utils.Logger import Logger
from Utils.Printer import *
from Voucher.Voucher import Voucher
from Voucher.VoucherRequest import VoucherRequest


def validate_voucher_request(
    voucher_request: VoucherRequest,
    *,
    idevid_cert_bytes: bytes | None,
    idev_logger: Logger,
) -> tuple[int, str]:
    """
    Validates a voucher request send by the pledge.
    Checks if the peer certificate matches the idev issuer certificate and if the serial numbers match.

    Args:
        voucher_request (VoucherRequest): The voucher request to be validated.
        pledge_cert_dict (dict): The dictionary representation of the pledge certificate.
        idev_logger (Logger): The logger to log the validation results.

    Returns:
        Tuple:
        - int: 1 if the request is in wrong format, 2 if authentication fails, 3 if the request is valid.
        - str: The error message if the request is invalid.
    """

    # Get the idevid issuer certificate from the request
    if idevid_cert_bytes is None:
        msg = "No idevid issuer in voucher request"
        log_error(idev_logger, voucher_request.serial_number, msg)
        return 1, msg
    idevid_cert = load_certificate_from_bytes(idevid_cert_bytes)

    # Verify the signature of the voucher request
    if not voucher_request.verify(idevid_cert.public_key()):
        msg = "Voucher request signature invalid"
        log_error(idev_logger, voucher_request.serial_number, msg)
        return 2, msg
    else:
        print_success("Voucher request signature valid")


    # Get the subjects serial number from the idevid certificate
    idev_subject = idevid_cert.subject
    idev_subject_serial_number = idev_subject.get_attributes_for_oid(
        NameOID.SERIAL_NUMBER
    )[0].value

    # Get voucher request serial number
    voucher_serial_number = voucher_request.serial_number

    print_info("Checking in with pledge with serial number", voucher_serial_number)

    # Check if serial numbers across all certs and requests match
    if (
        not idev_subject_serial_number
        == voucher_serial_number
    ):
        msg = f"Serial numbers do not match: {idev_subject_serial_number} != {voucher_serial_number}"
        log_error(
            idev_logger,
            voucher_request.serial_number,
            msg,
        )
        return 2, msg
    else:
        print_success("Serial numbers match")

    # TODO: Implement any further validation and check of voucher request

    return 3, ""


def validate_voucher(voucher: Voucher | None) -> tuple[bool, str]:
    """
    Validates the voucher received from the MASA.

    Args:
        voucher (Voucher): The voucher to be validated.

    Returns:
        Tuple:
        - bool: True if the voucher is valid, False otherwise.
        - str: The error message if the voucher is invalid.
    """
    if voucher is None:
        return False, "MASA did not issue a voucher"

    # TODO: Implement any further validation and check of voucher

    return True, ""


def validate_ldevid_cert_request(
    request: CertificateSigningRequest, serialnumber: str
) -> tuple[bool, str]:

    device_enrollment_status = get_device_enrollment_status(serialnumber)

    if not device_enrollment_status.get("allowed", False):
        return False, "Pledge is not allowed to request LDevID Certificate"
    
    # TODO: Implement any further validation and check of LDevID Certificate request

    return True, ""

