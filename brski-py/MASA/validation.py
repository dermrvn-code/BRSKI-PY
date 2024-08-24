# validation.py
from Certificates.Certificate import load_certificate_from_bytes
from cryptography.x509 import ObjectIdentifier, oid
from Utils.Interface import yes_or_no
from Utils.Printer import print_error, print_success
from Voucher.VoucherRequest import VoucherRequest


def validate_voucher_request(
    voucher_request: VoucherRequest, registrar_cert_bytes: bytes | None
) -> tuple[int, str]:
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
