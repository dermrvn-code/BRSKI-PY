from paths import set_parent_dir

script_dir, parent_dir = set_parent_dir(__file__)

from Certificates.Certificate import load_certificate_from_bytes
from cryptography.x509 import AuthorityKeyIdentifier, ExtendedKeyUsage, ObjectIdentifier
from Utils.Interface import yes_or_no
from Utils.Printer import print_error, print_success
from Voucher.VoucherRequest import VoucherRequest


def validate_voucher_request(
    voucher_request: VoucherRequest,
    *,
    idevid_cert_bytes: bytes | None,
    registrar_cert_bytes: bytes | None,
) -> tuple[int, str]:

    if registrar_cert_bytes is None:
        msg = "No registrar certificate given"
        print_error(msg)
        return 1, msg
    registrar_cert = load_certificate_from_bytes(registrar_cert_bytes)

    if idevid_cert_bytes is None:
        msg = "No idevid certificate given"
        print_error(msg)
        return 1, msg
    idevid_cert = load_certificate_from_bytes(idevid_cert_bytes)

    # Check if the registrar certificate is authorized to issue vouchers
    cmc_ra_oid = ObjectIdentifier("1.3.6.1.5.5.7.3.28")  # id-kp-cmcRA OID
    eku_extension = registrar_cert.extensions.get_extension_for_class(
        ExtendedKeyUsage
    ).value

    if cmc_ra_oid not in eku_extension:
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

    idevid_authkey = voucher_request.idevid_issuer
    if idevid_authkey is None:
        msg = "No idevid issuer in voucher request"
        print_error()
        return 1, msg

    idevid_cert_authkey = idevid_cert.extensions.get_extension_for_class(
        AuthorityKeyIdentifier
    ).value.key_identifier
    if idevid_authkey != idevid_cert_authkey:
        msg = "IDEVID issuer mismatch"
        print_error(msg)
        return 2, msg

    # Validate prior signature
    if not voucher_request.verify_prior_signed(idevid_cert.public_key()):
        msg = "Voucher request prior signature invalid"
        print_error(msg)
        return 2, msg
    else:
        print_success("Voucher request prior signature valid")

    """ 
    Additional validation of the voucher request can be made here
    """

    serial_number = voucher_request.serial_number
    if not yes_or_no(
        f"Can you validate the voucher request with serial number {serial_number}?"
    ):
        return 2, "The MASA rejected the voucher request"

    return 3, ""
