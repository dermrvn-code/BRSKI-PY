import base64

from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from paths import set_parent_dir

script_dir, parent_dir = set_parent_dir(__file__)

from Utils.Printer import *
from Voucher.Voucher import Voucher
from Voucher.VoucherRequest import VoucherRequest


def validate_voucher(
    voucher: Voucher,
    request: VoucherRequest,
    registrar_ra_cert: bytes,
    masa_public_key: PublicKeyTypes | None,
) -> tuple[bool, str]:
    """
    Validates a voucher received from the MASA server.

    Args:
        voucher (Voucher): The voucher to be validated.
        request (VoucherRequest): The voucher request the voucher was issued for.
        registrar_ra_cert (bytes): The certificate of the registrar RA.

    Returns:
        Tuple:
        - bool: True if the voucher is valid, False otherwise.
        - str: The error message if the voucher is invalid.
    """

    if masa_public_key is None:
        return False, "MASA public key could not be extracted"

    if not voucher.verify(masa_public_key):
        return False, "Voucher signature invalid"
    
    if voucher.idevid_issuer != request.idevid_issuer:
        return False, "IDEVID issuer mismatch"

    if voucher.serial_number != request.serial_number:
        return False, "Serial number mismatch"

    if voucher.nonce != request.nonce:
        return False, "Nonce mismatch"

    if voucher.pinned_domain_cert == None:
        return False, "Pinned domain certificate missing"
    else:
        if base64.b64encode(voucher.pinned_domain_cert) != base64.b64encode(
            registrar_ra_cert
        ):
            return False, "Registrar RA certificate mismatch"

    # TODO: Implement any further validation and check of voucher

    return True, ""
