from paths import *

script_dir, parent_dir = set_parent_dir(__file__)

from Certificates.Keys import load_passphrase_from_path, load_private_key_from_path
from Voucher.Voucher import Voucher, create_voucher_from_request
from Voucher.VoucherBase import Assertion
from Voucher.VoucherRequest import VoucherRequest


def create_voucher(
    voucher_request: VoucherRequest, registrar_cert_bytes: bytes, assertion: Assertion
) -> Voucher:
    masa_passphrase_path = os.path.join(script_dir, passphrase_file_path)
    private_key_path = os.path.join(script_dir, key_file_path)

    masa_passphrase = load_passphrase_from_path(masa_passphrase_path)
    private_key = load_private_key_from_path(private_key_path, masa_passphrase)
    voucher = create_voucher_from_request(
        voucher_request,
        pinned_domain_cert=registrar_cert_bytes,
        masa_private_key=private_key,
        assertion=assertion,
    )
    return voucher
