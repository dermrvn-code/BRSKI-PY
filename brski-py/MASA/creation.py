# creation.py
import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from Certificates.Keys import load_passphrase_from_path, load_private_key_from_path
from Voucher.Voucher import Voucher, create_voucher_from_request
from Voucher.VoucherRequest import VoucherRequest


def create_voucher(
    voucher_request: VoucherRequest, registrar_cert_bytes: bytes
) -> Voucher:
    masa_passphrase_path = os.path.join(script_dir, "certs/passphrase_masa.txt")
    private_key_path = os.path.join(script_dir, "certs/cert_private_masa.key")

    masa_passphrase = load_passphrase_from_path(masa_passphrase_path)
    private_key = load_private_key_from_path(private_key_path, masa_passphrase)
    voucher = create_voucher_from_request(
        voucher_request, registrar_cert_bytes, private_key
    )
    return voucher
