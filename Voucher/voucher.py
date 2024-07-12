import json
import base64
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.x509 import  Certificate


import sys
sys.path.append("../") 
from Voucher.Assertion import Assertion
from Certificates.Signature import sign, verify

class Voucher:
    def __init__(self, created_on : datetime,
                 assertion : Assertion, serial_number : str, 
                 pinned_domain_cert : bytes, expires_on : datetime = None,
                 idevid_issuer : bytes = None, 
                 domain_cert_revocation_checks : bool = None, nonce : bytes = None,
                 last_renewal_date : datetime = None):
        self.created_on : datetime = created_on
        self.expires_on : datetime = expires_on
        self.assertion : Assertion= assertion
        self.serial_number : str = serial_number
        self.idevid_issuer : bytes = idevid_issuer
        self.pinned_domain_cert : bytes = pinned_domain_cert
        self.domain_cert_revocation_checks : bool = domain_cert_revocation_checks
        self.nonce : bytes = nonce
        self.last_renewal_date : datetime = last_renewal_date
        self.signature : bytes = None

    def sign(self, signer_private_key : PrivateKeyTypes) -> bytes:
        # Create a copy of the voucher data dictionary without masa_signature
        data_to_sign = self.to_dict(True)
        
        # Convert to JSON and encode
        voucher_data = json.dumps(data_to_sign, sort_keys=True).encode('utf-8')
        
        self.signature = sign(voucher_data, signer_private_key)

    def verify(self, signer_public_key : PublicKeyTypes) -> bool:
        if self.signature is None:
            raise ValueError("Voucher is not signed")
        
        # Create a copy of the voucher data dictionary without masa_signature
        data_to_verify = self.to_dict(True)
        
        # Convert to JSON and encode
        voucher_data = json.dumps(data_to_verify, sort_keys=True).encode('utf-8')
        
        return verify(self.signature, voucher_data, signer_public_key)

    def to_dict(self, exclude_signature : bool = False) -> dict:
        dict = {
            "created-on": self.created_on.isoformat(),
            "expire-on": self.expires_on.isoformat() if self.expires_on is not None else None,
            "assertion": self.assertion.value,
            "serial-number": self.serial_number,
            "idevid-issuer": base64.b64encode(self.idevid_issuer).decode('utf-8') if self.idevid_issuer is not None else None,
            "pinned-domain-cert": base64.b64encode(self.pinned_domain_cert).decode('utf-8'),
            "domain-cert-revocation-checks": self.domain_cert_revocation_checks,
            "nonce": base64.b64encode(self.nonce).decode('utf-8') if self.nonce is not None else None,
            "last-renewal-date": self.last_renewal_date.isoformat() if self.last_renewal_date is not None else None,
        }

        if not exclude_signature and self.signature is not None:
            dict["signature"] = base64.b64encode(self.signature).decode('utf-8')

        dict = {key: value for key, value in dict.items() if value is not None}

        return dict

def create_voucher(
        masa_private_key : PrivateKeyTypes, 
        registrar_cert : bytes, 
        assertion : Assertion, 
        serial_number : str, 
        idevid_issuer : bytes,
        validity_days : int = 7) -> Voucher:
    nonce = base64.b64encode(b'some_random_nonce')
    current_time = datetime.now(timezone.utc)
    expiration_time = (datetime.now(timezone.utc) + timedelta(days=validity_days))
    pinned_domain_cert = base64.b64encode(registrar_cert)
    voucher = Voucher(
        created_on=current_time,
        expires_on=expiration_time,
        assertion=assertion,
        serial_number=serial_number,
        idevid_issuer=idevid_issuer,
        pinned_domain_cert=pinned_domain_cert,
        domain_cert_revocation_checks=False,
        nonce=nonce,
        last_renewal_date=current_time
    )
    voucher.sign(masa_private_key)
    return voucher

def parse_voucher(voucher_json : str) -> Voucher:
    voucher_dict = json.loads(voucher_json)
    voucher = Voucher(
        created_on=datetime.fromisoformat(voucher_dict.get("created-on")),
        expires_on=datetime.fromisoformat(voucher_dict.get("expire-on")),
        assertion=Assertion(voucher_dict.get("assertion")),
        serial_number=voucher_dict.get("serial-number"),
        idevid_issuer=base64.b64decode(voucher_dict.get("idevid-issuer").encode('utf-8')),
        pinned_domain_cert=base64.b64decode(voucher_dict.get("pinned-domain-cert").encode('utf-8')),
        domain_cert_revocation_checks=voucher_dict.get("domain-cert-revocation-checks"),
        nonce=base64.b64decode(voucher_dict.get("nonce").encode('utf-8')),
        last_renewal_date=datetime.fromisoformat(voucher_dict.get("last-renewal-date"))
    )

    voucher.signature = base64.b64decode(voucher_dict["signature"].encode('utf-8'))
    return voucher
