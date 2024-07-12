import json
import base64
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes

import sys
sys.path.append("../") 
from Voucher.Assertion import Assertion
from Certificates.Signature import sign, verify


class VoucherRequest:
    def __init__(self, serial_number : str, 
                 created_on : datetime = None, expires_on : datetime = None, 
                 assertion : Assertion = None, 
                 idevid_issuer : bytes = None, pinned_domain_cert : bytes = None, 
                 domain_cert_revocation_checks : bool = None, nonce : bytes = None,
                 last_renewal_date : datetime = None, prior_signed_voucher_request: bytes = None,
                 proximity_registrar_cert: bytes = None):
        
        
        if(assertion == Assertion.PROXIMITY and proximity_registrar_cert == None):
            raise ValueError("Proximity assertion requires proximity registrar certificate")

        self.created_on : datetime = created_on
        self.expires_on : datetime = expires_on
        self.assertion : Assertion= assertion
        self.serial_number : str = serial_number
        self.idevid_issuer : bytes = idevid_issuer
        self.pinned_domain_cert : bytes = pinned_domain_cert
        self.domain_cert_revocation_checks : bool = domain_cert_revocation_checks
        self.nonce : bytes = nonce
        self.last_renewal_date : datetime = last_renewal_date
        self.prior_signed_voucher_request : bytes = prior_signed_voucher_request
        self.proximity_registrar_cert : bytes = proximity_registrar_cert

        self.signature : bytes = None

    def sign(self, signer_private_key : PrivateKeyTypes) -> bytes:
        # Create a copy of the voucher data dictionary without masa_signature
        data_to_sign = self.to_dict(True)
        
        # Convert to JSON and encode
        voucher_data = json.dumps(data_to_sign, sort_keys=True).encode('utf-8')
        
        self.signature = sign(voucher_data, signer_private_key)

    def verify(self, signer_public_key : PublicKeyTypes) -> bool:
        if self.signature is None:
            raise ValueError("Voucher Request is not signed")
        
        # Create a copy of the voucher data dictionary without masa_signature
        data_to_verify = self.to_dict(True)
        
        # Convert to JSON and encode
        voucher_data = json.dumps(data_to_verify, sort_keys=True).encode('utf-8')
        
        return verify(self.signature, voucher_data, signer_public_key)

    def to_dict(self, exclude_signature : bool = False) -> dict:
        dict = {
            "created-on": self.created_on.isoformat() if self.created_on is not None else None,
            "expire-on": self.expires_on.isoformat() if self.expires_on is not None else None,
            "assertion": self.assertion.value if self.assertion is not None else None,
            "serial-number": self.serial_number,
            "idevid-issuer": base64.b64encode(self.idevid_issuer).decode('utf-8') if self.idevid_issuer is not None else None,
            "pinned-domain-cert": base64.b64encode(self.pinned_domain_cert).decode('utf-8') if self.pinned_domain_cert is not None else None,
            "domain-cert-revocation-checks": self.domain_cert_revocation_checks if self.domain_cert_revocation_checks is not None else None,
            "nonce": base64.b64encode(self.nonce).decode('utf-8') if self.nonce is not None else None,
            "last-renewal-date": self.last_renewal_date.isoformat() if self.last_renewal_date is not None else None,
            "prior-signed-voucher-request": base64.b64encode(self.prior_signed_voucher_request).decode('utf-8') if self.prior_signed_voucher_request is not None else None,
            "proximity-registrar-cert": base64.b64encode(self.proximity_registrar_cert).decode('utf-8') if self.proximity_registrar_cert is not None else None
        }

        if not exclude_signature and self.signature is not None:
            dict["signature"] = base64.b64encode(self.signature).decode('utf-8')
        
        dict = {key: value for key, value in dict.items() if value is not None}

        return dict

    

def create_pledge_voucher_request(
        pledge_private_key : PrivateKeyTypes,
        serial_number : str, 
        assertion : Assertion = None, 
        nonce : bytes = None,
        idevid_issuer : bytes = None,
        proximity_registrar_cert : bytes = None, 
        validity_days : int = 7) -> VoucherRequest:

    current_time = datetime.now(timezone.utc)
    expiration_time = (datetime.now(timezone.utc) + timedelta(days=validity_days))
    
    request = VoucherRequest(
        created_on=current_time,
        expires_on=expiration_time,
        assertion=assertion,
        serial_number=serial_number,
        idevid_issuer=idevid_issuer,
        pinned_domain_cert=None,
        domain_cert_revocation_checks=False,
        nonce=nonce,
        last_renewal_date=current_time,
        prior_signed_voucher_request=None,
        proximity_registrar_cert=base64.b64encode(proximity_registrar_cert) if proximity_registrar_cert is not None else None
    )
    request.sign(pledge_private_key)
    return request

def create_registrar_voucher_request(registrar_private_key : PrivateKeyTypes, request : VoucherRequest) -> VoucherRequest:

    current_time = datetime.now(timezone.utc)
    prior_signed_voucher_request = request.signature

    new_request = VoucherRequest(
        created_on=current_time,
        expires_on=request.expires_on,
        assertion=request.assertion,
        serial_number=request.serial_number,
        idevid_issuer=request.idevid_issuer,
        pinned_domain_cert=request.pinned_domain_cert,
        domain_cert_revocation_checks=request.domain_cert_revocation_checks,
        nonce=request.nonce,
        last_renewal_date=request.last_renewal_date,
        prior_signed_voucher_request=prior_signed_voucher_request,
        proximity_registrar_cert=request.proximity_registrar_cert
    )
    new_request.sign(registrar_private_key)
    return new_request


def parse_voucher_request(voucher_json : str) -> VoucherRequest:
    request_dict = json.loads(voucher_json)
    request = VoucherRequest(
        created_on=datetime.fromisoformat(request_dict.get("created-on")),
        expires_on=datetime.fromisoformat(request_dict.get("expire-on")),
        assertion=Assertion(request_dict.get("assertion")),
        serial_number=request_dict.get("serial-number"),
        idevid_issuer=base64.b64decode(request_dict.get("idevid-issuer").encode('utf-8')),
        pinned_domain_cert=base64.b64decode(request_dict.get("pinned-domain-cert").encode('utf-8')),
        domain_cert_revocation_checks=request_dict.get("domain-cert-revocation-checks"),
        nonce=base64.b64decode(request_dict.get("nonce").encode('utf-8')),
        last_renewal_date=datetime.fromisoformat(request_dict.get("last-renewal-date")),
        prior_signed_voucher_request=base64.b64decode(request_dict.get("prior-signed-voucher-request").encode('utf-8')),
        proximity_registrar_cert=base64.b64decode(request_dict.get("proximity-registrar-cert").encode('utf-8'))
    )
    return request

