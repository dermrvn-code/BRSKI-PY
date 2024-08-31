import base64
import json
from datetime import datetime, timedelta, timezone

from Certificates.Signature import verify
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.x509 import AuthorityKeyIdentifier, Certificate
from Voucher.VoucherBase import Assertion, VoucherBase


class VoucherRequest(VoucherBase):
    def __init__(
        self,
        serial_number: str,
        assertion: Assertion,
        created_on: datetime | None = None,
        expires_on: datetime | None = None,
        idevid_issuer: bytes | None = None,
        pinned_domain_cert: bytes | None = None,
        domain_cert_revocation_checks: bool | None = None,
        nonce: bytes | None = None,
        last_renewal_date: datetime | None = None,
        prior_signed_voucher_request: bytes | None = None,
        proximity_registrar_cert: bytes | None = None,
    ):
        """
        Initialize a voucher request.

        Args:
            serial_number (str): The serial number of the voucher request.
            created_on (datetime): The creation date of the voucher request. Defaults to None.
            expires_on (datetime): The expiration date of the voucher request. Defaults to None.
            assertion (Assertion): The assertion type of the voucher request. Defaults to None.
            idevid_issuer (bytes): The issuer Authority Key Identifier. Defaults to None.
            pinned_domain_cert (bytes): The pinned domain certificate of the voucher request. Defaults to None.
            domain_cert_revocation_checks (bool): Whether to perform domain certificate revocation checks. Defaults to None.
            nonce (bytes): The nonce of the voucher request. Defaults to None.
            last_renewal_date (datetime): The last renewal date of the voucher request. Defaults to None.
            prior_signed_voucher_request (bytes): The prior signed voucher request. Defaults to None.
            proximity_registrar_cert (bytes): The proximity registrar certificate. Defaults to None.

        Raises:
            ValueError: If the assertion is set to PROXIMITY without providing a proximity registrar certificate.
        """
        super().__init__()

        if assertion == Assertion.PROXIMITY and proximity_registrar_cert == None:
            raise ValueError(
                "Proximity assertion requires proximity registrar certificate"
            )

        self.created_on: datetime | None = created_on
        self.expires_on: datetime | None = expires_on
        self.assertion: Assertion = assertion
        self.serial_number: str = serial_number
        self.idevid_issuer: bytes | None = idevid_issuer
        self.pinned_domain_cert: bytes | None = pinned_domain_cert
        self.domain_cert_revocation_checks: bool | None = domain_cert_revocation_checks
        self.nonce: bytes | None = nonce
        self.last_renewal_date: datetime | None = last_renewal_date
        self.prior_signed_voucher_request: bytes | None = prior_signed_voucher_request
        self.proximity_registrar_cert: bytes | None = proximity_registrar_cert

        self.signature: bytes | None = None

    def to_dict(self, exclude_signature: bool = False) -> dict:
        dict = {
            "created-on": (
                self.created_on.isoformat() if self.created_on is not None else None
            ),
            "expire-on": (
                self.expires_on.isoformat() if self.expires_on is not None else None
            ),
            "assertion": (self.assertion.value if self.assertion is not None else None),
            "serial-number": self.serial_number,
            "idevid-issuer": (
                base64.b64encode(self.idevid_issuer).decode()
                if self.idevid_issuer is not None
                else None
            ),
            "pinned-domain-cert": (
                base64.b64encode(self.pinned_domain_cert).decode()
                if self.pinned_domain_cert is not None
                else None
            ),
            "domain-cert-revocation-checks": (
                self.domain_cert_revocation_checks
                if self.domain_cert_revocation_checks is not None
                else None
            ),
            "nonce": (
                base64.b64encode(self.nonce).decode()
                if self.nonce is not None
                else None
            ),
            "last-renewal-date": (
                self.last_renewal_date.isoformat()
                if self.last_renewal_date is not None
                else None
            ),
            "prior-signed-voucher-request": (
                base64.b64encode(self.prior_signed_voucher_request).decode()
                if self.prior_signed_voucher_request is not None
                else None
            ),
            "proximity-registrar-cert": (
                base64.b64encode(self.proximity_registrar_cert).decode()
                if self.proximity_registrar_cert is not None
                else None
            ),
        }

        if not exclude_signature and self.signature is not None:
            dict["signature"] = base64.b64encode(self.signature).decode()

        dict = {key: value for key, value in dict.items() if value is not None}

        return dict

    """
    TODO: Implement the verify method using CMS
    """

    def verify_prior_signed(self, signer_public_key: PublicKeyTypes) -> bool:
        """
        Verify the signature of the prior signed voucher request using the provided public key.

        Args:
            signer_public_key (PublicKeyTypes): The public key used for verification.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        if self.prior_signed_voucher_request is None:
            return False

        # Create a copy of the voucher data dictionary without prior-signed-voucher-request
        data_to_verify = self.to_dict(True)
        del data_to_verify["prior-signed-voucher-request"]

        # Convert to JSON and encode
        voucher_data = json.dumps(data_to_verify, sort_keys=True).encode()

        return verify(
            self.prior_signed_voucher_request,
            voucher_data,
            signer_public_key,
        )


def create_pledge_voucher_request(
    pledge_private_key: PrivateKeyTypes,
    serial_number: str,
    assertion: Assertion,
    nonce: bytes | None = None,
    idevid_issuer_certificate: Certificate | None = None,
    proximity_registrar_cert: bytes | None = None,
    validity_days: int = 7,
) -> VoucherRequest:
    """
    Creates a pledge voucher request.

    Args:
        pledge_private_key (PrivateKeyTypes): The private key of the pledge.
        serial_number (str): The serial number of the voucher request.
        assertion (Assertion): The assertion type of the voucher request. Defaults to None.
        nonce (bytes): The nonce of the voucher request. Defaults to None.
        idevid_issuer (bytes): The issuer identifier of the voucher request. Defaults to None.
        proximity_registrar_cert (bytes): The proximity registrar certificate. Defaults to None.
        validity_days (int): The number of days the voucher request is valid for. Defaults to 7.

    Returns:
        VoucherRequest: The created pledge voucher request.
    """
    current_time = datetime.now(timezone.utc)
    expiration_time = datetime.now(timezone.utc) + timedelta(days=validity_days)

    idev_id_issuer_authkey = None
    if idevid_issuer_certificate is not None:
        idev_id_issuer_authkey = (
            idevid_issuer_certificate.extensions.get_extension_for_class(
                AuthorityKeyIdentifier
            )
        )
        idev_id_issuer_authkey = idev_id_issuer_authkey.value.key_identifier

    request = VoucherRequest(
        created_on=current_time,
        expires_on=expiration_time,
        assertion=assertion,
        serial_number=serial_number,
        idevid_issuer=idev_id_issuer_authkey,
        pinned_domain_cert=None,
        domain_cert_revocation_checks=False,
        nonce=nonce,
        last_renewal_date=current_time,
        prior_signed_voucher_request=None,
        proximity_registrar_cert=(
            base64.b64encode(proximity_registrar_cert)
            if proximity_registrar_cert is not None
            else None
        ),
    )

    request.sign(pledge_private_key)
    return request


def create_registrar_voucher_request(
    registrar_private_key: PrivateKeyTypes, request: VoucherRequest
) -> VoucherRequest:
    """
    Creates a registrar voucher request.

    Args:
        registrar_private_key (PrivateKeyTypes): The private key of the registrar.
        request (VoucherRequest): The original voucher request.

    Returns:
        VoucherRequest: The created registrar voucher request.
    """
    prior_signed_voucher_request = request.signature

    new_request = VoucherRequest(
        created_on=request.created_on,
        expires_on=request.expires_on,
        assertion=request.assertion,
        serial_number=request.serial_number,
        idevid_issuer=request.idevid_issuer,
        pinned_domain_cert=request.pinned_domain_cert,
        domain_cert_revocation_checks=request.domain_cert_revocation_checks,
        nonce=request.nonce,
        last_renewal_date=request.last_renewal_date,
        prior_signed_voucher_request=prior_signed_voucher_request,
        proximity_registrar_cert=request.proximity_registrar_cert,
    )
    new_request.sign(registrar_private_key)
    return new_request


def parse_voucher_request(request) -> VoucherRequest:
    """
    Parses a voucher request from a JSON string or dictionary.

    Args:
        request (str or dict): The voucher request in JSON string or dictionary format.

    Returns:
        VoucherRequest: The parsed voucher request.
    """
    if type(request) is str:
        try:
            request_dict = json.loads(request)
        except json.JSONDecodeError:
            raise ValueError("Invalid voucher request json format")
    elif type(request) is dict:
        request_dict = request
    else:
        raise ValueError("Invalid voucher request json format")

    request = VoucherRequest(
        created_on=(
            datetime.fromisoformat(request_dict.get("created-on", ""))
            if request_dict.get("created-on") is not None
            else None
        ),
        expires_on=(
            datetime.fromisoformat(request_dict.get("expire-on", ""))
            if request_dict.get("expire-on") is not None
            else None
        ),
        assertion=(Assertion(request_dict.get("assertion", ""))),
        serial_number=request_dict.get("serial-number", ""),
        idevid_issuer=(
            base64.b64decode(request_dict.get("idevid-issuer", "").encode())
            if request_dict.get("idevid-issuer") is not None
            else None
        ),
        pinned_domain_cert=(
            base64.b64decode(request_dict.get("pinned-domain-cert", "").encode())
            if request_dict.get("pinned-domain-cert") is not None
            else None
        ),
        domain_cert_revocation_checks=(
            request_dict.get("domain-cert-revocation-checks", "")
            if request_dict.get("domain-cert-revocation-checks") is not None
            else None
        ),
        nonce=(
            base64.b64decode(request_dict.get("nonce", "").encode())
            if request_dict.get("nonce") is not None
            else None
        ),
        last_renewal_date=(
            datetime.fromisoformat(request_dict.get("last-renewal-date", ""))
            if request_dict.get("last-renewal-date") is not None
            else None
        ),
        prior_signed_voucher_request=(
            base64.b64decode(
                request_dict.get("prior-signed-voucher-request", "").encode()
            )
            if request_dict.get("prior-signed-voucher-request") is not None
            else None
        ),
        proximity_registrar_cert=(
            base64.b64decode(request_dict.get("proximity-registrar-cert", "").encode())
            if request_dict.get("proximity-registrar-cert") is not None
            else None
        ),
    )
    request.signature = (
        base64.b64decode(request_dict.get("signature", "").encode())
        if request_dict.get("signature") is not None
        else None
    )
    return request
