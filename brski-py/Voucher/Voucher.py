import base64
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from Voucher.VoucherBase import Assertion, VoucherBase
from Voucher.VoucherRequest import VoucherRequest


class Voucher(VoucherBase):
    def __init__(
        self,
        created_on: datetime,
        assertion: Assertion,
        serial_number: str,
        pinned_domain_cert: bytes,
        expires_on: datetime | None = None,
        idevid_issuer: bytes | None = None,
        domain_cert_revocation_checks: bool | None = None,
        nonce: bytes | None = None,
        last_renewal_date: datetime | None = None,
    ):
        """
        Initialize a Voucher object.

        Args:
            created_on (datetime): The creation date of the voucher.
            assertion (Assertion): The assertion associated with the voucher.
            serial_number (str): The serial number of the voucher.
            pinned_domain_cert (bytes): The pinned domain certificate.
            expires_on (datetime): The expiration date of the voucher. Defaults to None.
            idevid_issuer (bytes): The issuer Authority Key Identifier. Defaults to None.
            domain_cert_revocation_checks (bool): Flag indicating if domain certificate revocation checks are enabled. Defaults to None.
            nonce (bytes): The nonce value. Defaults to None.
            last_renewal_date (datetime): The last renewal date of the voucher. Defaults to None.
        """
        super().__init__()

        self.created_on: datetime = created_on
        self.expires_on: datetime | None = expires_on
        self.assertion: Assertion = assertion
        self.serial_number: str = serial_number
        self.idevid_issuer: bytes | None = idevid_issuer
        self.pinned_domain_cert: bytes = pinned_domain_cert
        self.domain_cert_revocation_checks: bool | None = domain_cert_revocation_checks
        self.nonce: bytes | None = nonce
        self.last_renewal_date: datetime | None = last_renewal_date
        self.signature: bytes | None = None

    def to_dict(self, exclude_signature: bool = False) -> dict:
        dict = {
            "created-on": self.created_on.isoformat(),
            "expire-on": (
                self.expires_on.isoformat() if self.expires_on is not None else None
            ),
            "assertion": self.assertion.value,
            "serial-number": self.serial_number,
            "idevid-issuer": (
                base64.b64encode(self.idevid_issuer).decode()
                if self.idevid_issuer is not None
                else None
            ),
            "pinned-domain-cert": base64.b64encode(self.pinned_domain_cert).decode(),
            "domain-cert-revocation-checks": self.domain_cert_revocation_checks,
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
        }

        if not exclude_signature and self.signature is not None:
            dict["signature"] = base64.b64encode(self.signature).decode()

        dict = {key: value for key, value in dict.items() if value is not None}

        return dict


def create_voucher_from_request(
    request: VoucherRequest,
    *,
    pinned_domain_cert: bytes,
    masa_private_key: PrivateKeyTypes,
    assertion: Assertion,
) -> Voucher:
    """
    Create a Voucher object from a VoucherRequest.

    Args:
        request (VoucherRequest): The VoucherRequest object.
        pinned_domain_cert (bytes): The pinned domain certificate.
        masa_private_key (PrivateKeyTypes): The private key used for signing the voucher.

    Returns:
        Voucher: The created Voucher object.
    """
    current_time = datetime.now(timezone.utc)

    voucher = Voucher(
        created_on=current_time,
        expires_on=request.expires_on,
        assertion=assertion,
        serial_number=request.serial_number,
        idevid_issuer=request.idevid_issuer,
        pinned_domain_cert=pinned_domain_cert,
        nonce=request.nonce,
    )
    voucher.sign(masa_private_key)
    return voucher


def parse_voucher(voucher: str | dict) -> Voucher:
    """
    Parse a voucher from a JSON string or dictionary.

    Args:
        voucher (str | dict): The voucher data.

    Returns:
        Voucher: The parsed Voucher object.
    """
    if type(voucher) is str:
        voucher_dict = json.loads(voucher)
    elif type(voucher) is dict:
        voucher_dict = voucher
    else:
        raise ValueError("Invalid voucher JSON format")

    parsed_voucher = Voucher(
        created_on=datetime.fromisoformat(voucher_dict["created-on"]),
        expires_on=(
            datetime.fromisoformat(voucher_dict.get("expire-on", ""))
            if voucher_dict.get("expire-on") is not None
            else None
        ),
        assertion=Assertion(voucher_dict["assertion"]),
        serial_number=voucher_dict["serial-number"],
        idevid_issuer=(
            base64.b64decode(voucher_dict.get("idevid-issuer", "").encode())
            if voucher_dict.get("idevid-issuer") is not None
            else None
        ),
        pinned_domain_cert=base64.b64decode(
            voucher_dict.get("pinned-domain-cert", "").encode()
        ),
        domain_cert_revocation_checks=(
            voucher_dict.get("domain-cert-revocation-checks")
            if voucher_dict.get("domain-cert-revocation-checks") is not None
            else None
        ),
        nonce=(
            base64.b64decode(voucher_dict.get("nonce", "").encode())
            if voucher_dict.get("nonce") is not None
            else None
        ),
        last_renewal_date=(
            datetime.fromisoformat(voucher_dict.get("last-renewal-date", ""))
            if voucher_dict.get("last-renewal-date") is not None
            else None
        ),
    )
    parsed_voucher.signature = (
        base64.b64decode(voucher_dict.get("signature", "").encode())
        if voucher_dict.get("signature") is not None
        else None
    )
    return parsed_voucher
