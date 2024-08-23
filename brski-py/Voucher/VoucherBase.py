import json
from abc import ABC, abstractmethod
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from Certificates.Signature import sign, verify
from Utils.Printer import prettyprint_json


class Assertion(Enum):
    VERIFIED = "verified"
    LOGGED = "logged"
    PROXIMITY = "proximity"


class VoucherBase(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def to_dict(self, exclude_signature: bool = False) -> dict:
        """
        Convert the Voucher object to a dictionary.

        Args:
            exclude_signature (bool): Flag indicating if the signature should be excluded from the dictionary. Defaults to False.

        Returns:
            dict: The voucher object as a dictionary.
        """
        pass

    def sign(self, signer_private_key: PrivateKeyTypes):
        """
        Sign the voucher data using the provided private key.

        Args:
            signer_private_key (PrivateKeyTypes): The private key used for signing.

        Returns:
            bytes: The signature of the voucher data.
        """
        # Create a copy of the voucher data dictionary without masa_signature
        data_to_sign = self.to_dict(True)

        # Convert to JSON and encode
        voucher_data = json.dumps(data_to_sign, sort_keys=True).encode("utf-8")

        self.signature = sign(voucher_data, signer_private_key)

    def verify(self, signer_public_key: PublicKeyTypes) -> bool:
        """
        Verify the signature of the voucher data using the provided public key.

        Args:
            signer_public_key (PublicKeyTypes): The public key used for verification.

        Returns:
            bool: True if the signature is valid, False otherwise.

        Raises:
            ValueError: If the voucher is not signed.
        """
        if self.signature is None:
            raise ValueError("Voucher is not signed")

        # Create a copy of the voucher data dictionary without masa_signature
        data_to_verify = self.to_dict(True)

        # Convert to JSON and encode
        voucher_data = json.dumps(data_to_verify, sort_keys=True).encode("utf-8")

        return verify(self.signature, voucher_data, signer_public_key)

    def print(self):
        """
        Print the voucher object as a pretty-printed JSON string.

        Returns:
            None
        """
        prettyprint_json(self.to_dict(), True)
