import json
from abc import ABC, abstractmethod
from enum import Enum

from Certificates.Signature import sign, verify
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
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
        Sign the voucher data using the provided private key and appends it to the voucher object.

        Args:
            signer_private_key (PrivateKeyTypes): The private key used for signing.
        """
        # Convert to JSON and exclude any existing signature
        voucher_data = self.to_json(True).encode()

        self.signature = sign(voucher_data, signer_private_key)

    def verify(self, signer_public_key: PublicKeyTypes) -> bool:
        """
        Verify the signature of the voucher data using the provided public key.

        Args:
            signer_public_key (PublicKeyTypes): The public key used for verification.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        if self.signature is None:
            return False

        # Convert to JSON and exclude the signature
        voucher_data = self.to_json(True).encode()

        return verify(self.signature, voucher_data, signer_public_key)

    def to_json(self, exclude_signature: bool = False) -> str:
        """
        Returns the voucher object as a JSON string.
        """
        return json.dumps(self.to_dict(exclude_signature), sort_keys=True)

    def print(self):
        """
        Print the voucher object as a pretty-printed JSON string.
        """
        prettyprint_json(self.to_dict(), True)
