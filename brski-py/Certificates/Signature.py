from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

"""
TODO: Implement the sign and verify method using CMS
"""


def sign(data, signer_private_key) -> bytes:
    """
    Signs the given data using the private key.

    Args:
        data: The data to be signed.
        signer_private_key: The private key used for signing.

    Returns:
        The signature as bytes.
    """
    signature = signer_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    return signature


def verify(signature: bytes, verification_data, signer_public_key) -> bool:
    """
    Verifies the given signature against the verification data using the public key.

    Args:
        signature (bytes): The signature to be verified.
        verification_data: The data used for verification.
        signer_public_key: The public key used for verification.

    Returns:
        True if the verification is successful, False otherwise.
    """
    try:
        signer_public_key.verify(
            signature,
            verification_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True

    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Error while verification: {e}")
        return False
