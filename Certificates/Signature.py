import json
import base64
from enum import Enum
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes

'''
TODO: Implement the sign and verify method using CMS
'''
def sign(data, signer_private_key : PrivateKeyTypes) -> bytes:

    signature = signer_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

def verify(signature : bytes, verification_data, signer_public_key : PublicKeyTypes) -> bool:
    try:
        signer_public_key.verify(
            signature,
            verification_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    
    except Exception as e:
        print(f"Verification failed: {e}")
        return False