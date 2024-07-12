from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate, Certificate
from cryptography.hazmat.backends import default_backend

def load_passphrase_from_path(path : str) -> str:
    with open(path, "rb") as f:
        passphrase = f.read()
    return passphrase

def load_private_key_from_path(path : str,passphrase : str) -> PrivateKeyTypes:
    with open(path, "rb") as f:
        private_key_data = f.read()
    return load_pem_private_key(private_key_data, password=passphrase, backend=default_backend())

def load_public_key_from_path(path : str) -> PublicKeyTypes:
    with open(path, "rb") as f:
        public_key_data = f.read()
    return load_pem_public_key(public_key_data, backend=default_backend())

def load_certificate_from_path(path : str) -> Certificate:
    with open(path, "rb") as f:
        cert_data = f.read()
    return load_pem_x509_certificate(cert_data, backend=default_backend())

def load_certificate_from_bytes(data : bytes) -> Certificate:
    try:
        return load_pem_x509_certificate(data, backend=default_backend())
    except:
        try:
            return load_der_x509_certificate(data, backend=default_backend())
        except:
            raise ValueError("Could not load certificate from bytes. Bytes are neither PEM nor DER encoded.")
    


def load_certificate_bytes_from_certificate(certfile : Certificate) -> bytes:
    return certfile.public_bytes(serialization.Encoding.DER)

def load_certificate_bytes_from_path(path) -> bytes:
    return load_certificate_bytes_from_certificate(load_certificate_from_path(path))