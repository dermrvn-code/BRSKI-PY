from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate, Certificate
from cryptography.hazmat.backends import default_backend

def load_passphrase_from_path(path : str) -> str:
    """
    Load passphrase from a file.

    Parameters:
        path (str): The path to the file containing the passphrase.

    Returns:
        str: The passphrase read from the file.
    """
    with open(path, "rb") as f:
        passphrase = f.read()
    return passphrase

def load_private_key_from_path(path : str, passphrase : str) -> PrivateKeyTypes:
    """
    Load a private key from a file.

    Parameters:
        path (str): The path to the file containing the private key.
        passphrase (str): The passphrase to decrypt the private key.

    Returns:
        PrivateKeyTypes: The loaded private key.
    """
    with open(path, "rb") as f:
        private_key_data = f.read()
    return load_pem_private_key(private_key_data, password=passphrase, backend=default_backend())

def load_public_key_from_path(path : str) -> PublicKeyTypes:
    """
    Load a public key from a file.

    Parameters:
        path (str): The path to the file containing the public key.

    Returns:
        PublicKeyTypes: The loaded public key.
    """
    with open(path, "rb") as f:
        public_key_data = f.read()
    return load_pem_public_key(public_key_data, backend=default_backend())

def load_certificate_from_path(path : str) -> Certificate:
    """
    Load a certificate from a file.

    Parameters:
        path (str): The path to the file containing the certificate.

    Returns:
        Certificate: The loaded certificate.
    """
    with open(path, "rb") as f:
        cert_data = f.read()
    return load_pem_x509_certificate(cert_data, backend=default_backend())

def load_certificate_from_bytes(data : bytes) -> Certificate:
    """
    Load a certificate from bytes.

    Parameters:
        data (bytes): The bytes representing the certificate.

    Returns:
        Certificate: The loaded certificate.

    Raises:
        ValueError: If the bytes are neither PEM nor DER encoded.
    """
    try:
        return load_pem_x509_certificate(data, backend=default_backend())
    except:
        try:
            return load_der_x509_certificate(data, backend=default_backend())
        except:
            raise ValueError("Could not load certificate from bytes. Bytes are neither PEM nor DER encoded.")

def load_certificate_bytes_from_certificate(certfile : Certificate) -> bytes:
    """
    Get the bytes representation of a certificate.

    Parameters:
        certfile (Certificate): The certificate object.

    Returns:
        bytes: The bytes representation of the certificate.
    """
    return certfile.public_bytes(serialization.Encoding.DER)

def load_certificate_bytes_from_path(path) -> bytes:
    """
    Get the bytes representation of a certificate from a file.

    Parameters:
        path (str): The path to the file containing the certificate.

    Returns:
        bytes: The bytes representation of the certificate.
    """
    return load_certificate_bytes_from_certificate(load_certificate_from_path(path))