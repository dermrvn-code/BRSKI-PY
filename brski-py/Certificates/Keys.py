import secrets
from os import makedirs, path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes


# Generate a random passphrase
def generate_passphrase(
    dest_folder: str, common_name: str, length: int = 30
) -> tuple[str, str]:
    """
    Generate a random passphrase and save it to a file.

    Args:
        dest_folder (str): The destination folder where the passphrase file will be saved.
        common_name (str): The common name associated with the passphrase.
        length (int): The length of the passphrase (default is 30).

    Returns:
        Tuple:
        - str: The generated passphrase.
        - str: The path to the file containing the passphrase.
    """
    alphabet = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="
    )
    passphrase = "".join(secrets.choice(alphabet) for i in range(length))

    # Write the passphrase to a .txt file

    if not path.exists(dest_folder):
        makedirs(dest_folder)

    file_path = path.join(dest_folder, f"passphrase_{common_name.lower()}.txt")
    with open(file_path, "w") as f:
        f.write(passphrase)

    return passphrase, file_path


def generate_rsa_keys(
    passphrase: str, dest_folder: str, common_name: str, prefix: str = "cert"
) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, str, str]:
    """
    Generates RSA private and public keys and saves them to files.

    Args:
        passphrase (str): The passphrase used to encrypt the private key.
        dest_folder (str): The destination folder where the keys will be saved.
        common_name (str): The common name used in the key filenames.

    Returns:
        Tuple:
        - RSAPrivateKey: The generated RSA private key.
        - RSAPublicKey: The generated RSA public key.
        - str: The path to the private key file.
        - str: The path to the public key file.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Encrypt the private key with the passphrase
    encrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
    )

    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if not path.exists(dest_folder):
        makedirs(dest_folder)

    # Write the private key to a file
    private_key_path = path.join(
        dest_folder, f"{prefix}_private_{common_name.lower()}.key"
    )
    with open(
        private_key_path,
        "wb",
    ) as key_file:
        key_file.write(encrypted_key)

    # Write the public key to a file
    public_key_path = path.join(
        dest_folder, f"{prefix}_public_{common_name.lower()}.key"
    )
    with open(public_key_path, "wb") as key_file:
        key_file.write(public_key_bytes)

    return private_key, public_key, private_key_path, public_key_path


def load_passphrase_from_path(path: str) -> bytes:
    """
    Load passphrase from a file.

    Args:
        path (str): The path to the file containing the passphrase.

    Returns:
        bytes: The passphrase read from the file as bytes.
    """
    with open(path, "rb") as f:
        passphrase = f.read()
    return passphrase


def load_private_key_from_bytes(private_key_data: bytes, passphrase: bytes):
    """
    Load a private key from bytes.

    Args:
        private_key_data (bytes): The private key data as bytes.
        passphrase (bytes): The passphrase to decrypt the private key as bytes.

    Returns:
        PrivateKey: The loaded private key.
    """
    return serialization.load_pem_private_key(
        private_key_data, password=passphrase, backend=default_backend()
    )


def load_private_key_from_path(path: str, passphrase: bytes):
    """
    Load a private key from a file.

    Args:
        path (str): The path to the file containing the private key.
        passphrase (bytes): The passphrase to decrypt the private key as bytes.

    Returns:
        PrivateKey: The loaded private key.
    """
    with open(path, "rb") as f:
        private_key_data = f.read()

    return load_private_key_from_bytes(private_key_data, passphrase=passphrase)


def load_public_key_from_bytes(public_key_data: bytes) -> PublicKeyTypes:
    """
    Load a public key from bytes.

    Args:
        public_key_data (bytes): The public key data as bytes.

    Returns:
        PublicKeyTypes: The loaded public key.
    """
    return serialization.load_pem_public_key(public_key_data, backend=default_backend())


def load_public_key_from_path(path: str) -> PublicKeyTypes:
    """
    Load a public key from a file.

    Args:
        path (str): The path to the file containing the public key.

    Returns:
        PublicKeyTypes: The loaded public key.
    """
    with open(path, "rb") as f:
        public_key_data = f.read()
    return load_public_key_from_bytes(public_key_data)


def setup_private_key(dest_folder: str, common_name: str):
    """
    Generates a passphrase and RSA keys for a device certificate.

    Args:
        dest_folder (str): The destination folder where the keys will be saved.
        common_name (str): The common name for the certificate.

    Returns:
        Tuple:
        - RSAPrivateKey: The generated RSA private key.
        - str: The path to the private key file.
        - str: The path to the passphrase file.
    """
    cert_passphrase, passphrase_file_path = generate_passphrase(
        dest_folder, common_name
    )
    private_key, public_key, private_key_path, public_key_path = generate_rsa_keys(
        cert_passphrase, dest_folder, common_name
    )

    return (private_key, private_key_path, passphrase_file_path)
