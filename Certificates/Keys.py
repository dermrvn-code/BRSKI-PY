from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.backends import default_backend
from os import makedirs, path
import secrets
import os


# Generate a random passphrase
def generate_passphrase(dest_folder : str, common_name : str, length : int = 30) -> str:
    """
    Generate a random passphrase and save it to a file.

    Parameters:
        dest_folder (str): The destination folder where the passphrase file will be saved.
        common_name (str): The common name associated with the passphrase.
        length (int): The length of the passphrase (default is 30).

    Returns:
        passphrase (str): The generated passphrase.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="
    passphrase = "".join(secrets.choice(alphabet) for i in range(length))

    # Write the passphrase to a .txt file
    
    if not path.exists(dest_folder):
        makedirs(dest_folder)
        
    with open(path.join(dest_folder,"passphrase_" + common_name.lower() + ".txt"), "w") as f:
        f.write(passphrase)

    return passphrase

def generate_rsa_keys(passphrase : str, dest_folder : str, common_name : str, prefix : str = "cert") -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]: 
    """
    Generates RSA private and public keys and saves them to files.

    Parameters:
        passphrase (str): The passphrase used to encrypt the private key.
        dest_folder (str): The destination folder where the keys will be saved.
        common_name (str): The common name used in the key filenames.

    Returns:
        private_key (RSAPrivateKey): The generated RSA private key.
        public_key (RSAPublicKey): The generated RSA public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Encrypt the private key with the passphrase
    encrypted_key = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )

    public_key = private_key.public_key()
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    
    if not path.exists(dest_folder):
        makedirs(dest_folder)
    
    # Write the private key to a file
    with open(path.join(dest_folder, prefix+"_private_" + common_name.lower() + ".key"), "wb") as key_file:
        key_file.write(encrypted_key)
    
    # Write the public key to a file
    with open(path.join(dest_folder, prefix+"_public_" + common_name.lower() + ".key"), "wb") as key_file:
        key_file.write(public_key_bytes)
    
    return private_key, public_key


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



def setup_private_key(dest_folder : str, common_name : str):
    """
    Generates a passphrase and RSA keys for a device certificate.

    Parameters:
        dest_folder (str): The destination folder where the keys will be saved.
        common_name (str): The common name for the certificate.

    Returns:
        private_key (RSAPrivateKey): The generated RSA private key.
    """
    cert_passphrase = generate_passphrase(dest_folder, common_name)
    private_key, public_key = generate_rsa_keys(cert_passphrase, dest_folder, common_name)

    return private_key