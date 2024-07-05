from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from os import path
import secrets

# Generate a random passphrase
def generate_passphrase(dest_folder, common_name, length=30):
    """
    Generate a random passphrase and save it to a file.

    Parameters:
    - dest_folder (str): The destination folder where the passphrase file will be saved.
    - common_name (str): The common name associated with the passphrase.
    - length (int): The length of the passphrase (default is 30).

    Returns:
    - passphrase (str): The generated passphrase.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="
    passphrase = "".join(secrets.choice(alphabet) for i in range(length))

    # Write the passphrase to a .txt file
    with open(path.join(dest_folder,"passphrase_" + common_name.lower() + ".txt"), "w") as f:
        f.write(passphrase)

    return passphrase

def generate_rsa_keys(passphrase, dest_folder, common_name, prefix="cert"):
    """
    Generates RSA private and public keys and saves them to files.

    Args:
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

    
    # Write the private key to a file
    with open(path.join(dest_folder, prefix+"_private_" + common_name.lower() + ".key"), "wb") as key_file:
        key_file.write(encrypted_key)
    
    # Write the public key to a file
    with open(path.join(dest_folder, prefix+"_public_" + common_name.lower() + ".key"), "wb") as key_file:
        key_file.write(public_key_bytes)
    
    return private_key, public_key