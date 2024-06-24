from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import secrets
from os import path
from Keys import generate_rsa_keys

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


# Generate self-signed root certificate
def generate_certificate_authority(country, common_name, dest_folder, days_valid=1825, passphrase_length=30):
    """
    Generate a self-signed root certificate and save it to a file.

    Parameters:
    - country (str): The country name associated with the certificate.
    - common_name (str): The common name associated with the certificate.
    - dest_folder (str): The destination folder where the certificate file will be saved.
    - days_valid (int): The number of days the certificate will be valid (default is 1825).
    - passphrase_length (int): The length of the passphrase used to encrypt the private key (default is 30).

    Returns:
    - certificate_path (str): The path to the generated certificate file.
    - private_key_path (str): The path to the generated private key file.
    - public_key_path (str): The path to the generated public key file.
    - passphrase (str): The passphrase used to encrypt the private key.
    """
    passphrase = generate_passphrase(dest_folder, common_name, passphrase_length)
    key, _ = generate_rsa_keys(passphrase,dest_folder,common_name)

    subject, issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=days_valid)
    ).sign(key, hashes.SHA256(), default_backend())

    # Write the certificate to a file
    with open(path.join(dest_folder,"CA_" + common_name.lower() + ".pem"), "wb") as cert_file:
        cert_file.write(cert.public_bytes(Encoding.PEM))

    return (
        path.join(dest_folder,"CA_" + common_name.lower() + ".pem"), 
        path.join(dest_folder,"CA_private_" + common_name.lower() + ".key"),
        path.join(dest_folder,"CA_public_" + common_name.lower() + ".key"),
        passphrase
    )
