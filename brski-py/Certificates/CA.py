import datetime
from os import makedirs, path

from Certificates.Keys import (generate_passphrase, generate_rsa_keys,
                               load_passphrase_from_path,
                               load_private_key_from_path)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from Utils.Config import Config


def generate_certificate_authority(
    dest_folder: str,
    *,
    country_code: str,
    common_name: str,
    days_valid: int = 1825,
    passphrase_length: int = 30
) -> tuple[str, str, str, str]:
    """
    Generate a self-signed root certificate and save it to a file.

    Args:
        dest_folder (str): The destination folder where the certificate file will be saved.
        country_code (str): The country_code name associated with the certificate.
        common_name (str): The common name associated with the certificate.
        days_valid (int): The number of days the certificate will be valid (default is 1825).
        passphrase_length (int): The length of the passphrase used to encrypt the private key (default is 30).
        
    Returns:
        Tuple:
        - str: The path to the generated certificate file.
        - str: The path to the generated private key file.
        - str: The path to the generated public key file.
        - str: The passphrase used to encrypt the private key.
    """
    passphrase, _ = generate_passphrase(dest_folder, common_name, passphrase_length)
    key, _, _, _ = generate_rsa_keys(passphrase, dest_folder, common_name, "ca")

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=days_valid)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                f"https://{Config.get("AUTHORITIES", "hostname")}:{Config.get("AUTHORITIES", "port")}{Config.get("AUTHORITIES", "crlpath")}?from={common_name.lower()}"
                            )
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=[x509.DirectoryName(issuer)],
                    )
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    if not path.exists(dest_folder):
        makedirs(dest_folder)

    with open(
        path.join(dest_folder, f"ca_{common_name.lower()}.crt"), "wb"
    ) as cert_file:
        cert_file.write(cert.public_bytes(Encoding.PEM))

    return (
        path.join(dest_folder, f"ca_{common_name.lower()}.crt"),
        path.join(dest_folder, f"ca_private_{common_name.lower()}.key"),
        path.join(dest_folder, f"ca_public_{common_name.lower()}.key"),
        path.join(dest_folder, f"passphrase_{common_name.lower()}.txt"),
    )


def sign_certificate(
    ca_cert: x509.Certificate,
    ca_key,
    cert_builder: x509.CertificateBuilder,
) -> x509.Certificate:
    """
    Signs a certificate and adds CRL Distribution points using the provided CA certificate
    and private key.

    Args:
        ca_cert (Certificate): The CA certificate used for signing.
        ca_key (): The private key of the CA certificate.
        cert_builder (CertificateBuilder): The certificate builder to be signed.

    Returns:
        Certificate: The signed certificate.
    """

    cert_builder = cert_builder.add_extension(
        ca_cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value,
        critical=False,
    )

    return cert_builder.sign(ca_key, hashes.SHA256())


def load_ca(
    ca_cert_path: str, ca_key_path: str, passphrase_path: str
) -> tuple[x509.Certificate, PrivateKeyTypes]:
    """
    Load the ca certificate and private key from files.

    Args:
        ca_cert_path (str): Path to the ca certificate file.
        ca_key_path (str): Path to the ca private key file.
        passphrase_path (str): Passphrase to decrypt the private key.

    Returns:
        Tuple:
        - Certificate: Loaded ca certificate.
        - PrivateKeyTypes: Loaded ca private key.
    """

    ca_passphrase = load_passphrase_from_path(passphrase_path)
    ca_key = load_private_key_from_path(ca_key_path, ca_passphrase)

    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    return ca_cert, ca_key
