from datetime import UTC, datetime, timedelta
from os import path

from Certificates.Certificate import load_certificate_from_path
from Certificates.Keys import load_passphrase_from_path, load_private_key_from_path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def generate_certificate_revocation_list(
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase_path: str,
    dest_folder: str,
    *,
    common_name: str,
) -> str:
    """
    Generate a Certificate Revocation List (CRL) for a given CA certificate.

    Args:
        ca_cert_path (str): Path to the CA certificate file.
        ca_key_path (str): Path to the CA private key file.
        ca_passphrase_path (str): Path to the file containing the passphrase for the CA private key.
        dest_folder (str): Destination folder to save the generated CRL.
        common_name (str): Common name for the CRL file.

    Returns:
        dest (str): Path to the generated CRL file.
    """

    ca_passphrase = load_passphrase_from_path(ca_passphrase_path)
    ca_cert = load_certificate_from_path(ca_cert_path)
    ca_private_key = load_private_key_from_path(ca_key_path, ca_passphrase)

    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(ca_cert.subject)
    crl_builder = crl_builder.last_update(datetime.now(UTC))
    crl_builder = crl_builder.next_update(datetime.now(UTC) + timedelta(days=30))

    crl = crl_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())  # type: ignore

    dest = path.join(dest_folder, f"crl_{common_name.lower()}.crl")
    with open(dest, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.DER))

    return dest


def update_certificate_revocation_list(
    crl_path: str,
    ca_key_path: str,
    ca_passphrase_path: str,
    revoked_cert_serial_number: int,
):
    """
    Update an existing Certificate Revocation List (CRL) with a new revoked certificate.

    Args:
        crl_path (str): Path to the existing CRL file.
        ca_key_path (str): Path to the CA private key file.
        ca_passphrase_path (str): Path to the file containing the passphrase for the CA private key.
        revoked_cert_serial_number (int): Serial number of the certificate to be revoked.
    """

    with open(crl_path, "rb") as f:
        crl = x509.load_der_x509_crl(f.read())

    ca_passphrase = load_passphrase_from_path(ca_passphrase_path)
    ca_private_key = load_private_key_from_path(ca_key_path, ca_passphrase)

    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(crl.issuer)
    crl_builder = crl_builder.last_update(datetime.now(UTC))
    crl_builder = crl_builder.next_update(datetime.now(UTC) + timedelta(days=30))

    for revoked_cert in crl:
        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    revocation_date = datetime.now(UTC)
    revoked_cert = (
        x509.RevokedCertificateBuilder()
        .serial_number(revoked_cert_serial_number)
        .revocation_date(revocation_date)
        .build()
    )
    crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    updated_crl = crl_builder.sign(
        private_key=ca_private_key, algorithm=hashes.SHA256()  # type: ignore
    )

    with open(crl_path, "wb") as f:
        f.write(updated_crl.public_bytes(serialization.Encoding.DER))
