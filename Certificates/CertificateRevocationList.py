from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, UTC
from Certificate import load_certificate_from_path
from Keys import load_private_key_from_path, load_passphrase_from_path
from os import path



def generate_certificate_revocation_list(
        ca_cert_path: str, 
        ca_key_path: str, 
        ca_passphrase_path: str,
        dest_folder: str,
        common_name: str
    ) -> str:

    # Load CA's private key and certificate
    ca_passphrase = load_passphrase_from_path(ca_passphrase_path)
    ca_cert = load_certificate_from_path(ca_cert_path)
    ca_private_key = load_private_key_from_path(ca_key_path, ca_passphrase)

    # Create a new CRL
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(ca_cert.subject)
    crl_builder = crl_builder.last_update(datetime.now(UTC))
    crl_builder = crl_builder.next_update(datetime.now(UTC) + timedelta(days=30))

    
    # Sign the CRL with the CA's private key
    crl = crl_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

    # Save the CRL to a file
    dest = path.join(dest_folder, "crl_" + common_name.lower() + ".crl")
    with open(dest, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.DER))

    return dest

def update_certificate_revocation_list(
        crl_path : str,
        ca_key_path: str, 
        ca_passphrase_path: str,
        revoked_cert_serial_number: int
    ):

    # Load existing CRL
    with open(crl_path, "rb") as f:
        crl = x509.load_der_x509_crl(f.read())


    # Load CA's private key and certificate
    ca_passphrase = load_passphrase_from_path(ca_passphrase_path)
    ca_private_key = load_private_key_from_path(ca_key_path, ca_passphrase)


    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(crl.issuer)
    crl_builder = crl_builder.last_update(datetime.now(UTC))
    crl_builder = crl_builder.next_update(datetime.now(UTC) + timedelta(days=30))

    # Add existing revoked certificates
    for revoked_cert in crl:
        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    # Optionally, revoke new certificates
    revocation_date = datetime.now(UTC)
    revoked_cert = x509.RevokedCertificateBuilder().serial_number(revoked_cert_serial_number).revocation_date(revocation_date).build()
    crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    # Sign the updated CRL with the CA's private key
    updated_crl = crl_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

    # Save the updated CRL to a file
    with open(crl_path, "wb") as f:
        f.write(updated_crl.public_bytes(serialization.Encoding.DER))



