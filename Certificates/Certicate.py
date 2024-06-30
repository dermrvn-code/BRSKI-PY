from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder
import datetime
from os import path
from Keys import generate_rsa_keys, generate_passphrase

def load_ca(ca_cert_path, ca_key_path, passphrase):
    """
    Load the ca certificate and private key from files.

    Parameters:
    - ca_cert_path (str): Path to the ca certificate file.
    - ca_key_path (str): Path to the ca private key file.
    - passphrase (str): Passphrase to decrypt the private key.

    Returns:
    - ca_cert (Certificate): Loaded ca certificate.
    - ca_key (RSAPrivateKey): Loaded ca private key.
    """
    with open(ca_cert_path, "rb") as ca_cert_file:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read())
    
    with open(ca_key_path, "rb") as ca_key_file:
        ca_key = load_pem_private_key(ca_key_file.read(), password=passphrase.encode())
    
    return ca_cert, ca_key

def save_cert(cert, dest_folder, common_name, cert_type="cert"):
    """
    Save the certificate to a file.

    Parameters:
    - cert (Certificate): Certificate to be saved.
    - dest_folder (str): Destination folder to save the certificate file.
    - common_name (str): Common name used in the certificate.
    - cert_type (str): Type of the certificate. Default is "cert".

    Returns:
    None
    """
    with open(path.join(dest_folder, cert_type + "_" + common_name.lower() + ".crt"), "wb") as device_cert_file:
        device_cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

def generate_simple_server_cert(
    ca_cert_path, ca_key_path, ca_passphrase,
    dest_folder,
    country_code, common_name, 
    hostname,
    expiration_days=365):
    """
    Generate a simple device certificate.

    Parameters:
    - ca_cert_path (str): Path to the ca certificate file.
    - ca_key_path (str): Path to the ca private key file.
    - ca_passphrase (str): Passphrase for the ca private key.
    - dest_folder (str): Destination folder to save the device certificate.
    - country_code (str): Country code for the device certificate.
    - common_name (str): Common name for the device certificate.
    - expiration_days (int): Number of days until the certificate expires. Default is 365.

    Returns:
    None
    """
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase)
    cert_passphrase = generate_passphrase(dest_folder, common_name)
    device_key, _ = generate_rsa_keys(cert_passphrase, dest_folder, common_name)
    
    alternative_name = x509.SubjectAlternativeName([
            x509.DNSName(hostname )
        ])

    # Generate CSR
    device_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])).add_extension(
        alternative_name,
        critical=False
    ).sign(device_key, hashes.SHA256())
    
    # Sign CSR with ca certificate
    device_cert = x509.CertificateBuilder().subject_name(
        device_csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        device_csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=expiration_days)
    ).add_extension(
        alternative_name,
        critical=False
    ).sign(ca_key, hashes.SHA256())

    save_cert(device_cert, dest_folder, common_name)

def generate_idevid_device_cert(
    ca_cert_path, ca_key_path, ca_passphrase,
    dest_folder,
    country_code, organization_name, organizational_unit_name, common_name,
    expiration_days=365, OtherName=False,
    othername_model=None, othername_serialnumber=None, othername_manufacturer=None,
    ):
    """
    Generate an idevid device certificate.

    Parameters:
    - ca_cert_path (str): Path to the ca certificate file.
    - ca_key_path (str): Path to the ca private key file.
    - ca_passphrase (str): Passphrase for the ca private key.
    - dest_folder (str): Destination folder to save the device certificate.
    - country_code (str): Country code for the device certificate.
    - organization_name (str): Organization name for the device certificate.
    - organizational_unit_name (str): Organizational unit name for the device certificate.
    - common_name (str): Common name for the device certificate.
    - expiration_days (int): Number of days until the certificate expires. Default is 365.
    - OtherName (bool): Whether to include OtherName extension in the certificate. Default is False.
    - othername_model (str): Model information for OtherName extension. Required if OtherName is True.
    - othername_serialnumber (str): Serial number information for OtherName extension. Required if OtherName is True.
    - othername_manufacturer (str): Manufacturer information for OtherName extension. Required if OtherName is True.

    Returns:
    None
    """
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase)
    cert_passphrase = generate_passphrase(dest_folder, common_name)
    device_key, _ = generate_rsa_keys(ca_passphrase, dest_folder, common_name)

    if(OtherName):
        class OtherName(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('model', univ.OctetString()),
                namedtype.NamedType('serialNumber', univ.OctetString()),
                namedtype.NamedType('manufacturer', univ.OctetString())
            )

        # Create an instance of your data
        data = OtherName()
        data['model'] = othername_model
        data['serialNumber'] = othername_serialnumber
        data['manufacturer'] = othername_manufacturer

        der_data = encoder.encode(data)

    alternative_name = x509.SubjectAlternativeName([
                x509.OtherName(x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), der_data)
            ])

    # Generate CSR
    device_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))

    # Add optional OtherName extension
    if(OtherName):
        device_csr = device_csr.add_extension(
            alternative_name,
            critical=False,
        )

    device_csr = device_csr.sign(device_key, hashes.SHA256())

    # Sign CSR with ca certificate
    device_cert = x509.CertificateBuilder().subject_name(
        device_csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        device_csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=expiration_days)
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(device_csr.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False, 
                      data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False, key_cert_sign=False, crl_sign=False),
        critical=True
    )
    
    # Add optional OtherName extension
    if(OtherName):
        device_cert = device_cert.add_extension(
            alternative_name,
            critical=False
        )

    device_cert = device_cert.sign(ca_key, hashes.SHA256())

    save_cert(device_cert, dest_folder, common_name, "idevid_cert")

