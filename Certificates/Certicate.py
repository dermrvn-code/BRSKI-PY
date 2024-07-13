from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder
import datetime
from os import path
from Keys import generate_rsa_keys, generate_passphrase


def load_ca(
        ca_cert_path : str, 
        ca_key_path : str, 
        passphrase : str
    ) -> tuple[x509.Certificate, PrivateKeyTypes]:
    """
    Load the ca certificate and private key from files.

    Parameters:
        ca_cert_path (str): Path to the ca certificate file.
        ca_key_path (str): Path to the ca private key file.
        passphrase (str): Passphrase to decrypt the private key.

    Returns:
        ca_cert (Certificate): Loaded ca certificate.
        ca_key (PrivateKeyTypes): Loaded ca private key.
    """
    with open(ca_cert_path, "rb") as ca_cert_file:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read())
    
    with open(ca_key_path, "rb") as ca_key_file:
        ca_key = load_pem_private_key(ca_key_file.read(), password=passphrase.encode())
    
    return ca_cert, ca_key

def save_cert(
        cert : x509.Certificate, 
        dest_folder : str, 
        common_name : str, 
        cert_type : str = "cert"
    ):
    """
    Save the certificate to a file.

    Parameters:
        cert (Certificate): Certificate to be saved.
        dest_folder (str): Destination folder to save the certificate file.
        common_name (str): Common name used in the certificate.
        cert_type (str): Type of the certificate. Default is "cert".

    Returns:
    None
    """
    with open(path.join(dest_folder, cert_type + "_" + common_name.lower() + ".crt"), "wb") as device_cert_file:
        device_cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

def generate_certificate_request(
        country_code : str, 
        common_name : str, 
        hostname : str = None, 
        organization_name : str = None, 
        organizational_unit_name : str = None
    ) -> x509.CertificateSigningRequestBuilder:
    """
    Generate a certificate signing request (CSR).

    Parameters:
        country_code (str): Country code for the certificate.
        common_name (str): Common name for the certificate.
        hostname (str): Hostname for the certificate. Optional.
        organization_name (str): Organization name for the certificate. Optional.
        organizational_unit_name (str): Organizational unit name for the certificate. Optional.

    Returns:
        csr (CertificateSigningRequestBuilder): Generated CSR.
    """
    nameAttributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ]

    if(organization_name):
        nameAttributes.append(
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name))
        
    if(organizational_unit_name):
        nameAttributes.append(
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit_name))
        
    if(hostname):
        nameAttributes.append(
            x509.NameAttribute(NameOID.COMMON_NAME, hostname)
        )

    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name(nameAttributes))

def generate_certificate(
        csr : x509.CertificateSigningRequestBuilder, 
        ca_cert : x509.Certificate, 
        expiration_days : int = 365
    ) -> x509.Certificate:
    """
    Generate a certificate based on the given CSR and CA certificate.

    Parameters:
        device_csr (CertificateSigningRequestBuilder): Certificate signing request.
        ca_cert (Certificate): CA certificate used for signing.
        expiration_days (int): Number of days until the certificate expires. Default is 365.
        
    Returns:
        cert (Certificate): Generated certificate.
    """
    return x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=expiration_days)
    )

def generate_basic_cert(
        ca_cert_path : str, 
        ca_key_path : str, 
        ca_passphrase : str,
        dest_folder : str,
        country_code : str, 
        common_name : str, 
        hostname : str = None,
        expiration_days : int = 365
    ) -> x509.Certificate:
    """
    Generate a simple device certificate.

    Parameters:
        ca_cert_path (str): Path to the ca certificate file.
        ca_key_path (str): Path to the ca private key file.
        ca_passphrase (str): Passphrase for the ca private key.
        dest_folder (str): Destination folder to save the device certificate.
        country_code (str): Country code for the device certificate.
        common_name (str): Common name for the device certificate.
        hostname (str): Hostname for the device certificate. Optional.
        expiration_days (int): Number of days until the certificate expires. Default is 365.

    Returns:
        cert (Certificate): Generated certificate.
    """
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase)
    cert_passphrase = generate_passphrase(dest_folder, common_name)
    device_key, _ = generate_rsa_keys(cert_passphrase, dest_folder, common_name)
    
    if(hostname):
        alternative_name = x509.SubjectAlternativeName([
                x509.DNSName(hostname )
            ])

    # Generate CSR
    device_csr = generate_certificate_request(country_code, common_name, hostname)
    
    if(hostname):
        device_csr = device_csr.add_extension(
            alternative_name,
            critical=False
        )
    
    device_csr = device_csr.sign(device_key, hashes.SHA256())
    
    # Sign CSR with ca certificate
    device_cert = generate_certificate(device_csr, ca_cert, expiration_days)

    
    if(hostname):
        device_cert = device_cert.add_extension(
            alternative_name,
            critical=False
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")  # id-kp-serverAuth OID
            ]),
            critical=False
        )
    
    device_cert = device_cert.sign(ca_key, hashes.SHA256())
    save_cert(device_cert, dest_folder, common_name)

    return device_cert

def generate_ra_cert(
        ca_cert_path : str, ca_key_path : str, ca_passphrase : str,
        dest_folder : str,
        country_code : str, common_name : str, 
        hostname : str,
        expiration_days : int = 365
    ) -> x509.Certificate:
    """
    Generate a RA (Registration Authority) certificate.

    Parameters:
        ca_cert_path (str): Path to the CA certificate file.
        ca_key_path (str): Path to the CA private key file.
        ca_passphrase (str): Passphrase for the CA private key.
        dest_folder (str): Destination folder to save the RA certificate.
        country_code (str): Country code for the RA certificate.
        common_name (str): Common name for the RA certificate.
        hostname (str): Hostname for the RA certificate.
        expiration_days (int): Number of days until the certificate expires. Default is 365.

    Returns:
        cert (Certificate): Generated certificate.
    """
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase)
    cert_passphrase = generate_passphrase(dest_folder, common_name)
    ra_key, _ = generate_rsa_keys(cert_passphrase, dest_folder, common_name)
    
    alternative_name = x509.SubjectAlternativeName([
        x509.DNSName(hostname)
    ])

    # Generate CSR
    ra_csr = generate_certificate_request(country_code, common_name, hostname)
    
    ra_csr = ra_csr.add_extension(
        alternative_name,
        critical=False
    ).sign(ra_key, hashes.SHA256())
    

    ra_cert = generate_certificate(ra_csr, ca_cert, expiration_days)
    
    # Add RA specific extensions
    ra_cert = ra_cert.add_extension(
        alternative_name,
        critical=False
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.28"),  # id-kp-cmcRA OID
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")  # id-kp-serverAuth OID
        ]),
        critical=False
    ).sign(ca_key, hashes.SHA256())

    save_cert(ra_cert, dest_folder, common_name)
    return ra_cert

def generate_idevid_device_cert(
        ca_cert_path: str, 
        ca_key_path: str, 
        ca_passphrase: str,
        dest_folder: str,
        country_code: str, 
        organization_name: str, 
        organizational_unit_name: str, 
        common_name: str,
        expiration_days: int = 365,
        othername_model: str = None, 
        othername_serialnumber: str = None, 
        othername_manufacturer: str = None,
    ) -> x509.Certificate:
    """
    Generate an idevid device certificate.

    Parameters:
        ca_cert_path (str): Path to the ca certificate file.
        ca_key_path (str): Path to the ca private key file.
        ca_passphrase (str): Passphrase for the ca private key.
        dest_folder (str): Destination folder to save the device certificate.
        country_code (str): Country code for the device certificate.
        organization_name (str): Organization name for the device certificate.
        organizational_unit_name (str): Organizational unit name for the device certificate.
        common_name (str): Common name for the device certificate.
        expiration_days (int): Number of days until the certificate expires. Default is 365.
        othername_model (str): Model information for OtherName extension. Default is None.
        othername_serialnumber (str): Serial number information for OtherName extension. Default is None.
        othername_manufacturer (str): Manufacturer information for OtherName extension. Default is None.

    
    Returns:
        cert (Certificate): Generated certificate.
    """

    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase)
    cert_passphrase = generate_passphrase(dest_folder, common_name)
    device_key, _ = generate_rsa_keys(cert_passphrase, dest_folder, common_name)

    OtherName = othername_model == None or \
                othername_serialnumber == None or \
                othername_manufacturer == None

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
                x509.OtherName(x509.ObjectIdentifier("1.3.6.1.5.5.7.8.4"), der_data) # id-on-hardwareModuleName OID
            ])

    # Generate CSR
    idevid_csr = generate_certificate_request(
        country_code, common_name, 
        organization_name, organizational_unit_name
    )

    # Add optional OtherName extension
    if(OtherName):
        idevid_csr = idevid_csr.add_extension(
            alternative_name,
            critical=False,
        )

    idevid_csr = idevid_csr.sign(device_key, hashes.SHA256())

    # Sign CSR with ca certificate
    idevid_cert = generate_certificate(idevid_csr, ca_cert, expiration_days)
    
    idevid_cert = idevid_cert.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(idevid_csr.public_key()),
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
        idevid_cert = idevid_cert.add_extension(
            alternative_name,
            critical=False
        )

    idevid_cert = idevid_cert.sign(ca_key, hashes.SHA256())

    save_cert(idevid_cert, dest_folder, common_name, "idevid_cert")
    return idevid_cert
