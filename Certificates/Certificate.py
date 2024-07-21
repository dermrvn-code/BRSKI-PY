from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate, Certificate
from cryptography.hazmat.backends import default_backend
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder
import datetime
from os import path


import sys
sys.path.append("../") 
from Certificates.Keys import setup_private_key
from Certificates.CA import load_ca, sign_certificate
 


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


def save_cert_to_file(
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

    request = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(nameAttributes))

    if(hostname):
        request = request.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname)
            ]),
            critical=False
        )

    return request

def generate_certificate(
        request : x509.CertificateSigningRequestBuilder, 
        ca_cert : x509.Certificate, 
        authority_key_identifier_set : bool = True,
        subject_key_identifier_set : bool = True,
        expiration_days : int = 365
    ) -> x509.Certificate:
    """
    Generate a certificate based on the given CSR and CA certificate.

    Parameters:
        request (CertificateSigningRequestBuilder): Certificate signing request.
        ca_cert (Certificate): CA certificate used for signing.
        expiration_days (int): Number of days until the certificate expires. Default is 365.
        
    Returns:
        cert (Certificate): Generated certificate.
    """
    cert = x509.CertificateBuilder().subject_name(
        request.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        request.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=expiration_days)
    )
    
    if(subject_key_identifier_set):
        cert = cert.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(request.public_key()),
            critical=False
        )

    if(authority_key_identifier_set):
        cert = cert.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False
        )

    valid_extensions = (
        x509.SubjectAlternativeName, x509.KeyUsage, 
        x509.ExtendedKeyUsage,x509.CertificatePolicies, 
        x509.AuthorityInformationAccess
    )

    for ext in request.extensions:
        if isinstance(ext.value,valid_extensions):
            cert = cert.add_extension(ext.value, critical=ext.critical)
        else:
            print("Extension not supported: ", ext.value)
            pass


    return cert;

def generate_tls_server_cert(
        ca_cert_path : str, 
        ca_key_path : str, 
        ca_passphrase_path : str,
        dest_folder : str,
        country_code : str, 
        common_name : str, 
        hostname : str,
        expiration_days : int = 365
    ) -> x509.Certificate:
    """
    Generate a simple device certificate.

    Parameters:
        ca_cert_path (str): Path to the ca certificate file.
        ca_key_path (str): Path to the ca private key file.
        ca_passphrase_path (str): Passphrase for the ca private key.
        dest_folder (str): Destination folder to save the device certificate.
        country_code (str): Country code for the device certificate.
        common_name (str): Common name for the device certificate.
        hostname (str): Hostname for the device certificate. Optional.
        expiration_days (int): Number of days until the certificate expires. Default is 365.

    Returns:
        cert (Certificate): Generated certificate.
    """
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase_path)
    private_key = setup_private_key(dest_folder, common_name)
    
    # Generate CSR
    request = generate_certificate_request(country_code, common_name, hostname)
    
    request = request.add_extension(
        x509.ExtendedKeyUsage([
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")  # id-kp-serverAuth OID
        ]),
        critical=False
    ).sign(private_key, hashes.SHA256())
    
    # Sign CSR with ca certificate
    cert = generate_certificate(request, ca_cert, expiration_days)
    cert = sign_certificate(ca_cert, ca_key, cert)
        
    save_cert_to_file(cert, dest_folder, common_name)
    return cert

def generate_tls_client_cert(
        ca_cert_path : str, 
        ca_key_path : str, 
        ca_passphrase_path : str,
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
        ca_passphrase_path (str): Passphrase for the ca private key.
        dest_folder (str): Destination folder to save the device certificate.
        country_code (str): Country code for the device certificate.
        common_name (str): Common name for the device certificate.
        hostname (str): Hostname for the device certificate. Optional.
        expiration_days (int): Number of days until the certificate expires. Default is 365.

    Returns:
        cert (Certificate): Generated certificate.
    """
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase_path)
    private_key = setup_private_key(dest_folder, common_name)

    # Generate CSR
    request = generate_certificate_request(country_code, common_name, hostname)
    
    request = request.add_extension(
                x509.ExtendedKeyUsage([
                    x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2")  # id-kp-client-auth OID
                ]),
                critical=False
            ).sign(private_key, hashes.SHA256())
    
    # Sign CSR with ca certificate
    cert = generate_certificate(request, ca_cert, expiration_days)
    cert = sign_certificate(ca_cert, ca_key, cert)
        
    save_cert_to_file(cert, dest_folder, common_name)
    return cert

def generate_ra_cert(
        ca_cert_path : str, ca_key_path : str, ca_passphrase_path : str,
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
        ca_passphrase_path (str): Passphrase for the CA private key.
        dest_folder (str): Destination folder to save the RA certificate.
        country_code (str): Country code for the RA certificate.
        common_name (str): Common name for the RA certificate.
        hostname (str): Hostname for the RA certificate.
        expiration_days (int): Number of days until the certificate expires. Default is 365.

    Returns:
        cert (Certificate): Generated certificate.
    """
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase_path)
    private_key = setup_private_key(dest_folder, common_name)

    # Generate CSR
    request = generate_certificate_request(country_code, common_name, hostname)
    
    # Add RA specific extensions
    request = request.add_extension(
        x509.ExtendedKeyUsage([
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.28"),  # id-kp-cmcRA OID
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")  # id-kp-serverAuth OID
        ]),
        critical=False
    ).sign(private_key, hashes.SHA256())
    

    cert = generate_certificate(request, ca_cert, expiration_days)
    cert = sign_certificate(ca_cert, ca_key, cert)

    save_cert_to_file(cert, dest_folder, common_name)
    return cert

def generate_idevid_cert(
        ca_cert_path: str, 
        ca_key_path: str, 
        ca_passphrase_path: str,
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
        ca_passphrase_path (str): Passphrase for the ca private key.
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

    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase_path)
    private_key = setup_private_key(dest_folder, common_name)

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
    request = generate_certificate_request(
        country_code, common_name, 
        organization_name, organizational_unit_name
    )
        
    
    if(OtherName):
        request = request.add_extension(
            alternative_name,
            critical=False,
        )

    # Add idevid specific extensions
    request = request.sign(private_key, hashes.SHA256())

    cert = generate_certificate(request, ca_cert, expiration_days, subject_key_identifier_set=False)
    cert = cert.add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False, 
                      data_encipherment=False, key_agreement=False, encipher_only=False, 
                      decipher_only=False, key_cert_sign=False, crl_sign=False),
        critical=True
    )

    cert = sign_certificate(ca_cert, ca_key, cert)

    save_cert_to_file(cert, dest_folder, common_name, "cert")
    return cert
