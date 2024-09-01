import datetime
from os import makedirs, path

from Certificates.CA import load_ca, sign_certificate
from Certificates.Keys import setup_private_key
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import encoder
from pyasn1.type import char, namedtype, univ  # type: ignore


def load_request_from_bytes(data: bytes) -> x509.CertificateSigningRequest:
    """
    Load a certificate request from bytes.

    Args:
        data (bytes): The bytes representing the certificate request.

    Returns:
        CertificateSigningRequest: The loaded certificate request.

    Raises:
        ValueError: If the bytes are neither PEM nor DER encoded.
    """
    try:
        return x509.load_pem_x509_csr(data, backend=default_backend())
    except:
        try:
            return x509.load_der_x509_csr(data, backend=default_backend())
        except:
            raise ValueError(
                "Could not load certificate request from bytes. Bytes are neither PEM nor DER encoded."
            )


def load_request_from_path(path: str) -> x509.CertificateSigningRequest:
    """
    Load a certificate request from a file.

    Args:
        path (str): The path to the file containing the certificate request.

    Returns:
        CertificateSigningRequest: The loaded certificate request.
    """
    with open(path, "rb") as f:
        request_data = f.read()
    return load_request_from_bytes(request_data)


def load_certificate_from_path(path: str) -> x509.Certificate:
    """
    Load a certificate from a file.

    Args:
        path (str): The path to the file containing the certificate.

    Returns:
        Certificate: The loaded certificate.
    """
    with open(path, "rb") as f:
        cert_data = f.read()
    return x509.load_pem_x509_certificate(cert_data, backend=default_backend())


def load_certificate_from_bytes(data: bytes) -> x509.Certificate:
    """
    Load a certificate from bytes.

    Args:
        data (bytes): The bytes representing the certificate.

    Returns:
        Certificate: The loaded certificate.

    Raises:
        ValueError: If the bytes are neither PEM nor DER encoded.
    """
    try:
        return x509.load_pem_x509_certificate(data, backend=default_backend())
    except:
        try:
            return x509.load_der_x509_certificate(data, backend=default_backend())
        except:
            raise ValueError(
                "Could not load certificate from bytes. Bytes are neither PEM nor DER encoded."
            )


def load_certificate_bytes_from_certificate(certfile: x509.Certificate) -> bytes:
    """
    Get the bytes representation of a certificate.

    Args:
        certfile (Certificate): The certificate object.

    Returns:
        bytes: The bytes representation of the certificate.
    """
    return certfile.public_bytes(serialization.Encoding.DER)


def load_certificate_bytes_from_path(path) -> bytes:
    """
    Get the bytes representation of a certificate from a file.

    Args:
        path (str): The path to the file containing the certificate.

    Returns:
        bytes: The bytes representation of the certificate.
    """
    return load_certificate_bytes_from_certificate(load_certificate_from_path(path))


def save_cert_to_file(
    cert: x509.Certificate,
    dest_folder: str,
    *,
    common_name: str,
    file_prefix: str = "cert",
) -> str:
    """
    Save the certificate to a file.

    Args:
        cert (Certificate): Certificate to be saved.
        dest_folder (str): Destination folder to save the certificate file.
        common_name (str): Common name used for naming the file.
        cert_type (str): Type of the certificate. Default is "cert".

    Returns:
        file_path (str): Path to the saved certificate file.
    """
    if not path.exists(dest_folder):
        makedirs(dest_folder)

    file_path = path.join(dest_folder, f"{file_prefix}_{common_name.lower()}.crt")
    with open(file_path, "wb") as device_cert_file:
        device_cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    return file_path


def save_request_to_file(
    request: x509.CertificateSigningRequest,
    dest_folder: str,
    *,
    common_name: str,
    file_prefix: str = "request",
) -> str:
    """
    Save the certificate request to a file.

    Args:
        request (CertificateSigningRequest): Certificate request to be saved.
        dest_folder (str): Destination folder to save the certificate request file.
        common_name (str): Common name used for naming the file.
        file_prefix (str): Prefix used for naming the file. Default is "request".

    Returns:
        file_path (str): Path to the saved certificate request file.
    """
    if not path.exists(dest_folder):
        makedirs(dest_folder)

    file_path = path.join(dest_folder, f"{file_prefix}_{common_name.lower()}.csr")
    with open(file_path, "wb") as request_file:
        request_file.write(request.public_bytes(serialization.Encoding.PEM))

    return file_path


def generate_certificate_request_builder(
    *,
    country_code: str,
    common_name: str,
    serialnumber: str = "",
    hostname: str = "",
    organization_name: str = "",
    organizational_unit_name: str = "",
) -> x509.CertificateSigningRequestBuilder:
    """
    Generate a certificate signing request (CSR).

    Args:
        country_code (str): Country code for the certificate.
        common_name (str): Common name for the certificate.
        serialnumber (str): Serial number for the device.
        hostname (str): Hostname for the certificate.
        organization_name (str): Organization name for the certificate.
        organizational_unit_name (str): Organizational unit name for the certificate.

    Returns:
        request_builder (CertificateSigningRequestBuilder): Generated CSR Builder.
    """
    nameAttributes = [x509.NameAttribute(NameOID.COUNTRY_NAME, country_code)]

    if organization_name:
        nameAttributes.append(
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name)
        )

    if organizational_unit_name:
        nameAttributes.append(
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit_name
            )
        )

    if hostname:
        nameAttributes.append(x509.NameAttribute(NameOID.COMMON_NAME, hostname))
    else:
        nameAttributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    if serialnumber:
        nameAttributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serialnumber))

    request_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(nameAttributes)
    )

    if hostname:
        request_builder = request_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        )

    return request_builder


def generate_certificate_builder(
    request: x509.CertificateSigningRequest,
    *,
    ca_cert: x509.Certificate,
    authority_key_identifier_set: bool = True,
    subject_key_identifier_set: bool = True,
    expiration_days: int = 365,
    expiration_date: datetime.datetime | None = None,
) -> x509.CertificateBuilder:
    """
    Generate a certificate based on the given CSR and CA certificate.

    Args:
        request (CertificateSigningRequestBuilder): Certificate signing request.
        ca_cert (Certificate): CA certificate used for signing.
        authority_key_identifier_set (bool): Whether to set the authority key identifier. Default is True.
        subject_key_identifier_set (bool): Whether to set the subject key identifier. Default is True.
        expiration_days (int): Number of days until the certificate expires. Default is 365.
        expiration_date (datetime): Explicit expiration date of the certificate.
    Returns:
        cert_builder (CertificateBuilder): Generated certificate builder.
    """

    if expiration_date == None:
        expiration_date = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            days=expiration_days
        )

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(request.subject)
        .issuer_name(ca_cert.subject)
        .public_key(request.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(expiration_date)
    )

    if subject_key_identifier_set:
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(request.public_key()),
            critical=False,
        )

    if authority_key_identifier_set:
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
            critical=False,
        )

    valid_extensions = (
        x509.SubjectAlternativeName,
        x509.KeyUsage,
        x509.ExtendedKeyUsage,
        x509.CertificatePolicies,
        x509.AuthorityInformationAccess,
    )

    for ext in request.extensions:
        if isinstance(ext.value, valid_extensions):
            cert_builder = cert_builder.add_extension(ext.value, critical=ext.critical)
        else:
            print("Extension not supported: ", ext.value)
            pass

    return cert_builder


def generate_tls_server_cert(
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase_path: str,
    dest_folder: str,
    *,
    country_code: str,
    common_name: str,
    hostname: str,
    expiration_days: int = 365,
) -> x509.Certificate:
    """
    Generate a simple device certificate.

    Args:
        ca_cert_path (str): Path to the ca certificate file.
        ca_key_path (str): Path to the ca private key file.
        ca_passphrase_path (str): Passphrase for the ca private key.
        dest_folder (str): Destination folder to save the device certificate.
        country_code (str): Country code for the device certificate.
        common_name (str): Common name for the device certificate.
        hostname (str): Hostname for the device certificate.
        expiration_days (int): Number of days until the certificate expires. Default is 365.

    Returns:
        cert (Certificate): Generated certificate.
    """
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase_path)
    private_key, _, _ = setup_private_key(dest_folder, common_name)

    # Generate CSR
    request = generate_certificate_request_builder(
        country_code=country_code, common_name=common_name, hostname=hostname
    )

    request = request.add_extension(
        x509.ExtendedKeyUsage(
            [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]  # id-kp-serverAuth OID
        ),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Sign CSR with ca certificate
    cert = generate_certificate_builder(
        request, ca_cert=ca_cert, expiration_days=expiration_days
    )
    cert = sign_certificate(ca_cert, ca_key, cert)

    save_cert_to_file(cert, dest_folder, common_name=common_name)
    return cert


def generate_tls_client_cert(
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase_path: str,
    dest_folder: str,
    *,
    country_code: str,
    common_name: str,
    hostname: str = "",
    expiration_days: int = 365,
) -> x509.Certificate:
    """
    Generate a simple device certificate.

    Args:
        ca_cert_path (str): Path to the ca certificate file.
        ca_key_path (str): Path to the ca private key file.
        ca_passphrase_path (str): Passphrase for the ca private key.
        dest_folder (str): Destination folder to save the device certificate.
        country_code (str): Country code for the device certificate.
        common_name (str): Common name for the device certificate.
        hostname (str): Hostname for the device certificate.
        expiration_days (int): Number of days until the certificate expires. Default is 365.

    Returns:
        cert (Certificate): Generated certificate.
    """
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase_path)
    private_key, _, _ = setup_private_key(dest_folder, common_name)

    # Generate CSR
    request = generate_certificate_request_builder(
        country_code=country_code, common_name=common_name, hostname=hostname
    )

    request = request.add_extension(
        x509.ExtendedKeyUsage(
            [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2")]  # id-kp-client-auth OID
        ),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Sign CSR with ca certificate
    cert = generate_certificate_builder(
        request, ca_cert=ca_cert, expiration_days=expiration_days
    )
    cert = sign_certificate(ca_cert, ca_key, cert)

    save_cert_to_file(cert, dest_folder, common_name=common_name)
    return cert


def generate_ra_cert(
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase_path: str,
    dest_folder: str,
    *,
    country_code: str,
    common_name: str,
    hostname: str,
    expiration_days: int = 365,
) -> x509.Certificate:
    """
    Generate a RA (Registration Authority) certificate.

    Args:
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
    private_key, _, _ = setup_private_key(dest_folder, common_name)

    # Generate CSR
    request = generate_certificate_request_builder(
        country_code=country_code, common_name=common_name, hostname=hostname
    )

    # Add RA specific extensions
    request = request.add_extension(
        x509.ExtendedKeyUsage(
            [
                x509.ObjectIdentifier("1.3.6.1.5.5.7.3.28"),  # id-kp-cmcRA OID
                x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1"),  # id-kp-serverAuth OID
            ]
        ),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    cert = generate_certificate_builder(
        request, ca_cert=ca_cert, expiration_days=expiration_days
    )
    cert = sign_certificate(ca_cert, ca_key, cert)

    save_cert_to_file(cert, dest_folder, common_name=common_name)
    return cert


def generate_idevid_cert(
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase_path: str,
    dest_folder: str,
    *,
    country_code: str,
    serialnumber: str,
    organization_name: str,
    organizational_unit_name: str,
    common_name: str,
    masa_url: str,
    hwtype: str = "",
    hwSerialNum: str = "",
) -> x509.Certificate:
    """
    Generate an idevid device certificate.

    Args:
        ca_cert_path (str): Path to the ca certificate file.
        ca_key_path (str): Path to the ca private key file.
        ca_passphrase_path (str): Passphrase for the ca private key.
        dest_folder (str): Destination folder to save the device certificate.
        country_code (str): Country code for the device certificate.
        serialnumber (str): Serial number for the device.
        organization_name (str): Organization name for the device certificate.
        organizational_unit_name (str): Organizational unit name for the device certificate.
        common_name (str): Common name for the device certificate.
        masa_url (str): URL of the MASA server.
        expiration_days (int): Number of days until the certificate expires. Default is 365.
        hwtype (str): OID of Hardware Modules Type. Default is None.
        hwSerialNum (str): Serial Number of the hardware Module. Default is None.

    Returns:
        cert (Certificate): Generated certificate.
    """

    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase_path)
    private_key, _, _ = setup_private_key(dest_folder, common_name)

    useOtherName = hwtype != "" and hwSerialNum != ""

    if useOtherName:

        class OtherName(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("hwType", univ.ObjectIdentifier()),
                namedtype.NamedType("hwSerialNum", univ.OctetString()),
            )

        # Create an instance of your data
        data = OtherName()
        data["hwType"] = univ.ObjectIdentifier(hwtype)
        data["hwSerialNum"] = hwSerialNum

        der_data = encoder.encode(data)

        alternative_name = x509.SubjectAlternativeName(
            [
                x509.OtherName(
                    x509.ObjectIdentifier("1.3.6.1.5.5.7.8.4"), der_data
                )  # id-on-hardwareModuleName OID
            ]
        )

    # Generate CSR
    request = generate_certificate_request_builder(
        country_code=country_code,
        common_name=common_name,
        serialnumber=serialnumber,
        organization_name=organization_name,
        organizational_unit_name=organizational_unit_name,
    )

    if useOtherName:
        request = request.add_extension(
            alternative_name,
            critical=False,
        )

    request = request.sign(private_key, hashes.SHA256())

    # Create certificate with an "infinite" far away expiration date
    cert = generate_certificate_builder(
        request,
        ca_cert=ca_cert,
        subject_key_identifier_set=False,
        expiration_date=datetime.datetime(9999, 12, 31),
    )
    cert = cert.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False,
        ),
        critical=True,
    ).add_extension(MASAURLExt(masa_url), critical=False)

    cert = sign_certificate(ca_cert, ca_key, cert)

    save_cert_to_file(cert, dest_folder, common_name=common_name, file_prefix="cert")
    return cert


def MASAURLExt(uri: str) -> x509.ExtensionType:
    """
    Creates a MASA URL extension for a certificate.

    Args:
        uri (str): The MASA URL to be encoded in the extension.

    Returns:
        Extension: The MASA URL extension.
    """

    class MASAURLSyntax(char.IA5String):
        pass

    # Create an instance of MASAURLSyntax
    masa_url = MASAURLSyntax(uri)
    encoded_masa_url = encoder.encode(masa_url)[2:]  # Skip the first two bytes

    return x509.UnrecognizedExtension(
        oid=x509.ObjectIdentifier("1.3.6.1.5.5.7.1.32"), value=encoded_masa_url
    )


def generate_ldevid_cert_from_request(
    request: x509.CertificateSigningRequest,
    *,
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase_path: str,
    dest_folder: str,
) -> x509.Certificate:
    """
    Generates an LDevID certificate from a certificate request.

    Args:
        request (CertificateSigningRequest): The certificate signing request.
        ca_cert_path (str): The file path of the CA certificate.
        ca_key_path (str): The file path of the CA private key.
        ca_passphrase_path (str): The file path of the passphrase for the CA private key.
        dest_folder (str): The destination folder to save the generated certificate.
        common_name (str): The common name for the generated certificate.

    Returns:
        Certificate: The generated LDevID certificate.

    Raises:
        ValueError: If the common name is not found in the certificate request
    """

    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path, ca_passphrase_path)

    cert = generate_certificate_builder(
        request,
        ca_cert=ca_cert,
        expiration_date=datetime.datetime(
            9999, 12, 31
        ),  # "infinite" far away expiration date
    )
    cert = sign_certificate(ca_cert, ca_key, cert)

    common_name = request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

    if len(common_name) == 0:
        raise ValueError("Common name not found in certificate request.")

    common_name = str(common_name[0].value)

    save_cert_to_file(cert, dest_folder, common_name=common_name)
    return cert


def generate_ldevid_request(
    *,
    dest_folder_request: str,
    dest_folder_key: str,
    country_code: str,
    serialnumber: str,
    common_name: str,
) -> tuple[x509.CertificateSigningRequest, str, str, str]:
    """
    Generate an LDevID certificate request.

    Args:
        dest_folder_request (str): Destination folder to save the certificate request.
        dest_folder_key (str): Destination folder to save the private key.
        country_code (str): Country code for the certificate request.
        serialnumber (str): Serial number for the device.
        common_name (str): Common name for the device certificate.

    Returns:
        Tuple:
        - CertificateSigningRequest: Generated certificate request.
        - str: Path to the saved certificate request
        - str: Path to the saved private key
    """

    private_key, private_key_path, passphrase_file_path = setup_private_key(
        dest_folder_key, common_name
    )

    # Generate CSR
    request = generate_certificate_request_builder(
        country_code=country_code, common_name=common_name, serialnumber=serialnumber
    ).sign(private_key, hashes.SHA256())

    request_file_path = save_request_to_file(
        request, dest_folder=dest_folder_request, common_name=common_name
    )

    return request, request_file_path, private_key_path, passphrase_file_path
