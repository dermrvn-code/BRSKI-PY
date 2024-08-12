import sys
from cryptography import x509
sys.path.append("../") 
from Certificates.Certificate import generate_idevid_cert, generate_tls_client_cert, generate_ra_cert, generate_tls_server_cert
from Certificates.CA import generate_certificate_authority
from Certificates.CertificateRevocationList import generate_certificate_revocation_list


def generate_certificates() -> None:
    # Manufacturer ca
    dest_folder = "../Pledge/ca/"
    common_name = "Manufacturer"
    (ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = generate_certificate_authority(dest_folder, country_code="DE", common_name=common_name)
    print("Generated Manufacturer ca certificate")

    # Manufacturer CRL
    generate_certificate_revocation_list(ca_cert_path, ca_key_path, passphrase_path, dest_folder, common_name=common_name)
    print("Generated Manufacturer CRL")

    # Pledge IDevID certificate
    dest_folder = "../Pledge/certs/"
    generate_idevid_cert(
        ca_cert_path, ca_key_path, passphrase_path, dest_folder,
        country_code="DE", serialnumber="02481632", 
        organization_name="HSHL", organizational_unit_name="Trustpoint", 
        common_name="Pledge", masa_url="https://localhost:8888/.well-known/brski",
        hwtype="1.3.6.1.4.1.343.2.17.1", hwSerialNum="123456")
    print("Generated Pledge IDevID certificate")



    # MASA ca
    dest_folder = "../MASA/ca/"
    common_name = "MASA_ca"
    (ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = generate_certificate_authority(dest_folder, country_code="DE", common_name=common_name)
    print("Generated MASA ca certificate")

    # MASA CRL
    generate_certificate_revocation_list(ca_cert_path, ca_key_path, passphrase_path, dest_folder, common_name=common_name)
    print("Generated MASA CRL")

    dest_folder = "../MASA/certs/"
    generate_tls_server_cert(
        ca_cert_path, ca_key_path, passphrase_path, 
        dest_folder,
        country_code="DE", common_name="MASA", 
        hostname="localhost")
    print("Generated MASA certificate")



    # Registrar ca
    dest_folder = "../Registrar/ca/"
    common_name = "Registrar_ca"
    (ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = generate_certificate_authority(dest_folder, country_code="DE", common_name=common_name)
    print("Generated Registrar ca certificate")

    # Registrar CRL
    generate_certificate_revocation_list(ca_cert_path, ca_key_path, passphrase_path, dest_folder, common_name=common_name)
    print("Generated Registrar CRL")

    dest_folder = "../Registrar/certs/server"
    generate_ra_cert(
        ca_cert_path, ca_key_path, passphrase_path, 
        dest_folder,
        country_code="DE", common_name="registrar_server", 
        hostname="localhost")
    print("Generated Registrar RA certificate")

    dest_folder = "../Registrar/certs/client"
    generate_tls_client_cert(
        ca_cert_path, ca_key_path, passphrase_path, 
        dest_folder,
        country_code="DE", common_name="registrar_client",
        hostname="localhost"
    )
    print("Generated Registrar Client certificate")

    # CA Server ca
    dest_folder = "../Authorities/ca/"
    common_name = "CAServer_ca"
    (ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = generate_certificate_authority(dest_folder, country_code="DE", common_name=common_name)
    print("Generated Authorities ca certificate")

    # CA Server CRL
    generate_certificate_revocation_list(ca_cert_path, ca_key_path, passphrase_path, dest_folder=dest_folder, common_name=common_name)
    print("Generated Authorities CRL")

    dest_folder = "../Authorities/certs/"
    generate_tls_server_cert(
        ca_cert_path, ca_key_path, passphrase_path, 
        dest_folder,
        country_code="DE", common_name="Authorities", 
        hostname="localhost"
    )


if __name__ == "__main__":
    generate_certificates()
