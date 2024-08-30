import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from Certificates.CA import generate_certificate_authority
from Certificates.Certificate import (generate_idevid_cert, generate_ra_cert,
                                      generate_tls_client_cert,
                                      generate_tls_server_cert)
from Certificates.CertificateRevocationList import \
    generate_certificate_revocation_list
from Certificates.clear_certificates import clear_certificates
from Utils.Config import Config


def generate_certificates() -> None:
    # Manufacturer ca
    dest_folder = "../Pledge/certs/ca/"
    dest_folder = os.path.abspath(os.path.join(script_dir, dest_folder))
    common_name = "Manufacturer"
    (ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = (
        generate_certificate_authority(
            dest_folder, country_code="DE", common_name=common_name
        )
    )
    print("Generated Manufacturer ca certificate")

    # Manufacturer CRL
    generate_certificate_revocation_list(
        ca_cert_path, ca_key_path, passphrase_path, dest_folder, common_name=common_name
    )
    print("Generated Manufacturer CRL")

    serialnumber = Config.get("PLEDGE", "serialnumber")
    masa_url = f"https://{Config.get("MASA", "hostname")}:{Config.get("MASA", "port")}{Config.get("MASA", "brskipath")}"

    # Pledge IDevID certificate
    dest_folder = "../Pledge/certs/"
    dest_folder = os.path.abspath(os.path.join(script_dir, dest_folder))
    generate_idevid_cert(
        ca_cert_path,
        ca_key_path,
        passphrase_path,
        dest_folder,
        country_code="DE",
        serialnumber=serialnumber,
        organization_name=Config.get("PLEDGE", "organization"),
        organizational_unit_name=Config.get("PLEDGE", "organizationunit"),
        common_name=f"pledge-{serialnumber}",
        masa_url=masa_url,
        hwtype=Config.get("PLEDGE", "hwtypeoid"),
        hwSerialNum=Config.get("PLEDGE", "hwserialnumber"),
    )
    print("Generated Pledge IDevID certificate")

    # MASA ca
    dest_folder = "../MASA/certs/ca/"
    dest_folder = os.path.abspath(os.path.join(script_dir, dest_folder))
    common_name = "MASA_ca"
    (ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = (
        generate_certificate_authority(
            dest_folder, country_code="DE", common_name=common_name
        )
    )
    print("Generated MASA ca certificate")

    # MASA CRL
    generate_certificate_revocation_list(
        ca_cert_path, ca_key_path, passphrase_path, dest_folder, common_name=common_name
    )
    print("Generated MASA CRL")

    dest_folder = "../MASA/certs/"
    dest_folder = os.path.abspath(os.path.join(script_dir, dest_folder))
    generate_tls_server_cert(
        ca_cert_path,
        ca_key_path,
        passphrase_path,
        dest_folder,
        country_code="DE",
        common_name="MASA",
        hostname=Config.get("MASA", "hostname"),
    )
    print("Generated MASA certificate")

    # Registrar ca
    dest_folder = "../Registrar/certs/ca/"
    dest_folder = os.path.abspath(os.path.join(script_dir, dest_folder))
    common_name = "Registrar_ca"
    (ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = (
        generate_certificate_authority(
            dest_folder, country_code="DE", common_name=common_name
        )
    )
    print("Generated Registrar ca certificate")

    # Registrar CRL
    generate_certificate_revocation_list(
        ca_cert_path, ca_key_path, passphrase_path, dest_folder, common_name=common_name
    )
    print("Generated Registrar CRL")

    dest_folder = "../Registrar/certs/server"
    dest_folder = os.path.abspath(os.path.join(script_dir, dest_folder))
    generate_ra_cert(
        ca_cert_path,
        ca_key_path,
        passphrase_path,
        dest_folder,
        country_code="DE",
        common_name="registrar_server",
        hostname=Config.get("REGISTRAR", "hostname"),
    )
    print("Generated Registrar RA certificate")

    dest_folder = "../Registrar/certs/client"
    dest_folder = os.path.abspath(os.path.join(script_dir, dest_folder))
    generate_tls_client_cert(
        ca_cert_path,
        ca_key_path,
        passphrase_path,
        dest_folder,
        country_code="DE",
        common_name="registrar_client",
        hostname=Config.get("REGISTRAR", "hostname"),
    )
    print("Generated Registrar Client certificate")

    # CA Server ca
    dest_folder = "../Authorities/certs/ca/"
    dest_folder = os.path.abspath(os.path.join(script_dir, dest_folder))
    common_name = "CAServer_ca"
    (ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = (
        generate_certificate_authority(
            dest_folder, country_code="DE", common_name=common_name
        )
    )
    print("Generated Authorities ca certificate")

    # CA Server CRL
    generate_certificate_revocation_list(
        ca_cert_path,
        ca_key_path,
        passphrase_path,
        dest_folder=dest_folder,
        common_name=common_name,
    )
    print("Generated Authorities CRL")

    dest_folder = "../Authorities/certs/"
    dest_folder = os.path.abspath(os.path.join(script_dir, dest_folder))
    generate_tls_server_cert(
        ca_cert_path,
        ca_key_path,
        passphrase_path,
        dest_folder,
        country_code="DE",
        common_name="Authorities",
        hostname=Config.get("AUTHORITIES", "hostname"),
    )


if __name__ == "__main__":
    clear_certificates()
    generate_certificates()
