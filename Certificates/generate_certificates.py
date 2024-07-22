import sys
from cryptography import x509
sys.path.append("../") 
from Certificates.Certificate import generate_idevid_cert, generate_tls_client_cert, generate_ra_cert, generate_tls_server_cert
from Certificates.CA import generate_certificate_authority
from Certificates.CertificateRevocationList import generate_certificate_revocation_list


# Manufacturer ca
dest_folder = "../Pledge/ca/"
common_name = "Manufacturer"
(ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = generate_certificate_authority("DE", common_name, dest_folder)
print("Generated Manufacturer ca certificate")

# Manufacturer CRL
generate_certificate_revocation_list(ca_cert_path, ca_key_path, passphrase_path, dest_folder, common_name)
print("Generated Manufacturer CRL")

# Pledge IDevID certificate
dest_folder = "../Pledge/certs/"
generate_idevid_cert(
    ca_cert_path, ca_key_path, passphrase_path, 
    dest_folder,
    "DE", "HSHL", "Trustpoint", "Pledge",
    hwtype="1.3.6.1.4.1.343.2.17.1", hwSerialNum="123456")
print("Generated Pledge IDevID certificate")



# MASA ca
dest_folder = "../MASA/ca/"
common_name = "MASA_ca"
(ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = generate_certificate_authority("DE", common_name, dest_folder)
print("Generated MASA ca certificate")

# MASA CRL
generate_certificate_revocation_list(ca_cert_path, ca_key_path, passphrase_path, dest_folder, common_name)
print("Generated MASA CRL")

dest_folder = "../MASA/certs/"
generate_tls_client_cert(
    ca_cert_path, ca_key_path, passphrase_path, 
    dest_folder,
    "DE", "MASA", 
    "localhost")
print("Generated MASA certificate")



# Registrar ca
dest_folder = "../Registrar/ca/"
common_name = "Registrar_ca"
(ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = generate_certificate_authority("DE", common_name, dest_folder)
print("Generated Registrar ca certificate")

# Registrar CRL
generate_certificate_revocation_list(ca_cert_path, ca_key_path, passphrase_path, dest_folder, common_name)
print("Generated Registrar CRL")

dest_folder = "../Registrar/certs/server"
generate_ra_cert(
    ca_cert_path, ca_key_path, passphrase_path, 
    dest_folder,
    "DE", "registrar_server", 
    "localhost")
print("Generated Registrar RA certificate")

dest_folder = "../Registrar/certs/client"
generate_tls_client_cert(
    ca_cert_path, ca_key_path, passphrase_path, 
    dest_folder,
    "DE", "registrar_client",
    "localhost"
)
print("Generated Registrar Client certificate")

# CA Server ca
dest_folder = "../CAServer/ca/"
common_name = "CAServer_ca"
(ca_cert_path, ca_key_path, ca_public_key_path, passphrase_path) = generate_certificate_authority("DE", common_name, dest_folder)
print("Generated CAServer ca certificate")

# CA Server CRL
generate_certificate_revocation_list(ca_cert_path, ca_key_path, passphrase_path, dest_folder, common_name)
print("Generated CAServer CRL")

dest_folder = "../CAServer/certs/"
generate_tls_server_cert(
    ca_cert_path, ca_key_path, passphrase_path, 
    dest_folder,
    "DE", "CAServer", 
    "localhost"
)

