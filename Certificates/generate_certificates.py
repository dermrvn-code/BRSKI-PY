from Certificate import generate_idevid_cert, generate_tls_client_cert, generate_ra_cert
from CA import generate_certificate_authority
from CertificateRevocationList import generate_certificate_revocation_list, update_certificate_revocation_list


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
    expiration_days=365,
    othername_model="ESP32", othername_serialnumber="123456", othername_manufacturer="Espressif")
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
