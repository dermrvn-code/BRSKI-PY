from Certicate import generate_idevid_device_cert, generate_basic_cert, generate_ra_cert
from CA import generate_certificate_authority


# Manufacturer ca
dest_folder = "../Pledge/ca/"
(ca_cert_path, ca_key_path, ca_public_key_path, passphrase) = generate_certificate_authority("DE", "Manufacturer", dest_folder)
print("Generated Manufacturer ca certificate")

# Pledge IDevID certificate
dest_folder = "../Pledge/certs/"
generate_idevid_device_cert(
    ca_cert_path, ca_key_path, passphrase, 
    dest_folder,
    "DE", "HSHL", "Trustpoint", "Pledge",
    expiration_days=365,
    othername_model="ESP32", othername_serialnumber="123456", othername_manufacturer="Espressif")
print("Generated Pledge IDevID certificate")



# MASA ca
dest_folder = "../MASA/ca/"
(ca_cert_path, ca_key_path, ca_public_key_path, passphrase) = generate_certificate_authority("DE", "MASA_ca", dest_folder)
print("Generated MASA ca certificate")

dest_folder = "../MASA/certs/"
generate_basic_cert(
    ca_cert_path, ca_key_path, passphrase, 
    dest_folder,
    "DE", "MASA", 
    "localhost")
print("Generated MASA certificate")



# Registrar ca
dest_folder = "../Registrar/ca/"
(ca_cert_path, ca_key_path, ca_public_key_path, passphrase) = generate_certificate_authority("DE", "Registrar_ca", dest_folder)
print("Generated Registrar ca certificate")

dest_folder = "../Registrar/certs/server"
generate_ra_cert(
    ca_cert_path, ca_key_path, passphrase, 
    dest_folder,
    "DE", "registrar_server", 
    "localhost")
print("Generated Registrar RA certificate")

dest_folder = "../Registrar/certs/client"
generate_basic_cert(
    ca_cert_path, ca_key_path, passphrase, 
    dest_folder,
    "DE", "registrar_client"
)
print("Generated Registrar Client certificate")
