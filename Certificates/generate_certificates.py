from Certicate import generate_idevid_device_cert, generate_simple_device_cert
from CA import generate_certificate_authority


# Manufacturer CA
dest_folder = "../Pledge/ca/"
(ca_cert_path, ca_key_path, ca_public_key_path, passphrase) = generate_certificate_authority("DE", "Manufacturer", dest_folder)
print("Generated Manufacturer CA certificate")

# Pledge IDevID certificate
dest_folder = "../Pledge/certs/"
generate_idevid_device_cert(
    ca_cert_path, ca_key_path, passphrase, 
    dest_folder,
    "DE", "HSHL", "Trustpoint", "Pledge",
    expiration_days=365, OtherName=True,
    othername_model="ESP32", othername_serialnumber="123456", othername_manufacturer="Espressif")
print("Generated Pledge IDevID certificate")



# MASA CA
dest_folder = "../MASA/ca/"
(ca_cert_path, ca_key_path, ca_public_key_path, passphrase) = generate_certificate_authority("DE", "MASA_CA", dest_folder)
print("Generated MASA CA certificate")

dest_folder = "../MASA/certs/"
generate_simple_device_cert(
    ca_cert_path, ca_key_path, passphrase, 
    dest_folder,
    "DE", "MASA")
print("Generated MASA certificate")

