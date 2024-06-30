from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

def load_passphrase(path):
    with open(path, "rb") as f:
        passphrase = f.read()
    return passphrase

def load_private_keyfile(path,passphrase):
    with open(path, "rb") as f:
        private_key_data = f.read()
    return load_pem_private_key(private_key_data, password=passphrase, backend=default_backend())

def load_public_keyfile(path):
    with open(path, "rb") as f:
        public_key_data = f.read()
    return load_pem_public_key(public_key_data, backend=default_backend())

def load_certificatefile(path):
    with open(path, "rb") as f:
        cert_data = f.read()
    return load_pem_x509_certificate(cert_data, backend=default_backend())