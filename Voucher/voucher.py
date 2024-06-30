import json
import base64
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

class Voucher:
    def __init__(self, version, created_on, expires_on, serial_number, nonce, pinned_domain_cert, domain_id, assertion):
        self.version = version
        self.created_on = created_on
        self.expires_on = expires_on
        self.serial_number = serial_number
        self.nonce = nonce
        self.pinned_domain_cert = pinned_domain_cert
        self.domain_id = domain_id
        self.assertion = assertion
        self.masa_signature = None

    def to_dict(self, exclude_masa_signature=False):
        dict = {
            "version": self.version,
            "created_on": self.created_on,
            "expires_on": self.expires_on,
            "serial_number": self.serial_number,
            "nonce": self.nonce,
            "pinned_domain_cert": self.pinned_domain_cert,
            "domain_id": self.domain_id,
            "assertion": self.assertion,
            # Exclude masa_signature here
        }

        if not exclude_masa_signature:
            dict["masa_signature"] = self.masa_signature

        return dict

    '''
    TODO: Implement the sign and verify method using PKCS#4
    '''
    def sign(self, masa_private_key):
        # Create a copy of the voucher data dictionary without masa_signature
        data_to_sign = self.to_dict(True)
        
        # Convert to JSON and encode
        voucher_data = json.dumps(data_to_sign, sort_keys=True).encode('utf-8')
        
        # Sign the voucher data
        signature = masa_private_key.sign(
            voucher_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self.masa_signature = base64.b64encode(signature).decode('utf-8')

    def verify(self, masa_public_key, registrar_domain, registrar_cert):
        if self.masa_signature is None:
            raise ValueError("Voucher is not signed")
        
        # Create a copy of the voucher data dictionary without masa_signature
        data_to_verify = self.to_dict(True)
        
        # Convert to JSON and encode
        voucher_data = json.dumps(data_to_verify, sort_keys=True).encode('utf-8')
        
        signature = base64.b64decode(self.masa_signature)
        
        try:
            masa_public_key.verify(
                signature,
                voucher_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            if self.domain_id != registrar_domain:
                raise ValueError("Domain ID mismatch")
            
            registrar_cert_bytes = registrar_cert.public_bytes(serialization.Encoding.DER)
            if self.pinned_domain_cert != base64.b64encode(registrar_cert_bytes).decode('utf-8'):
                raise ValueError("Registrar certificate mismatch")
            
            return True
        except Exception as e:
            print(f"Verification failed: {e}")
            return False

def create_voucher(masa_private_key, registrar_cert_bytes, domain_id, assertion, serial_number="1234567890", validity_days=7):
    nonce = base64.b64encode(b'some_random_nonce').decode('utf-8')
    current_time = datetime.now(timezone.utc).isoformat()
    expiration_time = (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat()
    pinned_domain_cert = base64.b64encode(
        registrar_cert_bytes
    ).decode('utf-8')
    voucher = Voucher(
        version="1",
        created_on=current_time,
        expires_on=expiration_time,
        serial_number=serial_number,
        nonce=nonce,
        pinned_domain_cert=pinned_domain_cert,
        domain_id=domain_id,
        assertion=assertion
    )
    voucher.sign(masa_private_key)
    return voucher

def parse_voucher(voucher_json):
    voucher_dict = json.loads(voucher_json)
    voucher = Voucher(
        version=voucher_dict["version"],
        created_on=voucher_dict["created_on"],
        expires_on=voucher_dict["expires_on"],
        serial_number=voucher_dict["serial_number"],
        nonce=voucher_dict["nonce"],
        pinned_domain_cert=voucher_dict["pinned_domain_cert"],
        domain_id=voucher_dict["domain_id"],
        assertion=voucher_dict["assertion"]
    )
    voucher.masa_signature = voucher_dict["masa_signature"]
    return voucher
