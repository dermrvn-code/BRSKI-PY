import sys
sys.path.append("../")
from Certificates.Keys import load_passphrase_from_path
from Utils.HTTPS import SSLConnection

def main() -> None:
    cert = "../Registrar/certs/client/cert_registrar_client.crt"
    private_key = "../Registrar/certs/client/cert_private_registrar_client.key"    
    passphrase = load_passphrase_from_path("../Registrar/certs/client/passphrase_registrar_client.txt")


    conn = SSLConnection(
        "localhost", 8008, 
        cert, 
        private_key, 
        passphrase
    )
    print(conn.get_request("/crl?from=registrar"))

if __name__ == "__main__":
    main()
