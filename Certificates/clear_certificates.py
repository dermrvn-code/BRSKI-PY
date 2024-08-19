import os
import sys
# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

def clear_certificates():
    folder = [
        "Pledge/ca/",
        "Pledge/certs/",
        "MASA/ca/",
        "MASA/certs/",
        "Registrar/ca/",
        "Registrar/certs/server",
        "Registrar/certs/client",
        "Authorities/ca/",
        "Authorities/certs/"
    ]

    for path in folder:
        if(os.path.exists(path)):
            for file in os.listdir(path):
                file_endings = [".key", ".txt", ".crt", ".pem", ".crl"]  # Add the desired file endings here
                
                if any(file.endswith(ending) for ending in file_endings):
                    print(f"Removing {file}")
                    os.remove(os.path.join(path, file))

if __name__ == "__main__":
    clear_certificates()