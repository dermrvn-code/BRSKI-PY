import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)


def clear_certificates():
    folder = [
        "Pledge/certs/ca/",
        "Pledge/certs/ldevid/",
        "Pledge/certs/",
        "MASA/certs/ca/",
        "MASA/certs/",
        "Registrar/certs/ca/",
        "Registrar/certs/server",
        "Registrar/certs/client",
        "Authorities/certs/ca/",
        "Authorities/certs/",
    ]

    for path in folder:
        path = os.path.join(parent_dir, path)
        if os.path.exists(path):
            for file in os.listdir(path):
                file_endings = [
                    ".key",
                    ".txt",
                    ".crt",
                    ".pem",
                    ".crl",
                ]  # Add the desired file endings here

                if any(file.endswith(ending) for ending in file_endings):
                    print(f"Removing {file}")
                    os.remove(os.path.join(path, file))


if __name__ == "__main__":
    clear_certificates()
