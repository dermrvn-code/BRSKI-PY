import os

def clear_certificates():
    folder = [
        "../Pledge/ca/",
        "../Pledge/certs/",
        "../MASA/ca/",
        "../MASA/certs/",
        "../Registrar/ca/",
        "../Registrar/certs/server",
        "../Registrar/certs/client"
    ]

    for path in folder:
        for file in os.listdir(path):
            file_endings = [".key", ".txt", ".crt", ".pem", ".crl"]  # Add the desired file endings here
            
            if any(file.endswith(ending) for ending in file_endings):
                print(f"Removing {file}")
                os.remove(os.path.join(path, file))

if __name__ == "__main__":
    clear_certificates()