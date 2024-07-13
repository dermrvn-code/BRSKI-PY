import os


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
        if file.endswith(".key") or file.endswith(".txt") or file.endswith(".crt") or file.endswith(".pem"):
            print(f"Removing {file}")
            os.remove(os.path.join(path, file))