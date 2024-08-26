import os
import shutil
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)


def reset_process():
    folders = [
        "Pledge/certs/ldevid",
        "Pledge/certs/ldevid_requests",
        "Registrar/issued_ldevid_certs",
        "Registrar/log",
        "MASA/log",
    ]

    for folder in folders:
        folder_path = os.path.join(script_dir, folder)
        if os.path.exists(folder_path):
            try:
                shutil.rmtree(folder_path)
                print(f"Removed folder {folder}")
            except PermissionError:
                print("Please stop all scripts, before running this script.")

    files = [
        "Registrar/enrollment_status.json",
    ]

    for file in files:
        file_path = os.path.join(script_dir, file)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"Removed file {file}")
            except PermissionError:
                print("Please stop all scripts, before running this script.")


if __name__ == "__main__":
    reset_process()
