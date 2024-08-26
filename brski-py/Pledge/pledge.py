from enroll import request_ldevid_cert
from paths import *
from sends_requests import open_socket_connection, request_voucher

script_dir, parent_dir = set_parent_dir(__file__)

from Utils.Config import Config
from Utils.Interface import yes_or_no
from Utils.Printer import *

ldev_cert_file_path, ldev_private_key_path, ldev_passphrase_path = "", "", ""


def main() -> None:
    print_title("Pledge")

    while True:
        try:
            selection = input("Do you want to bootstrap or communicate? (b/c): ")

            if selection == "b":
                bootstrap()
            elif selection == "c":
                communication()
            else:
                print("Invalid selection, please try again.")

            print("\n" * 10)
        except KeyboardInterrupt:
            break


def communication():

    ldev_cert_file_path, ldev_private_key_path, ldev_passphrase_path = load_ldev_certs()

    if (
        ldev_cert_file_path == ""
        or ldev_private_key_path == ""
        or ldev_passphrase_path == ""
    ):
        print_error("No valid LDevID certificate found")

    open_socket_connection(
        Config.get("REGISTRAR", "hostname"),
        int(Config.get("REGISTRAR", "localcommunicationport")),
        ldev_cert_file_path,
        ldev_private_key_path,
        ldev_passphrase_path,
    )


def bootstrap():
    print_info("Requesting voucher...")
    voucher = request_voucher(
        Config.get("REGISTRAR", "hostname"),
        int(Config.get("REGISTRAR", "port")),
    )

    if voucher:
        print_success("Voucher received and validated successfully:")
        voucher.print()
    else:
        print_error("No valid voucher received")
        return

    request_ldevcert = yes_or_no("Do you want to request a LDevID Certificate?")

    if request_ldevcert:
        serialnumber = Config.get("PLEDGE", "serialnumber")
        print_info(f"Requesting LDevID Certificate for serialnumber: {serialnumber}...")
        cert_file_path, private_key_path, passphrase_path = request_ldevid_cert(
            serialnumber
        )

    if cert_file_path == "" or private_key_path == "" or passphrase_path == "":
        print_error("No valid LDevID certificate received")
        return


def load_ldev_certs() -> tuple[str, str, str]:
    """
    Load the LDevID certificate files.

    Returns:
        str: The path to the LDevID certificate file.
        str: The path to the LDevID private key file.
        str: The path to the LDevID passphrase file.
    """

    # Destination folder for the LDevID certificate files
    dest_folder = os.path.join(script_dir, "certs/ldevid")
    serialnumber = Config.get("PLEDGE", "serialnumber")

    private_key_path = os.path.join(
        dest_folder, f"cert_private_pledge.{serialnumber}.key"
    )
    cert_path = os.path.join(dest_folder, f"cert_pledge.{serialnumber}.crt")
    passphrase_path = os.path.join(dest_folder, f"pledge.{serialnumber}_passphrase.txt")

    print(os.path.exists(private_key_path), private_key_path)
    print(os.path.exists(cert_path), cert_path)
    print(os.path.exists(passphrase_path), passphrase_path)

    if (
        os.path.exists(private_key_path)
        and os.path.exists(cert_path)
        and os.path.exists(passphrase_path)
    ):
        return cert_path, private_key_path, passphrase_path
    else:
        return "", "", ""


# TODO: Write a socket communication script with ldevid_cert to display secure connection establishment

if __name__ == "__main__":
    main()
