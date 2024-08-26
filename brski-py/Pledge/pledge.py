from enroll import request_ldevid_cert
from paths import *
from sends_requests import request_voucher

script_dir, parent_dir = set_parent_dir(__file__)

from Utils.Config import Config
from Utils.Interface import yes_or_no
from Utils.Printer import *


def main() -> None:
    print_title("Pledge")

    while True:
        try:
            input("Press enter to request a voucher...")
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
                continue

            request_ldevcert = yes_or_no("Do you want to request a LDevID Certificate?")

            if request_ldevcert:
                serialnumber = Config.get("PLEDGE", "serialnumber")
                print_info(
                    f"Requesting LDevID Certificate for serialnumber: {serialnumber}..."
                )
                cert_file_path, private_key_path = request_ldevid_cert(serialnumber)

            # TODO: Implement a exchange of LDevID Certificate Requests and Establish secure connection

            print("\n"*3)
        except KeyboardInterrupt:
            break


# TODO: Write a socket communication script with ldevid_cert to display secure connection establishment

if __name__ == "__main__":
    main()
