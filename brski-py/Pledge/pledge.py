from paths import *
from sends_requests import request_voucher

script_dir, parent_dir = set_parent_dir(__file__)

from Utils.Config import Config
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

            # TODO: Implement a exchange of LDevID Certificate Requests and Establish secure connection

        except KeyboardInterrupt:
            break


# TODO: Write request_ldevid_cert function
# TODO: Write a socket communication script with ldevid_cert to display secure connection establishment

if __name__ == "__main__":
    main()
