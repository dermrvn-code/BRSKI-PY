from paths import set_parent_dir
from request_handlers import *

script_dir, parent_dir = set_parent_dir(__file__)

from Utils.Config import Config
from Utils.HTTPS import HTTPSServer
from Utils.Printer import *

# TODO: Write sign_ldevid_request and url handler
# TODO: Write a socket communication script with ldevid_cert to display secure connection establishment to pledge


def main() -> None:
    print_title("Registrar")
    routes = {
        Config.get("REGISTRAR", "brskipath"): handle_request_voucher,
        Config.get("REGISTRAR", "voucherstatuspath"): handle_voucher_status,
    }

    certfile = os.path.join(script_dir, server_cert_file_path)
    keyfile = os.path.join(script_dir, server_key_file_path)
    passphrasefile = os.path.join(script_dir, server_passphrase_file_path)
    local_cas = Config.get_values_from_section("CAS")

    server = HTTPSServer(
        address=Config.get("REGISTRAR", "hostname"),
        port=Config.get("REGISTRAR", "port"),
        routes_post=routes,
        certfile=certfile,
        keyfile=keyfile,
        passphrasefile=passphrasefile,
        local_cas=local_cas,
    )
    server.start()


if __name__ == "__main__":
    main()
