from paths import global_log_file, set_parent_dir
from request_handlers import *

script_dir, parent_dir = set_parent_dir(__file__)

from Utils.Config import Config
from Utils.HTTPS import HTTPSServer
from Utils.Logger import Logger
from Utils.Printer import print_title

global_logger = Logger(os.path.join(script_dir, global_log_file))


def main() -> None:
    print_title("MASA")
    routes = {
        Config.get("MASA", "brskipath"): (handle_request_voucher, global_logger),
        Config.get("MASA", "publickeypath"): handle_public_key,
        Config.get("MASA", "auditlogpath"): (handle_request_audit_log, global_logger),
    }
    certfile = os.path.join(script_dir, cert_file_path)
    keyfile = os.path.join(script_dir, key_file_path)
    passphrasefile = os.path.join(script_dir, passphrase_file_path)
    local_cas = Config.get_values_from_section("CAS")

    server = HTTPSServer(
        address=Config.get("MASA", "hostname"),
        port=Config.get("MASA", "port"),
        routes_post=routes,
        certfile=certfile,
        keyfile=keyfile,
        passphrasefile=passphrasefile,
        local_cas=local_cas,
    )
    server.start()


if __name__ == "__main__":
    main()
