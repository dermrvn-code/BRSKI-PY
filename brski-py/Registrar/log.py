from paths import set_parent_dir

script_dir, parent_dir = set_parent_dir(__file__)

from Utils.Logger import Logger
from Utils.Printer import *


def log_error(logger: Logger, serialNumber: str, msg: str, is_request: bool = True):
    prefix = (
        "No voucher request was forwarded " if is_request else "No voucher was issued "
    )
    print_error(msg)
    logger.log(f"{prefix} for serial number {serialNumber}: {msg}")
