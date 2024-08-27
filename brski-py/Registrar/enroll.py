import json
import os

from paths import set_parent_dir

script_dir, parent_dir = set_parent_dir(__file__)

from Utils.Config import Config


def set_device_enrollment_status(
    serialnumber: str, allowed: bool | None = None, enrolled: bool | None = None
):
    """
    Set the enrollment status of a device identified by the given serial number.

    Args:
        serialnumber (str): The serial number of the device.
        allowed (bool | None): The allowed status of the device. If not provided, the current allowed status will be used. Defaults to None.
        enrolled (bool | None): The enrolled status of the device. If not provided, the current enrolled status will be used. Defaults to None.
    """

    enrollment_status, enrollment_file_path = get_enrollment_status()

    device_enrollment_status = get_device_enrollment_status(
        serialnumber, enrollment_status
    )

    enrollment_status[serialnumber] = {
        "allowed": (
            allowed if allowed is not None else device_enrollment_status["allowed"]
        ),
        "enrolled": (
            enrolled if enrolled is not None else device_enrollment_status["enrolled"]
        ),
    }

    # Update the enrollment status
    with open(enrollment_file_path, "w") as f:
        json.dump(enrollment_status, f)


def get_device_enrollment_status(
    serialnumber: str, enrollment_status: dict | None = None
) -> dict:
    """
    Retrieves the enrollment status of a device based on its serial number.

    Args:
        serialnumber (str): The serial number of the device.

    Returns:
        dict: A dictionary containing the enrollment status of the device. The dictionary has the following keys:
        - bool: Indicates whether the device is allowed for enrollment.
        - bool: Indicates whether the device is already enrolled.
    """

    if enrollment_status is None:
        enrollment_status, _ = get_enrollment_status()

    # TODO: Extend enrollment status with more information
    standard_enrollment_status = {"allowed": False, "enrolled": False}
    device_enrollment_status = enrollment_status.get(
        serialnumber, standard_enrollment_status
    )

    return device_enrollment_status


def get_enrollment_status() -> tuple[dict, str]:
    """
    Reads the enrollment status of all devices from the enrollment status file.

    Returns:
        Tuple:
        - dict : A dictionary containing the enrollment status of all devices.
        - str : The path to the enrollment status file.
    """
    enrollment_status_file_path = os.path.join(
        script_dir, Config.get("REGISTRAR", "enrollmentstatusfile")
    )

    enrollment_status = {}
    if os.path.exists(enrollment_status_file_path):
        with open(enrollment_status_file_path, "r") as f:
            enrollment_status = json.load(f)

    return enrollment_status, enrollment_status_file_path
