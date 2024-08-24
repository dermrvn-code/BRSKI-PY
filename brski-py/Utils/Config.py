import os
from configparser import ConfigParser


class Config:
    config = ConfigParser()
    path = "config.ini"

    if not os.path.exists("config.ini"):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
        parent_dir = os.path.abspath(os.path.join(parent_dir, os.pardir))
        path = os.path.join(parent_dir, "config.ini")

    if not os.path.exists(path):
        raise FileNotFoundError(f"Configuration file not found at {path}")

    config.read(path)

    @staticmethod
    def get(section: str, key: str):
        """
        Retrieve the value of a configuration key from the specified section.

        Args:
            section (str): The section name in the configuration file.
            key (str): The key name in the specified section.

        Returns:
            str: The value associated with the specified key in the specified section.
        """
        return Config.config.get(section, key)

    @staticmethod
    def set(section: str, key: str, value: str):
        """
        Sets the value of a key in the specified section of the configuration file.

        Args:
            section (str): The section in the configuration file.
            key (str): The key to set the value for.
            value (str): The value to set for the key.
        """
        Config.config.set(section, key, value)
        with open("config.ini", "w") as configfile:
            Config.config.write(configfile)

    @staticmethod
    def get_items_from_section(section: str):
        """
        Retrieves all items from the specified section in the configuration.

        Args:
            section (str): The name of the section in the configuration.

        Returns:
            list: A list of tuples containing the items from the specified section.
        """
        return Config.config.items(section)

    @staticmethod
    def get_values_from_section(section: str):
        """
        Retrieves all values from the specified section in the configuration.

        Args:
            section (str): The name of the section in the configuration.

        Returns:
            list: A list of values from the specified section.
        """
        return [value for key, value in Config.config.items(section)]
