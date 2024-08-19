

from configparser import ConfigParser

class Config:
    config = ConfigParser()
    config.read("config.ini")

    @staticmethod
    def get(section, key):
        return Config.config.get(section, key)

    @staticmethod
    def set(section, key, value):
        Config.config.set(section, key, value)
        with open('config.ini', 'w') as configfile:
            Config.config.write(configfile)
