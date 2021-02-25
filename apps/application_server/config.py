import json
import logging
import os
import tempfile

logger = logging.getLogger('AppServerConfig')


class Config:
    @classmethod
    def get_config_attr(cls):
        return [attr for attr in dir(cls) if not callable(getattr(cls, attr)) and not attr.startswith("__")]


class DefaultConfig(Config):
    DATASTORE = os.environ.get('DATASTORE')
    SECRET_KEY = os.environ.get('SECRET_KEY')


class TestConfig(DefaultConfig):
    DATASTORE = tempfile.mkdtemp()
    SECRET_KEY = 'testing'


class UserConfig(DefaultConfig):
    @classmethod
    def read(cls, config_path: str):
        """
        Reads config file and replaces attributes with valid properties

        :param config_path: Path to config file
        :return: None
        """
        with open(config_path) as json_file:
            # load configuration
            logger.info(f"applying configuration from file: '{config_path}'")
            config_file = json.load(json_file)

        for key, value in config_file.items():
            if hasattr(cls, key):
                setattr(cls, key, value)
            else:
                logger.warning(f'`{key}` is not a valid config property')
