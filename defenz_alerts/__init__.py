"""
Defenz alerts
"""
import logging
import os
from configparser import ConfigParser
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from shutil import copyfile


APP_PATH = os.path.dirname(os.path.realpath(__file__))
LOGS_PATH = str(Path.home()) + '/defenz'
LOG_FILE = '/defenz_alerts.log'
LOGGER_NAME = 'defenz_alerts'


def config_logger():
    """
    Configs logger.
    """

    if not os.path.isdir(LOGS_PATH):
        os.mkdir(LOGS_PATH)

    timed_rotating_file_handler = \
        TimedRotatingFileHandler(LOGS_PATH + LOG_FILE, when='D')
    logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s',
                        level=logging.DEBUG,
                        handlers=[timed_rotating_file_handler])
    return logging.getLogger(LOGGER_NAME)


def load_config():
    """
    Loads config file
    """
    config_path = APP_PATH + '/config.ini'
    config = ConfigParser()

    if not Path(config_path).is_file():
        copyfile(APP_PATH + '/config.sample.ini', config_path)

    config.read(config_path)

    return config


LOGGER = config_logger()
CONFIG = load_config()
