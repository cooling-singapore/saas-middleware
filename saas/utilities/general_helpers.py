"""
Contains a number of helper functions and classes used throughout the SaaS Middleware.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import time
import logging
import json

logger = logging.getLogger('Utilities.general_helpers')


def get_timestamp_now():
    """
    Returns the current time in milliseconds since the beginning of the epoch
    :return: integer representing time in milliseconds
    """
    return int(round(time.time() * 1000))


def dump_json_to_file(json_input, destination_path):
    """
    Write a given JSON input to a file.
    :param json_input: the JSON input
    :param destination_path: the path of the destination file
    :return: None
    """
    with open(destination_path, 'w') as f:
        json.dump(json_input, f, indent=4, sort_keys=True)
