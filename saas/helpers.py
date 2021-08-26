"""
Contains a number of helper functions and classes used throughout the SaaS Middleware.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import os
import shutil
import time
import logging
import json
import subprocess
import random
import string

from getpass import getpass

import jsonschema

logger = logging.getLogger('helpers')


def remove_path(path):
    """
    Removes a filesystem element (file or directory) including all its contents
    (in case of a directory)
    :param path:
    :return:
    """
    if os.path.isdir(path):
        shutil.rmtree(path)
    elif os.path.isfile(path):
        os.remove(path)


def get_timestamp_now():
    """
    Returns the current time in milliseconds since the beginning of the epoch
    :return: integer representing time in milliseconds
    """
    return int(round(time.time() * 1000))


def validate_json(content, schema):
    try:
        jsonschema.validate(instance=content, schema=schema)
        return True

    except jsonschema.exceptions.ValidationError:
        return False

    except jsonschema.exceptions.SchemaError:
        return False


def read_json_from_file(path, schema=None):
    with open(path, 'r') as f:
        content = json.load(f)

        # do we have a schema to validate?
        if schema is not None:
            jsonschema.validate(instance=content, schema=schema)

        return content


def write_json_to_file(content, path, schema=None, indent=4, sort_keys=False):
    with open(path, 'w') as f:
        json.dump(content, f, indent=indent, sort_keys=sort_keys)

        # do we have a schema to validate?
        if schema is not None:
            jsonschema.validate(instance=content, schema=schema)

        return content


def generate_random_string(length, characters=string.ascii_letters+string.digits):
    return ''.join(random.choice(characters) for c in range(length))


def object_to_ordered_list(obj):
    """
    Recursively sort any lists (and convert dictionaries to lists of (key, value) pairs so that they can be sorted)
    and return the result as a sorted list.
    Source: https://stackoverflow.com/questions/25851183/how-to-compare-two-json-objects-with-the-same-elements-in-a-different-order-equa
    :param obj: a dictionary
    :return:
    """
    if isinstance(obj, dict):
        return sorted((k, object_to_ordered_list(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(object_to_ordered_list(x) for x in obj)
    else:
        return obj


def get_address_from_string(address_string):
    temp = address_string.split(":")
    return temp[0], int(temp[1])


def all_in_dict(required, dictionary):
    return all(r in dictionary for r in required)


def create_symbolic_link(source_path, destination_path):
    if os.path.exists(destination_path):
        subprocess.check_output(['rm', destination_path])
    subprocess.check_output(['ln', '-s', source_path, destination_path])


def prompt(question, valid_answers=None, valid_range=None, hidden=False, multi_selection=False):
    f = getpass if hidden else input
    while True:
        if valid_range:
            answer = f(f"{question} ({valid_range[0]}:{valid_range[1]}) ")
            answer.strip()

            if multi_selection:
                result = []
                for item in answer.split(","):
                    if item.isdigit():
                        item = int(item)
                        if valid_range[0] <= item <= valid_range[1]:
                            result.append(item)

                if len(result) > 0:
                    return result

            else:
                if answer.isdigit():
                    answer = int(answer)
                    if valid_range[0] <= answer <= valid_range[1]:
                        return answer

        elif valid_answers:
            joined_answers = "|".join(valid_answers)
            answer = f(f"{question} ({joined_answers}) ")

            if answer in valid_answers:
                return answer

        else:
            answer = f(f"{question} ")
            return answer
