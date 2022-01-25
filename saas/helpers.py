import time
import json
import random
import string

from typing import Union

import jsonschema

from saas.logging import Logging

logger = Logging.get('helpers')


def get_timestamp_now() -> int:
    """
    Returns the current time in milliseconds since the beginning of the epoch
    :return: integer representing time in milliseconds
    """
    return int(round(time.time() * 1000))


def validate_json(content: dict, schema: dict) -> bool:
    try:
        jsonschema.validate(instance=content, schema=schema)
        return True

    except jsonschema.exceptions.ValidationError:
        return False

    except jsonschema.exceptions.SchemaError:
        return False


def read_json_from_file(path: str, schema: dict = None) -> Union[list, dict]:
    with open(path, 'r') as f:
        content = json.load(f)

        # do we have a schema to validate?
        if schema is not None:
            jsonschema.validate(instance=content, schema=schema)

        return content


def write_json_to_file(content: Union[list, dict], path: str, schema: dict = None, indent: int = 4,
                       sort_keys: bool = False):
    with open(path, 'w') as f:
        json.dump(content, f, indent=indent, sort_keys=sort_keys)

        # do we have a schema to validate?
        if schema is not None:
            jsonschema.validate(instance=content, schema=schema)

        return content


def generate_random_string(length: int, characters: str = string.ascii_letters+string.digits):
    return ''.join(random.choice(characters) for c in range(length))


def object_to_ordered_list(obj: Union[dict, list]) -> Union[dict, list]:
    """
    Recursively sort any lists (and convert dictionaries to lists of (key, value) pairs so that they can be sorted)
    and return the result as a sorted list.
    Source: https://stackoverflow.com/questions/25851183/how-to-compare-two-json-objects-with-the-same-elements-in-a-different-order-equa
    :param obj: a dictionary or list
    :return:
    """
    if isinstance(obj, dict):
        return sorted((k, object_to_ordered_list(v)) for k, v in obj.items())
    elif isinstance(obj, list):
        return sorted(object_to_ordered_list(x) for x in obj)
    else:
        return obj

