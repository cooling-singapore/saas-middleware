import os
import sys
import time
import logging
import json
import subprocess
import importlib

from saas.utilities.general_helpers import dump_json_to_file

from threading import Lock, Thread

logger = logging.getLogger('testing.dummy_adapter')

descriptor = {
    'name': 'dummy',
    'version': '20201014',
    'type': 'script',
    'input': [
        {
            'name': 'a',
            'data_type': 'JSONObject',
            'data_format': 'json'
        },
        {
            'name': 'b',
            'data_type': 'JSONObject',
            'data_format': 'json'
        }
    ],
    'output': [
        {
            'name': 'c',
            'data_type': 'JSONObject',
            'data_format': 'json'
        }
    ]
}


def function(task_descriptor, working_directory, status_logger):
    logger.info(f"f({task_descriptor}, '{working_directory}')")

    try:
        a_path = os.path.join(working_directory, 'a')
        with open(a_path, 'r') as f:
            a = json.load(f)
            a = a['a']

        b_path = os.path.join(working_directory, 'b')
        with open(b_path, 'r') as f:
            b = json.load(f)
            b = b['b']

        print(f"a={a}")
        print(f"b={b}")
        c = {
            'c': a + b
        }
        print(f"c={c}")

        c_path = os.path.join(working_directory, 'c')
        dump_json_to_file(c, c_path)

        return True

    except Exception as e:
        logger.error(f"exception in function: {e}")
        return False

