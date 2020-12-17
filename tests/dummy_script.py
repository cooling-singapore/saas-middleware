import os
import sys
import time
import logging
import json
import subprocess
import importlib

from threading import Lock, Thread

logger = logging.getLogger('testing.dummy_adapter')

descriptor = {
    'name': 'dummy',
    'version': '20201014',
    'type': 'script',
    'input': [
        {
            'name': 'a',
            'data_type': 'integer',
            'data_format': 'json'
        },
        {
            'name': 'b',
            'data_type': 'integer',
            'data_format': 'json'
        }
    ],
    'output': [
        {
            'name': 'c',
            'data_type': 'integer',
            'data_format': 'json'
        }
    ]
}


def function(task_descriptor, working_directory, status_logger):
    logger.info("f({}, '{}')".format(task_descriptor, working_directory))

    try:
        a_path = os.path.join(working_directory, 'a')
        with open(a_path, 'r') as f:
            a = json.load(f)

        b_path = os.path.join(working_directory, 'b')
        with open(b_path, 'r') as f:
            b = json.load(f)

        c = int(a) + int(b)

        c_path = os.path.join(working_directory, 'c')
        with open(c_path, 'w') as f:
            f.write("\"{}\"".format(c))

        return True

    except Exception as e:
        logger.error("exception in function: {}".format(e))
        return False

