import json
import logging
import os

logger = logging.getLogger('testing.dummy_adapter')


def function(task_descriptor, working_directory, status_logger):
    logger.info(f"f({task_descriptor}, '{working_directory}')")

    try:
        a_path = os.path.join(working_directory, 'a')
        with open(a_path, 'r') as f:
            a = json.load(f)
            a = a['v']

        b_path = os.path.join(working_directory, 'b')
        with open(b_path, 'r') as f:
            b = json.load(f)
            b = b['v']

        print(f"a={a}")
        print(f"b={b}")
        c = {
            'v': a + b
        }
        print(f"c={c}")

        c_path = os.path.join(working_directory, 'c')

        with open(c_path, 'w') as f:
            json.dump(c, f, indent=4, sort_keys=True)

        return True

    except Exception as e:
        logger.error(f"exception in function: {e}")
        return False

