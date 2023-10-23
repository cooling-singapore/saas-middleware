import json
import logging
import os
import sys
import time

logger = logging.getLogger('example-processor-2')


def function(working_directory):
    print("trigger:progress:0")

    a_path = os.path.join(working_directory, 'a')
    with open(a_path, 'r') as f:
        a = json.load(f)
        a = a['v']
    print(f"a={a}")
    print("trigger:progress:10")
    sys.stdout.flush()

    b_path = os.path.join(working_directory, 'b')
    with open(b_path, 'r') as f:
        b = json.load(f)
        b = b['v']
    print(f"b={b}")
    print("trigger:progress:20")
    sys.stdout.flush()

    # calculate the result
    c = {
        'v': a + b
    }
    print(f"c={c}")
    print("trigger:progress:30")
    sys.stdout.flush()

    # simply wait for a while...
    parameters_path = os.path.join(working_directory, 'parameters')
    with open(parameters_path, 'r') as f:
        parameters = json.load(f)
        delay = parameters['delay']
        time.sleep(delay)

    c_path = os.path.join(working_directory, 'c')
    with open(c_path, 'w') as f:
        json.dump(c, f, indent=4, sort_keys=True)
    print("trigger:progress:90")
    print("trigger:output:c")
    sys.stdout.flush()

    print("trigger:progress:100")
    sys.stdout.flush()


if __name__ == '__main__':
    function(sys.argv[1])
