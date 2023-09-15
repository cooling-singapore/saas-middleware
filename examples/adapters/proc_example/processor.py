import json
import logging
import os
import sys
import time

logger = logging.getLogger('example-processor')


def function(working_directory):
    print("trigger:progress:0")
    print("trigger:message:info:This is a message at the very beginning of the process.")

    a_path = os.path.join(working_directory, 'a')
    with open(a_path, 'r') as f:
        a = json.load(f)
        a = a['v']
    print(f"a={a}")
    print("trigger:progress:20")
    time.sleep(a)

    b_path = os.path.join(working_directory, 'b')
    with open(b_path, 'r') as f:
        b = json.load(f)
        b = b['v']
    print(f"b={b}")
    print("trigger:progress:40")
    time.sleep(b)

    c = {
        'v': a + b
    }
    print(f"c={c}")
    print("trigger:progress:60")
    print(f"trigger:message:info:a={a}")
    print(f"trigger:message:info:b={b}")
    print(f"trigger:message:info:c={c}")
    time.sleep(0.2)

    c_path = os.path.join(working_directory, 'c')
    with open(c_path, 'w') as f:
        json.dump(c, f, indent=4, sort_keys=True)
    print("trigger:progress:80")
    print("trigger:output:c")
    time.sleep(0.2)

    print("trigger:progress:100")
    print("trigger:message:info:...and we are done!")


if __name__ == '__main__':
    function(sys.argv[1])
