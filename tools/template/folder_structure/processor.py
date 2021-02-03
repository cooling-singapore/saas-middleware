import json
import os


def function(task_descriptor: dict, working_directory: str, status_logger):
    """
    This function takes an integer and multiplies it by 2
    """

    a_path = os.path.join(working_directory, 'a')
    with open(a_path, 'r') as f:
        a = json.load(f)

    b = int(a) * 2

    b_path = os.path.join(working_directory, 'b')
    with open(b_path, 'w') as f:
        f.write(f"\"{b}\"")

    return True
