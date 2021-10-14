import time
import json
import subprocess
import random
import string

from getpass import getpass
from typing import IO, AnyStr, TextIO, Union

import jsonschema

import saas.exceptions as exceptions
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


def read_json_from_file(path: str, schema: dict = None) -> dict:
    with open(path, 'r') as f:
        content = json.load(f)

        # do we have a schema to validate?
        if schema is not None:
            jsonschema.validate(instance=content, schema=schema)

        return content


def write_json_to_file(content: dict, path: str, schema: dict = None, indent: int = 4, sort_keys: bool = False):
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


def run_command(command: list[str], cwd: str = None, suppress_exception: bool = False) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, capture_output=True)
    if not suppress_exception and result.returncode != 0:
        raise exceptions.RunCommandError({
            'command': command,
            'cwd': cwd,
            'result': result
        })
    return result


def parse_stream(pipe: IO[AnyStr], file: TextIO = None, triggers: dict = None) -> None:
    while True:
        # read the line, strip the '\n' and break if nothing left
        line = pipe.readline().rstrip()
        if not line:
            break

        # if we have a file
        if file is not None:
            file.write(line+'\n')
            file.flush()

        # parse the lines for this round
        if triggers is not None:
            for pattern, info in triggers.items():
                if pattern in line:
                    info['func'](line, info['context'])


def monitor_command(command: list[str], triggers: dict, cwd: str = None,
                    stdout_path: str = None, stderr_path: str = None) -> (list[str], list[str]):

    with open(stdout_path, 'x') as f_stdout:
        with open(stderr_path, 'x') as f_stderr:
            proc = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            while proc.poll() is None:
                parse_stream(proc.stdout, file=f_stdout, triggers=triggers)
                parse_stream(proc.stderr, file=f_stderr)

            proc.stdout.close()
            proc.stderr.close()


def create_symbolic_link(link_path: str, target_path: str, working_directory: str = None) -> None:
    run_command(['ln', '-sf', target_path, link_path], cwd=working_directory)


def scp_local_to_remote(local_path: str, remote_path: str, login: str, host: str, ssh_key_path: str) -> None:
    run_command(['scp', '-i', ssh_key_path, local_path, f"{login}@{host}:{remote_path}"])


def scp_remote_to_local(remote_path: str, local_path: str, login: str, host: str, ssh_key_path: str) -> None:
    run_command(['scp', '-i', ssh_key_path, f"{login}@{host}:{remote_path}", local_path])


def prompt(question: str, valid_answers: list = None, valid_range: (int, int) = None, hidden: bool = False,
           multi_selection: bool = False) -> Union[int, list[int]]:

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
