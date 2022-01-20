import os
import time
import json
import subprocess
import random
import string

from typing import IO, AnyStr, TextIO, Union

import jsonschema

import saas.keystore.assets.credentials as credentials
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


def parse_stream(name: str, pipe: IO[AnyStr], file: TextIO = None, triggers: dict = None) -> None:
    while True:
        # read the line, strip the '\n' and break if nothing left
        line = pipe.readline().rstrip()
        logger.debug(f"parse_stream[{name}]\t{line}")
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


def monitor_command(command: str, triggers: dict, ssh_credentials: credentials.SSHCredentials = None, cwd: str = None,
                    stdout_path: str = None, stderr_path: str = None) -> (list[str], list[str]):

    # wrap the command depending on whether it is to be executed locally or remote (if ssh credentials provided)
    if ssh_credentials:
        a = ['sshpass', '-p', ssh_credentials.key] if ssh_credentials.key_is_password else []
        b = ['-i', ssh_credentials.key] if not ssh_credentials.key_is_password else []
        c = ['-oHostKeyAlgorithms=+ssh-rsa']

        wrapped_command = [*a, 'ssh', *b, *c, f"{ssh_credentials.login}@{ssh_credentials.host}", command]

    else:
        wrapped_command = ['bash', '-c', command]

    with open(stdout_path, 'x') as f_stdout:
        with open(stderr_path, 'x') as f_stderr:
            proc = subprocess.Popen(wrapped_command, cwd=cwd, stdout=subprocess.PIPE, stderr=f_stderr,
                                    universal_newlines=True)
            while proc.poll() is None:
                parse_stream('stdout', proc.stdout, file=f_stdout, triggers=triggers)

            logger.debug(f"process is done: stdout={stdout_path} stderr={stderr_path}")
            proc.stdout.close()


def run_command(command: str, ssh_credentials: credentials.SSHCredentials = None,
                suppress_exception: bool = False) -> subprocess.CompletedProcess:

    # wrap the command depending on whether it is to be executed locally or remote (if ssh credentials provided)
    if ssh_credentials:
        a = ['sshpass', '-p', ssh_credentials.key] if ssh_credentials.key_is_password else []
        b = ['-i', ssh_credentials.key] if not ssh_credentials.key_is_password else []
        c = ['-oHostKeyAlgorithms=+ssh-rsa']

        wrapped_command = [*a, 'ssh', *b, *c, f"{ssh_credentials.login}@{ssh_credentials.host}", command]

    else:
        wrapped_command = ['bash', '-c', command]

    # execute command
    result = subprocess.run(wrapped_command, capture_output=True)
    if not suppress_exception and result.returncode != 0:
        raise exceptions.RunCommandError({
            'wrapped_command': wrapped_command,
            'ssh_credentials': ssh_credentials.record if ssh_credentials else None,
            'result': result
        })
    return result


def create_symbolic_link(link_path: str, target_path: str, working_directory: str = None) -> None:
    if working_directory:
        link_path = os.path.join(working_directory, link_path)
        target_path = os.path.join(working_directory, target_path)
    run_command(f"ln -sf {target_path} {link_path}")


def scp_local_to_remote(local_path: str, remote_path: str, ssh_credentials: credentials.SSHCredentials) -> None:
    # generate the wrapped command
    a = ['sshpass', '-p', ssh_credentials.key] if ssh_credentials.key_is_password else []
    b = ['-i', ssh_credentials.key] if not ssh_credentials.key_is_password else []
    c = ['-oHostKeyAlgorithms=+ssh-rsa']
    wrapped_command = [*a, 'scp', *b, *c, local_path, f"{ssh_credentials.login}@{ssh_credentials.host}:{remote_path}"]

    # execute command
    result = subprocess.run(wrapped_command, capture_output=True)
    if result.returncode != 0:
        raise exceptions.RunCommandError({
            'wrapped_command': wrapped_command,
            'ssh_credentials': ssh_credentials.record,
            'result': result
        })


def scp_remote_to_local(remote_path: str, local_path: str, ssh_credentials: credentials.SSHCredentials) -> None:
    # generate the wrapped command
    a = ['sshpass', '-p', ssh_credentials.key] if ssh_credentials.key_is_password else []
    b = ['-i', ssh_credentials.key] if not ssh_credentials.key_is_password else []
    c = ['-oHostKeyAlgorithms=+ssh-rsa']
    wrapped_command = [*a, 'scp', *b, *c, f"{ssh_credentials.login}@{ssh_credentials.host}:{remote_path}", local_path]

    # execute command
    result = subprocess.run(wrapped_command, capture_output=True)
    if result.returncode != 0:
        raise exceptions.RunCommandError({
            'wrapped_command': wrapped_command,
            'ssh_credentials': ssh_credentials.record,
            'result': result
        })
