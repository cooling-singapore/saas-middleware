import os
import subprocess
from threading import Lock

from saas.core.exceptions import SaaSRuntimeException
from saas.core.helpers import get_timestamp_now


class PortMaster:
    _mutex = Lock()
    _next_p2p = {}
    _next_rest = {}

    @classmethod
    def generate_p2p_address(cls, host: str = '127.0.0.1') -> (str, int):
        with cls._mutex:
            if host not in cls._next_p2p:
                cls._next_p2p[host] = 4100

            address = (host, cls._next_p2p[host])
            cls._next_p2p[host] += 1
            return address

    @classmethod
    def generate_rest_address(cls, host: str = '127.0.0.1') -> (str, int):
        with cls._mutex:
            if host not in cls._next_rest:
                cls._next_rest[host] = 5100

            address = (host, cls._next_rest[host])
            cls._next_rest[host] += 1
            return address


def create_wd(wd_parent_path: str = None) -> str:
    # determine the working directory path
    if wd_parent_path:
        wd_path = os.path.join(wd_parent_path, 'testing', str(get_timestamp_now()))
    else:
        wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))

    # the testing directory gets deleted after the test is completed. if it already exists (unlikely) then
    # we abort in order not to end up deleting something that shouldn't be deleted.
    if os.path.exists(wd_path):
        raise SaaSRuntimeException(f"path to working directory for testing '{wd_path}' already exists!")

    # create an empty working directory
    os.makedirs(wd_path, exist_ok=True)

    return wd_path


def create_rnd_hex_string(n: int) -> str:
    result = subprocess.run(['openssl', 'rand', '-hex', str(n)], capture_output=True)
    result = result.stdout.decode('utf-8')
    result = result.strip()
    return result


def generate_random_file(path: str, size: int) -> str:
    with open(path, 'wb') as f:
        f.write(os.urandom(int(size)))
    return path
