import os
import shutil
import time

from multiprocessing import Lock

from saas.core.exceptions import SaaSRuntimeException
from saas.core.helpers import get_timestamp_now, read_json_from_file, validate_json
from saas.core.keystore import Keystore
from saas.core.logging import Logging
from saas.core.schemas import SSHCredentials, GithubCredentials
from saas.node import Node

logger = Logging.get('tests.base_testcase')


def update_keystore_from_credentials(keystore: Keystore, credentials_path: str = None) -> None:
    """
    Updates a keystore with credentials loaded from credentials file. This is a convenience function useful for
    testing purposes. A valid example content may look something like this:
    {
        "name": "John Doe",
        "email": "john.doe@internet.com",
        "ssh-credentials": [
            {
            "name": "my-remote-machine-A",
            "login": "johnd",
            "host": "10.8.0.1",
            "password": "super-secure-password-123"
            },
            {
            "name": "my-remote-machine-B",
            "login": "johnd",
            "host": "10.8.0.2",
            "key_path": "/home/johndoe/machine-b-key"
            }
        ],
        "github-credentials": [
            {
                "repository": "https://github.com/my-repo",
                "login": "JohnDoe",
                "personal_access_token": "ghp_xyz..."
            }
        ]
    }

    For SSH credentials note that you can either indicate a password or a path to a key file.

    :param keystore: the keystore that is to be updated
    :param credentials_path: the optional path to the credentials file (default is $HOME/.saas-credentials.json)
    :return:
    """

    credentials_schema = {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'email': {'type': 'string'},
            'ssh-credentials': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'name': {'type': 'string'},
                        'login': {'type': 'string'},
                        'host': {'type': 'string'},
                        'password': {'type': 'string'},
                        'key_path': {'type': 'string'}
                    },
                    'required': ['name', 'login', 'host']
                }
            },
            'github-credentials': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'repository': {'type': 'string'},
                        'login': {'type': 'string'},
                        'personal_access_token': {'type': 'string'}
                    },
                    'required': ['repository', 'login', 'personal_access_token']
                }
            }
        }
    }

    # load the credentials and validate
    path = credentials_path if credentials_path else os.path.join(os.environ['HOME'], '.saas-credentials.json')
    credentials = read_json_from_file(path)
    if not validate_json(content=credentials, schema=credentials_schema):
        raise SaaSRuntimeException("JSON validation failed", details={
            'instance': credentials,
            'schema': credentials_schema
        })

    # update profile (if applicable)
    keystore.update_profile(name=credentials['name'] if 'name' in credentials else None,
                            email=credentials['email'] if 'email' in credentials else None)

    # do we have SSH credentials?
    if 'ssh-credentials' in credentials:
        for item in credentials['ssh-credentials']:
            # password or key path?
            if 'password' in item:
                keystore.ssh_credentials.update(item['name'],
                                                SSHCredentials(host=item['host'], login=item['login'],
                                                               key=item['password'], key_is_password=True))

            elif 'key_path' in item:
                # read the ssh key from file
                with open(item['key_path'], 'r') as f:
                    ssh_key = f.read()

                keystore.ssh_credentials.update(item['name'],
                                                SSHCredentials(host=item['host'], login=item['login'],
                                                               key=ssh_key, key_is_password=False))

            else:
                raise RuntimeError(f"Unexpected SSH credentials format: {item}")

        keystore.sync()

    # do we have Github credentials?
    if 'github-credentials' in credentials:
        for item in credentials['github-credentials']:
            keystore.github_credentials.update(item['repository'], GithubCredentials.parse_obj(item))
        keystore.sync()


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


class TestCaseBase:
    def __init__(self):
        self._mutex = Lock()
        self.wd_path = None
        self.host = None
        self.nodes = None
        self.proxies = None

    def initialise(self, wd_parent_path: str = None, snapshot_path: str = None, host: str = '127.0.0.1') -> None:
        # determine the working directory for testing
        if wd_parent_path:
            self.wd_path = os.path.join(wd_parent_path, 'testing', str(get_timestamp_now()))
        else:
            self.wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))

        # the testing directory gets deleted after the test is completed. if it already exists (unlikely) then
        # we abort in order not to end up deleting something that shouldn't be deleted.
        if os.path.exists(self.wd_path):
            raise Exception(f"path to working directory for testing '{self.wd_path}' already exists!")

        # do we have a snapshot path? if so, copy all the contents
        if snapshot_path:
            shutil.copytree(snapshot_path, self.wd_path)
        else:
            # create an enpty working directory
            os.makedirs(self.wd_path, exist_ok=True)

        self.host = host
        self.nodes = {}
        self.proxies = {}

    def cleanup(self, snapshot_path: str = None) -> None:
        for name in self.nodes:
            logger.info(f"stopping node '{name}'")
            node = self.nodes[name]
            node.shutdown(leave_network=False)

        # retain the working directory as snapshot?
        if snapshot_path:
            os.rename(self.wd_path, snapshot_path)
        else:
            shutil.rmtree(self.wd_path)

    def create_keystores(self, n: int, use_credentials: bool = False) -> list[Keystore]:
        keystores = []
        for i in range(n):
            keystore = Keystore.create(self.wd_path, f"keystore_{i}", f"no-email-provided", f"password_{i}")
            keystores.append(keystore)

            # update keystore credentials (if applicable)
            if use_credentials:
                update_keystore_from_credentials(keystore)

        return keystores

    def create_nodes(self, n: int, offset: int = 0, use_credentials: bool = True, perform_join: bool = True,
                     enable_rest: bool = False) -> list[Node]:
        nodes = []
        for i in range(n):
            nodes.append(self.get_node(f"node_{i+offset}", use_credentials=use_credentials, enable_rest=enable_rest))

            if perform_join and i > 0:
                nodes[i].join_network(nodes[0].p2p.address())
                time.sleep(2)

        return nodes

    def generate_random_file(self, filename: str, size: int) -> str:
        path = os.path.join(self.wd_path, filename)
        with open(path, 'wb') as f:
            f.write(os.urandom(int(size)))
        return path

    def generate_zero_file(self, filename: str, size: int) -> str:
        path = os.path.join(self.wd_path, filename)
        with open(path, 'wb') as f:
            f.write(b"\0" * int(size))
        return path

    def create_file_with_content(self, filename: str, content: str) -> str:
        path = os.path.join(self.wd_path, filename)
        with open(path, 'w') as f:
            f.write(content)
        return path

    def get_node(self, name: str, use_credentials: bool = True, enable_rest: bool = False,
                 use_dor: bool = True, use_rti: bool = True, retain_job_history: bool = True,
                 strict_deployment: bool = False, keep_track: bool = True, wd_path: str = None) -> Node:
        if keep_track and name in self.nodes:
            return self.nodes[name]

        else:
            p2p_address = PortMaster.generate_p2p_address(self.host)
            rest_address = PortMaster.generate_rest_address(self.host)

            storage_path = os.path.join(wd_path if wd_path else self.wd_path, name)
            os.makedirs(storage_path, exist_ok=True)

            if use_credentials:
                keystore = Keystore.create(storage_path, name, f"no-email-provided", 'password')
                update_keystore_from_credentials(keystore)

            else:
                keystore = Keystore.create(storage_path, name, f"no-email-provided", 'password')

            # create node and startup services
            node = Node(keystore, storage_path)
            node.startup(p2p_address, enable_dor=use_dor, enable_rti=use_rti,
                         rest_address=rest_address if enable_rest else None,
                         retain_job_history=retain_job_history if use_rti else None,
                         strict_deployment=strict_deployment if use_rti else None)

            if keep_track:
                self.nodes[name] = node

            return node

    def resume_node(self, name: str, enable_rest: bool = False, use_dor: bool = True, use_rti: bool = True,
                    retain_job_history: bool = True, strict_deployment: bool = False) -> Node:
        if name in self.nodes:
            return self.nodes[name]

        else:
            p2p_address = PortMaster.generate_p2p_address(self.host)
            rest_address = PortMaster.generate_rest_address(self.host)

            storage_path = os.path.join(self.wd_path, name)
            if not os.path.isdir(storage_path):
                raise RuntimeError(f"no storage path found to resume node at {storage_path}")

            # infer the keystore id
            keystore = None
            for filename in os.listdir(storage_path):
                if filename.endswith('.json') and len(filename) == 69:
                    keystore = Keystore.load(os.path.join(storage_path, filename), 'password')
                    break

            # create node and startup services
            node = Node(keystore, storage_path)
            node.startup(p2p_address, enable_dor=use_dor, enable_rti=use_rti,
                         rest_address=rest_address if enable_rest else None,
                         retain_job_history=retain_job_history if use_rti else None,
                         strict_deployment=strict_deployment if use_rti else None)

            self.nodes[name] = node
            return node
