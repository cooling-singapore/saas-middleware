import os
import shutil
import time

from multiprocessing import Lock

from saascore.keystore.keystore import Keystore, update_keystore_from_credentials
from saascore.log import Logging

from saas.node import Node
from saascore.helpers import get_timestamp_now

logger = Logging.get('tests.base_testcase')


class TestCaseBase:
    def __init__(self):
        self._mutex = Lock()

        self.wd_path = None
        self.host = None
        self.nodes = None
        self.proxies = None
        self._next_p2p_port = None
        self._next_rest_port = None

    def initialise(self, wd_parent_path: str = None, snapshot_path: str = None, host: str = '127.0.0.1',
                   next_p2p_port: int = 4000, next_rest_port: int = 5000) -> None:
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

        self._next_p2p_port = next_p2p_port
        self._next_rest_port = next_rest_port

    def cleanup(self, snapshot_path: str = None) -> None:
        for name in self.nodes:
            logger.info(f"stopping node '{name}'")
            node = self.nodes[name]
            node.shutdown()

        # retain the working directory as snapshot?
        if snapshot_path:
            os.rename(self.wd_path, snapshot_path)
        else:
            shutil.rmtree(self.wd_path)

    def generate_p2p_address(self) -> (str, int):
        with self._mutex:
            address = (self.host, self._next_p2p_port)
            self._next_p2p_port += 1
            return address

    def generate_rest_address(self) -> (str, int):
        with self._mutex:
            address = (self.host, self._next_rest_port)
            self._next_rest_port += 1
            return address

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
                 use_dor: bool = True, use_rti: bool = True, retain_job_history: bool = True) -> Node:
        if name in self.nodes:
            return self.nodes[name]

        else:
            p2p_address = self.generate_p2p_address()
            rest_address = self.generate_rest_address()

            storage_path = os.path.join(self.wd_path, name)
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
                         retain_job_history=retain_job_history)

            self.nodes[name] = node
            return node

    def resume_node(self, name: str, enable_rest: bool = False, use_dor: bool = True, use_rti: bool = True,
                    retain_job_history: bool = True) -> Node:
        if name in self.nodes:
            return self.nodes[name]

        else:
            p2p_address = self.generate_p2p_address()
            rest_address = self.generate_rest_address()

            storage_path = os.path.join(self.wd_path, name)
            if not os.path.isdir(storage_path):
                raise RuntimeError(f"no storage path found to resume node at {storage_path}")

            # infer the keystore id
            keystore_id = None
            for filename in os.listdir(storage_path):
                if filename.endswith('.json') and len(filename) == 69:
                    keystore_id = filename.split('.')[0]
                    break

            keystore = Keystore.load(storage_path, keystore_id, 'password')

            # create node and startup services
            node = Node(keystore, storage_path)
            node.startup(p2p_address, enable_dor=use_dor, enable_rti=use_rti,
                         rest_address=rest_address if enable_rest else None,
                         retain_job_history=retain_job_history)

            self.nodes[name] = node
            return node
