import os
import subprocess
import time
import logging

from multiprocessing import Lock

from saas.keystore.keystore import Keystore
from saas.node import Node
from saas.registry.protocol import RegistryP2PProtocol
from saas.utilities.general_helpers import get_timestamp_now

logger = logging.getLogger('tests.base_testcase')


class TestCaseBase:
    def __init__(self):
        self._mutex = Lock()

        self.wd_path = None
        self.host = None
        self.nodes = None
        self.proxies = None
        self._next_p2p_port = None
        self._next_rest_port = None

    def initialise(self, wd_parent_path=None, host='127.0.0.1', next_p2p_port=4000, next_rest_port=5000):
        # determine the working directory for testing
        if wd_parent_path:
            self.wd_path = os.path.join(wd_parent_path, 'testing', str(get_timestamp_now()))
        else:
            self.wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))

        # the testing directory gets deleted after the test is completed. if it already exists (unlikely) then
        # we abort in order not to end up deleting something that shouldn't be deleted.
        if os.path.exists(self.wd_path):
            raise Exception(f"path to working directory for testing '{self.wd_path}' already exists!")

        # create working directory
        subprocess.check_output(['mkdir', '-p', self.wd_path])

        self.host = host
        self.nodes = {}
        self.proxies = {}

        self._next_p2p_port = next_p2p_port
        self._next_rest_port = next_rest_port

    def cleanup(self):
        for name in self.nodes:
            logger.info(f"stopping node '{name}'")
            node = self.nodes[name]
            node.stop_services()

        # delete working directory
        subprocess.check_output(['rm', '-rf', self.wd_path])

    def generate_p2p_address(self):
        with self._mutex:
            address = (self.host, self._next_p2p_port)
            self._next_p2p_port += 1
            return address

    def generate_rest_address(self):
        with self._mutex:
            address = (self.host, self._next_rest_port)
            self._next_rest_port += 1
            return address

    def create_nodes(self, n, perform_join=True):
        nodes = []
        for i in range(n):
            nodes.append(self.get_node(f"node_{i}"))

            if perform_join and i > 0:
                # send a join message to node0
                protocol = RegistryP2PProtocol(nodes[i])
                protocol.send_join(nodes[0].p2p.address())
                time.sleep(2)

        return nodes

    def generate_random_file(self, filename, size):
        path = os.path.join(self.wd_path, filename)
        with open(path, 'wb') as f:
            f.write(os.urandom(int(size)))
        return path

    def generate_zero_file(self, filename, size):
        path = os.path.join(self.wd_path, filename)
        with open(path, 'wb') as f:
            f.write(b"\0" * int(size))
        return path

    def create_file_with_content(self, filename, content):
        path = os.path.join(self.wd_path, filename)
        with open(path, 'w') as f:
            f.write(content)
        return path

    def get_node(self, name, enable_rest=False):
        if name in self.nodes:
            return self.nodes[name]

        else:
            p2p_address = self.generate_p2p_address()
            rest_address = self.generate_rest_address()

            storage_path = os.path.join(self.wd_path, name)
            subprocess.check_output(['mkdir', '-p', storage_path])

            logger.info(f"creating node '{name}' at p2p={p2p_address} rest={rest_address} datastore={storage_path}")

            keystore = Keystore.create(storage_path, name, f"{name}@somewhere.com", 'password')
            node = Node(keystore, storage_path)
            node.start_p2p_service(p2p_address)
            if enable_rest:
                node.start_rest_service(rest_address)

            node.start_nodedb_service()
            node.start_registry_service()
            node.start_dor_service()
            node.start_rti_service()

            self.nodes[name] = node
            return node