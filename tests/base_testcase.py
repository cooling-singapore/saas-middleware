import os
import subprocess
import time
import logging

from multiprocessing import Lock

from saas.keystore.assets.credentials import SMTPCredentialsAsset, SSHCredentialsAsset, GithubCredentialsAsset
from saas.keystore.keystore import Keystore
from saas.node import Node
from saas.helpers import get_timestamp_now, read_json_from_file

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
            node.shutdown()

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

    def create_keystores(self, n):
        keystores = []
        for i in range(n):
            keystores.append(
                Keystore.create(self.wd_path, f"keystore_{i}", f"no-email-provided", f"password_{i}")
            )

        return keystores

    def create_nodes(self, n, offset=0, use_credentials=True, perform_join=True, enable_rest=False):
        nodes = []
        for i in range(n):
            nodes.append(self.get_node(f"node_{i+offset}", use_credentials=use_credentials, enable_rest=enable_rest))

            if perform_join and i > 0:
                nodes[i].join_network(nodes[0].p2p.address())
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

    # def has_ssh_credentials(self):
    #     path = 'credentials.json'
    #     if os.path.isfile(path):
    #         credentials = read_json_from_file('credentials.json')
    #         return 'ssh_auth' in credentials
    #     else:
    #         return False

    def get_node(self, name, use_credentials=True, enable_rest=False, use_ssh_profile=None):
        if name in self.nodes:
            return self.nodes[name]

        else:
            p2p_address = self.generate_p2p_address()
            rest_address = self.generate_rest_address()

            storage_path = os.path.join(self.wd_path, name)
            subprocess.check_output(['mkdir', '-p', storage_path])

            ssh_profile = None
            if use_credentials:
                credentials = read_json_from_file('credentials.json')
                keystore = Keystore.create(storage_path, name, credentials['email'], 'password')

                # do we have SMTP credentials?
                if 'smtp-credentials' in credentials:
                    smtp_cred = SMTPCredentialsAsset.create('smtp-credentials')
                    smtp_cred.update(credentials['email'],
                                     credentials['smtp-credentials']['server'],
                                     credentials['smtp-credentials']['login'],
                                     credentials['smtp-credentials']['password'])
                    keystore.update_asset(smtp_cred)

                # do we have SSH credentials?
                if 'ssh-credentials' in credentials:
                    ssh_cred = SSHCredentialsAsset.create('ssh-credentials')
                    for item in credentials['ssh-credentials']:
                        ssh_cred.update(item['name'], item['host'], item['login'], key_path=item['key_path'])
                    keystore.update_asset(ssh_cred)

                    # get the specific SSH profile to be used for this node (if any)
                    if use_ssh_profile:
                        ssh_profile = ssh_cred.get(use_ssh_profile)
                        if not ssh_profile:
                            return None

                # do we have Github credentials?
                if 'github-credentials' in credentials:
                    github_cred = GithubCredentialsAsset.create('github-credentials')
                    for item in credentials['github-credentials']:
                        github_cred.update(item['repository'], item['login'], item['personal_access_token'])
                    keystore.update_asset(github_cred)

            else:
                keystore = Keystore.create(storage_path, name, f"no-email-provided", 'password')

            # ssh_auth = None
            # if use_credentials:
            #     credentials = read_json_from_file('credentials.json')
            #     keystore = Keystore.load(credentials['path'], credentials['keystore_id'], credentials['password'])
            #     logger.info(f"creating node '{name}' at p2p={p2p_address} rest={rest_address} datastore={storage_path} "
            #                 f"using existing keystore (id={keystore.identity().id()})")
            #
            #     if use_ssh_auth and 'ssh_auth' in credentials:
            #         ssh_auth = credentials['ssh_auth']
            # else:
            #     logger.info(f"creating node '{name}' at p2p={p2p_address} rest={rest_address} datastore={storage_path} "
            #                 f"using new (fake) keystore")
            #     keystore = Keystore.create(storage_path, name, f"{name}@somewhere.com", 'password')

            # create node and startup services
            node = Node(keystore, storage_path)
            node.startup(p2p_address)
            node.start_dor_service()
            node.start_rti_service(ssh_profile=ssh_profile)
            if enable_rest:
                node.start_rest_service(rest_address)

            self.nodes[name] = node
            return node
