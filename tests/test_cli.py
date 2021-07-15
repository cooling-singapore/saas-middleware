import filecmp
import json
import os
import logging
import time
import unittest

from saas.cryptography.helpers import decrypt_file
from saas.dor.blueprint import DORProxy
from saas.helpers import dump_json_to_file, get_timestamp_now, prompt
from saas.nodedb.blueprint import NodeDBProxy
from saas.rti.blueprint import RTIProxy
from saas_cli import parse_args, load_keystore, exec_cmd_service
from tests.base_testcase import TestCaseBase

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class CLITestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        self.password = 'pwd!@#'

    def tearDown(self):
        self.cleanup()

    def add_test_processor_to_dor(self, owner, dor_proxy):
        git_proc_pointer_path = os.path.join(self.wd_path, "git_proc_pointer.json")
        dump_json_to_file({
            'source': 'https://github.com/cooling-singapore/saas-processor-template',
            'commit_id': '09d00d6',
            'path': 'processor_dummy',
            'descriptor': {
                "name": "test",
                "input": [
                    {
                        "name": "a",
                        "data_type": "JSONObject",
                        "data_format": "json"
                    },
                    {
                        "name": "b",
                        "data_type": "JSONObject",
                        "data_format": "json"
                    }
                ],
                "output": [
                    {
                        "name": "c",
                        "data_type": "JSONObject",
                        "data_format": "json"
                    }
                ]
            }
        }, git_proc_pointer_path)

        data_type = 'Git-Processor-Pointer'
        data_format = 'json'
        created_t = get_timestamp_now()
        created_by = 'test_user'

        proc_id, _ = dor_proxy.add_data_object(git_proc_pointer_path, owner,
                                               False, False, None,
                                               data_type, data_format, created_by, created_t)

        return proc_id

    def create_keystore_and_make_identity_known(self, db_proxy, n=1, name=None, email=None):
        result_keystore = []
        result_identity = []

        for i in range(n):
            # create identity
            args = [
                '--keystore', self.wd_path,
                '--password', self.password,
                'identity', 'create',
                '--name', name if name is not None else f"name_{i}",
                '--email', email if email is not None else f"email_{i}@internet.com"
            ]
            keystore_id = parse_args(args)
            assert(keystore_id is not None)

            # load keystore
            args = {
                'keystore': self.wd_path,
                'password': self.password,
                'keystore-id': keystore_id
            }
            keystore = load_keystore(args)

            # make identity known
            signature = keystore.update()
            identity = keystore.identity()
            db_proxy.update_identity(identity, signature)

            result_keystore.append(keystore)
            result_identity.append(identity)

        if n == 1:
            return result_keystore[0], result_identity[0]

        else:
            return result_keystore, result_identity

    def create_node_and_proxies(self):
        node = self.get_node('node', enable_rest=True)
        dor_proxy = DORProxy(node.rest.address())
        rti_proxy = RTIProxy(node.rest.address())
        db_proxy = NodeDBProxy(node.rest.address())
        return node, dor_proxy, rti_proxy, db_proxy

    def test_cmd_identity(self):
        args = {
            'keystore': self.wd_path,
            'password': self.password,
            'keystore-id': None
        }
        keystore_id = load_keystore(args)
        assert(keystore_id is None)

        args = [
            '--keystore', self.wd_path,
            '--password', self.password,
            'identity', 'create',
            '--name', 'name', '--email', 'email@internet.com'
        ]
        keystore_id = parse_args(args)
        assert(keystore_id is not None)

        master_path = os.path.join(self.wd_path, f"{keystore_id}.master")
        keystore_path = os.path.join(self.wd_path, f"{keystore_id}.keystore")
        assert(os.path.isfile(master_path))
        assert(os.path.isfile(keystore_path))

        args = {
            'keystore': self.wd_path,
            'password': self.password,
            'keystore-id': None
        }
        keystore = load_keystore(args)
        assert(keystore_id == keystore.identity().id())

        args = {
            'keystore': self.wd_path,
            'password': self.password,
            'keystore-id': keystore_id
        }
        keystore = load_keystore(args)
        assert(keystore_id == keystore.identity().id())

        args = {
            'keystore': self.wd_path,
            'password': self.password,
            'keystore-id': 'sdfsldfkhsd'
        }
        keystore = load_keystore(args)
        assert(keystore is None)

    def test_cmd_service(self):
        # create identity
        args = [
            '--keystore', self.wd_path,
            '--password', self.password,
            'identity', 'create',
            '--name', 'name', '--email', 'email@internet.com'
        ]
        keystore_id = parse_args(args)
        assert(keystore_id is not None)

        service_host = '127.0.0.1'
        service_rest_port = 5002
        service_p2p_port = 4001

        args = {
            'keystore': self.wd_path,
            'keystore-id': keystore_id,
            'password': self.password,
            'datastore': self.wd_path,
            'host': service_host,
            'rest-port': service_rest_port,
            'p2p-port': service_p2p_port,
            'boot-node': f"{service_host}:{service_p2p_port}",
            'type': 'full'
        }
        keystore = load_keystore(args)
        node = exec_cmd_service(args, keystore)
        db_proxy = NodeDBProxy((service_host, service_rest_port))
        result = db_proxy.get_node()
        logger.info(result)
        assert(result is not None)
        assert(result['rest_service_address'][0] == service_host)
        assert(result['rest_service_address'][1] == service_rest_port)

        node.shutdown()

    def test_cmd_dor_add_remove(self):
        # create node and proxies
        node, dor_proxy, rti_proxy, db_proxy = self.create_node_and_proxies()

        # create keystore and identity
        keystore, identity = self.create_keystore_and_make_identity_known(db_proxy)

        # create some data object content
        path = self.generate_random_file('content.dat', 1024*1024)

        # perform ADD operation
        address = node.rest.address()
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'add', '--restrict-access', '--data-type', 'Type', '--data-format', 'Format', path
        ]
        obj_id = parse_args(args)
        assert(obj_id is not None)
        record = node.db.get_object_by_id(obj_id)
        assert(record is not None)
        print(record.obj_id)
        print(record.owner_iid)
        assert(record.obj_id == obj_id)
        assert(record.owner_iid == identity.id())

        # perform REMOVE operation
        fake_obj_id = '345345345345345'
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'remove', obj_id, fake_obj_id
        ]
        result = parse_args(args)
        print(result)
        assert(result is not None)
        assert(obj_id in result)
        assert(fake_obj_id in result)
        assert(result[obj_id] is not None)
        assert(result[fake_obj_id] is None)

    def test_cmd_dor_add_remove_with_encryption(self):
        # create node and proxies
        node, dor_proxy, rti_proxy, db_proxy = self.create_node_and_proxies()
        address = node.rest.address()

        # create keystore and identity
        keystore, identity = self.create_keystore_and_make_identity_known(db_proxy)

        # create some data object content
        path = self.generate_random_file('content.dat', 1024*1024)

        # perform ADD operation
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'add', '--restrict-access', '--encrypt-content', '--data-type', 'Type', '--data-format', 'Format', path
        ]
        obj_id = parse_args(args)
        assert(obj_id is not None)
        record = node.db.get_object_by_id(obj_id)
        assert(record is not None)
        print(record.obj_id)
        print(record.owner_iid)
        assert(record.obj_id == obj_id)
        assert(record.owner_iid == identity.id())

        # get the content of the data object
        dor_proxy = DORProxy(address)
        download_path = os.path.join(self.wd_path, f"{obj_id}.enc")
        dor_proxy.get_content(obj_id, keystore.signing_key(), download_path)

        # reload keystore (because its content has been changed -> content key has been added
        args = {
            'keystore': self.wd_path,
            'password': self.password,
            'keystore-id': identity.id()
        }
        keystore = load_keystore(args)

        # decrypt the file
        destination_path = os.path.join(self.wd_path, f"{obj_id}")
        content_key = keystore.get_object_key(obj_id)
        decrypt_file(download_path, destination=destination_path, key=content_key)
        assert(filecmp.cmp(path, destination_path))

        # perform REMOVE operation
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'remove', obj_id
        ]
        result = parse_args(args)
        print(result)
        assert(result is not None)
        assert(obj_id in result)
        assert(result[obj_id] is not None)

    def test_cmd_dor_tag_untag(self):
        # create node and proxies
        node, dor_proxy, rti_proxy, db_proxy = self.create_node_and_proxies()
        address = node.rest.address()

        # create keystore and identity
        keystore, identity = self.create_keystore_and_make_identity_known(db_proxy)

        # add data objects
        path = self.generate_random_file(f"content.dat", 1024*1024)
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'add', '--restrict-access', '--data-type', 'Type', '--data-format', 'Format', path
        ]
        obj_id = parse_args(args)
        assert(obj_id is not None)
        record = node.db.get_object_by_id(obj_id)
        assert(record is not None)
        print(record.obj_id)
        print(record.owner_iid)
        assert(record.obj_id == obj_id)
        assert(record.owner_iid == identity.id())

        # tag the data object
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'tag', '--obj-id', obj_id, 'key1=value1', 'key2=value2'
        ]
        tags = parse_args(args)
        assert(len(tags) == 2)
        assert('key1' in tags)
        assert('key2' in tags)
        assert(tags['key1'] == 'value1')
        assert(tags['key2'] == 'value2')

        # remove one of the tags (also test removing a key that doesn't exist)
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'untag', '--obj-id', obj_id, 'key1', 'key_doesnt_exist'
        ]
        tags = parse_args(args)
        assert(len(tags) == 1)
        assert('key2' in tags)
        assert(tags['key2'] == 'value2')

    def test_cmd_dor_search(self):
        # create node and proxies
        node, dor_proxy, rti_proxy, db_proxy = self.create_node_and_proxies()
        address = node.rest.address()

        # create keystore and identity
        keystore, identity = self.create_keystore_and_make_identity_known(db_proxy)

        # add data objects
        obj_ids = []
        for i in range(3):
            path = self.generate_random_file(f"content_{i}.dat", 1024*1024)
            args = [
                '--keystore', self.wd_path, '--temp-dir', self.wd_path,
                '--keystore-id', identity.id(), '--password', self.password,
                'dor', '--address', f"{address[0]}:{address[1]}",
                'add', '--restrict-access', '--data-type', 'Type', '--data-format', 'Format', path
            ]
            obj_id = parse_args(args)
            assert(obj_id is not None)
            obj_ids.append(obj_id)

            # tag the data object
            args = [
                '--keystore', self.wd_path, '--temp-dir', self.wd_path,
                '--keystore-id', identity.id(), '--password', self.password,
                'dor', '--address', f"{address[0]}:{address[1]}",
                'tag', '--obj-id', obj_id, f"key={i}"
            ]
            tags = parse_args(args)
            assert (len(tags) == 1)
            assert ('key' in tags)
            assert (tags['key'] == f"{i}")

        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'search', '--own', 'key'
        ]
        tags = parse_args(args)
        assert(len(tags) == len(obj_ids))

        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'search', '--own', '1'
        ]
        tags = parse_args(args)
        assert(len(tags) == 1)

    def test_cmd_access_grant_revoke(self):
        # create node and proxies
        node, dor_proxy, rti_proxy, db_proxy = self.create_node_and_proxies()
        address = node.rest.address()

        # create keystore and identity
        keystores, identities = self.create_keystore_and_make_identity_known(db_proxy, 2)

        # create some data object content
        path = self.generate_random_file('content.dat', 1024*1024)

        # perform ADD operation
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identities[0].id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'add', '--restrict-access', '--data-type', 'Type', '--data-format', 'Format', path
        ]
        obj_id = parse_args(args)
        assert(obj_id is not None)

        result = node.db.get_access_list(obj_id)
        assert(len(result) == 1)
        assert(identities[0].id() in result)

        # grant access
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identities[0].id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'grant', '--iid', identities[1].id(), obj_id
        ]
        granted = parse_args(args)
        assert(obj_id in granted)

        result = node.db.get_access_list(obj_id)
        assert(len(result) == 2)
        assert(identities[0].id() in result)
        assert(identities[1].id() in result)

        # revoke access
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identities[0].id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'revoke', '--iid', identities[1].id(), obj_id
        ]
        granted = parse_args(args)
        assert(obj_id in granted)

        result = node.db.get_access_list(obj_id)
        assert(len(result) == 1)
        assert(identities[0].id() in result)

        # perform REMOVE operation
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identities[0].id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'remove', obj_id
        ]
        result = parse_args(args)
        print(result)
        assert(result is not None)
        assert(obj_id in result)
        assert(result[obj_id] is not None)

    def test_cmd_rti_deploy_undeploy(self):
        # create node and proxies
        node, dor_proxy, rti_proxy, db_proxy = self.create_node_and_proxies()
        address = node.rest.address()

        # create keystore and identity
        keystore, identity = self.create_keystore_and_make_identity_known(db_proxy)

        # add test processor
        proc_id = self.add_test_processor_to_dor(identity, dor_proxy)
        fake_proc_id = '345345345345345'

        # perform DEPLOY operation w/ invalid proc_id
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'deploy', '--proc-id', fake_proc_id
        ]
        descriptor = parse_args(args)
        assert(descriptor is None)

        # perform DEPLOY operation w/ valid proc_id
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'deploy', '--proc-id', proc_id
        ]
        descriptor = parse_args(args)
        assert(descriptor is not None)

        # perform UNDEPLOY w/ invalid proc_id
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'undeploy', '--proc-id', fake_proc_id
        ]
        result = parse_args(args)
        assert(result is None)

        # perform DESCRIPTOR w/ invalid proc_id
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'descriptor', '--proc-id', fake_proc_id
        ]
        result = parse_args(args)
        assert(result is None)

        # perform DESCRIPTOR w/ valid proc_id
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'descriptor', '--proc-id', proc_id
        ]
        result = parse_args(args)
        assert(result is not None)

        # perform UNDEPLOY w/ valid proc_id
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'undeploy', '--proc-id', proc_id
        ]
        result = parse_args(args)
        assert(result is not None)

    def test_cmd_rti_submit_status(self):
        # create node and proxies
        node, dor_proxy, rti_proxy, db_proxy = self.create_node_and_proxies()
        address = node.rest.address()

        # create keystore and identity
        keystore, identity = self.create_keystore_and_make_identity_known(db_proxy)

        # add and deploy test processor
        proc_id = self.add_test_processor_to_dor(identity, dor_proxy)
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'deploy', '--proc-id', proc_id
        ]
        descriptor = parse_args(args)
        assert(descriptor is not None)

        # create input data objects
        a_file_path = self.create_file_with_content('a.json', json.dumps({'v': 1}))
        b_file_path = self.create_file_with_content('b.json', json.dumps({'v': 2}))
        a_obj_id, _ = dor_proxy.add_data_object(a_file_path, identity,
                                                False, False, None, 'JSONObject', 'json', identity.name())
        b_obj_id, _ = dor_proxy.add_data_object(b_file_path, identity,
                                                False, False, None, 'JSONObject', 'json', identity.name())

        # perform SUBMIT operation w/ invalid proc_id
        invalid_proc_id = "sdfsdfsdf"
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'submit', '--proc-id', invalid_proc_id,
            f"a:{a_file_path}", f"b:{b_file_path}", f"c:{identity.id()}:false:false"
        ]
        job_id = parse_args(args)
        assert(job_id is None)

        # perform SUBMIT operation w/ invalid input
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'submit', '--proc-id', proc_id,
            f"a:x:y"
        ]
        job_id = parse_args(args)
        assert(job_id is None)

        # perform SUBMIT operation w/ invalid input
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'submit', '--proc-id', proc_id,
            f"a:{os.path.join(a_file_path, 'doesnt_exist')}"
        ]
        job_id = parse_args(args)
        assert(job_id is None)

        # perform SUBMIT operation w/ invalid output (invalid owner id)
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'submit', '--proc-id', proc_id,
            f"c:invalid_owner_id:false:false"
        ]
        job_id = parse_args(args)
        assert(job_id is None)

        # perform SUBMIT operation w/ invalid output (invalid restrict_access flag)
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'submit', '--proc-id', proc_id,
            f"c:{identity.id()}:fasdflse:false"
        ]
        job_id = parse_args(args)

        assert(job_id is None)

        # perform SUBMIT operation w/ invalid output (invalid encrypt_content flag)
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'submit', '--proc-id', proc_id,
            f"c:{identity.id()}:false:sdfsdfse"
        ]
        job_id = parse_args(args)
        assert (job_id is None)

        # perform SUBMIT operation w/ incomplete items
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'submit', '--proc-id', proc_id,
            f"a:{a_obj_id}",
            f"c:{identity.id()}:false:false"
        ]
        job_id = parse_args(args)
        assert (job_id is None)

        # perform SUBMIT operation
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'submit', '--proc-id', proc_id,
            f"a:{a_obj_id}",
            f"b:{b_file_path}",
            f"c:{identity.id()}:false:false"
        ]
        job_id = parse_args(args)
        assert (job_id is not None)

        # perform STATUS operation w/ invalid job_id
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'status', '--job-id', 'invalid-job-id'
        ]
        status = parse_args(args)
        assert (status is None)

        while True:
            # perform STATUS operation
            args = [
                '--keystore', self.wd_path, '--temp-dir', self.wd_path,
                '--keystore-id', identity.id(), '--password', self.password,
                'rti', '--address', f"{address[0]}:{address[1]}",
                'status', '--job-id', job_id
            ]
            status = parse_args(args)
            assert (status is not None)

            if status['state'] == 'successful' or status['state'] == 'failed':
                break

            time.sleep(1)

        assert True

    def test_cmd_handle_content_key_request(self):
        # create node and proxies
        node, dor_proxy, rti_proxy, db_proxy = self.create_node_and_proxies()
        address = node.rest.address()

        email = "aydt@arch.ethz.ch"
        account = "aydth@ethz.ch"
        password = prompt("SMTP password:", hidden=True)
        node.update_identity(name="Heiko Aydt", email=email)
        node.start_email_service(('mail.ethz.ch', 587), account, password)

        # create keystore and identity (note: need to use a real user here otherwise SMTP won't work)
        keystore, identity = self.create_keystore_and_make_identity_known(db_proxy,
                                                                          name='Heiko Aydt', email='aydt@arch.ethz.ch')

        # add and deploy test processor
        proc_id = self.add_test_processor_to_dor(identity, dor_proxy)
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'deploy', '--proc-id', proc_id
        ]
        descriptor = parse_args(args)
        assert(descriptor is not None)

        # create data object contents
        a_file_path = self.create_file_with_content('a.json', json.dumps({'v': 1}))
        b_file_path = self.create_file_with_content('b.json', json.dumps({'v': 2}))

        # add input data object A
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'dor', '--address', f"{address[0]}:{address[1]}",
            'add', '--restrict-access', '--encrypt-content', '--data-type', 'JSONObject', '--data-format', 'json',
            a_file_path
        ]
        a_obj_id = parse_args(args)
        assert(a_obj_id is not None)

        # perform SUBMIT operation
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'rti', '--address', f"{address[0]}:{address[1]}",
            'submit', '--proc-id', proc_id,
            f"a:{a_obj_id}",
            f"b:{b_file_path}",
            f"c:{identity.id()}:false:false"
        ]
        job_id = parse_args(args)
        assert (job_id is not None)

        # process request
        request = prompt("Copy and paste encrypted request here:")
        args = [
            '--keystore', self.wd_path, '--temp-dir', self.wd_path,
            '--keystore-id', identity.id(), '--password', self.password,
            'handle', request
        ]
        result = parse_args(args)
        assert (result is True)

        while True:
            # perform STATUS operation
            args = [
                '--keystore', self.wd_path, '--temp-dir', self.wd_path,
                '--keystore-id', identity.id(), '--password', self.password,
                'rti', '--address', f"{address[0]}:{address[1]}",
                'status', '--job-id', job_id
            ]
            status = parse_args(args)
            assert (status is not None)

            if status['state'] == 'successful' or status['state'] == 'failed':
                break

            time.sleep(1)


if __name__ == '__main__':
    unittest.main()
