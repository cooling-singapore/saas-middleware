import json
import logging
import os
import time
import unittest
from threading import Thread

from saas.cryptography.helpers import encrypt_file
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.dor.blueprint import DORProxy
from saas.keystore.identity import Identity
from saas.keystore.keystore import Keystore
from saas.nodedb.blueprint import NodeDBProxy
from saas.rti.adapters.docker import prune_image
from saas.rti.blueprint import RTIProxy
from saas.rti.status import State
from saas.helpers import get_timestamp_now, prompt
from tests.base_testcase import TestCaseBase

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


def wait_for_job(rti, job_id):
    while True:
        time.sleep(5)
        descriptor, status = rti.get_job_info(job_id)
        if descriptor and status:
            logger.info(f"descriptor={descriptor}")
            logger.info(f"status={status}")

            state = State.from_string(status['state'])
            if state == State.SUCCESSFUL:
                return True
            elif state == State.FAILED:
                return False


def add_test_processor_to_dor(dor: DORProxy, owner: Identity, config: str):
    source = 'https://github.com/cooling-singapore/saas-processor-template'
    commit_id = '972bd54'
    proc_path = 'processor_test'
    proc_config = config
    created_t = get_timestamp_now()
    created_by = 'test_user'

    proc_id, _ = dor.add_gpp_data_object(source, commit_id, proc_path, proc_config, owner, created_by, created_t)
    return proc_id


class RTIServiceTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

    def tearDown(self):
        self.cleanup()

    def prompt_for_request(self, rti: RTIProxy, owner_k: Keystore, content_key: str):
        request = prompt("Copy and paste the request received by email")

        # we should be able to decrypt it
        request = owner_k.decrypt(request.encode('utf-8')).decode('utf-8')
        request = json.loads(request)
        print(request)

        # get the ephemeral key and encrypt the content key with the ephemeral key
        key = RSAKeyPair.from_public_key_string(request['ephemeral_public_key'])
        content_key = owner_k.decrypt(content_key.encode('utf-8')).decode('utf-8')
        content_key = key.encrypt(content_key.encode('utf-8'), base64_encoded=True).decode('utf-8')

        # submit the content key
        rti.put_permission(request['req_id'], content_key)

    def add_dummy_data_object(self, dor: DORProxy, owner: Identity, access_restricted: bool):
        test_file_path = self.create_file_with_content('a.dat', json.dumps({'v': 1}))
        test_obj_id = 'c1cfe06853dae66d0340811947a7237d16983f5a4dbfa5608338eadfe423d3ae'

        data_type = 'JSONObject'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        obj_id, _ = dor.add_data_object(test_file_path, owner,
                                        access_restricted, False,
                                        data_type, data_format, created_by, created_t)

        return test_obj_id, obj_id

    def add_encrypted_dummy_data_object(self, dor: DORProxy, owner: Identity):
        test_file_path = self.create_file_with_content('a.dat', json.dumps({'v': 1}))

        data_type = 'JSONObject'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        content_key = encrypt_file(test_file_path, encrypt_for=owner, delete_source=True)

        obj_id, _ = dor.add_data_object(test_file_path, owner,
                                        True, True,
                                        data_type, data_format, created_by, created_t)

        return obj_id, content_key

    def submit_job_and_wait(self, db: NodeDBProxy, rti: RTIProxy, proc_id, a_obj_id, output_owner: Identity,
                            user: Keystore, generate_valid_signature: bool):
        rti_node_info = db.get_node()
        if generate_valid_signature:
            a_access_token = f"{rti_node_info['iid']}:{a_obj_id}"
            a_signature = user.sign(a_access_token.encode('utf-8'))

        else:
            a_access_token = f"invalid content"
            a_signature = user.sign(a_access_token.encode('utf-8'))

        job_input = [
            {
                'name': 'a',
                'type': 'reference',
                'obj_id': a_obj_id,
                'user_signature': a_signature
            },
            {
                'name': 'b',
                'type': 'value',
                'value': {
                    'v': 2
                }
            }
        ]

        job_output = [
            {
                'name': 'c',
                'owner_iid': output_owner.id,
                'restricted_access': False,
                'content_encrypted': False
            }
        ]

        job_id = rti.submit_job(proc_id, job_input, job_output, user.identity)
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        result = wait_for_job(rti, job_id)
        return job_id, result

    def test_deployment_undeployment(self):
        # create node
        node = self.get_node('node', enable_rest=True)
        db = NodeDBProxy(node.rest.address())
        rti = RTIProxy(node.rest.address())
        dor = DORProxy(node.rest.address())

        # create owner identity
        owner = self.create_keystores(1)[0]
        db.update_identity(owner.identity)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

        proc_id = add_test_processor_to_dor(dor, owner.identity, 'default')
        logger.info(f"proc_id={proc_id}")

        descriptor = rti.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        descriptor = rti.get_descriptor(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        result = rti.undeploy('false proc id')
        assert result is None

        result = rti.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_processor_execution_value(self):
        # create node
        node = self.get_node('node', enable_rest=True)
        db = NodeDBProxy(node.rest.address())
        rti = RTIProxy(node.rest.address())
        dor = DORProxy(node.rest.address())

        # create owner identity
        keystores = self.create_keystores(2)
        owner = keystores[0]
        user = keystores[1]
        db.update_identity(owner.identity)
        db.update_identity(user.identity)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

        proc_id = add_test_processor_to_dor(dor, owner.identity, 'default')
        logger.info(f"proc_id={proc_id}")

        descriptor = rti.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        job_input = [
            {
                'name': 'a',
                'type': 'value',
                'value': {
                    'v': 1
                }
            },
            {
                'name': 'b',
                'type': 'value',
                'value': {
                    'v': 2
                }
            }
        ]

        job_output = [
            {
                'name': 'c',
                'owner_iid': owner.identity.id,
                'restricted_access': False,
                'content_encrypted': False
            }
        ]

        job_id = rti.submit_job(proc_id, job_input, job_output, user.identity)
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        wait_for_job(rti, job_id)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, node.datastore(), 'jobs', str(job_id), 'c')
        assert os.path.isfile(output_path)

        result = rti.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_processor_execution_specific_target_node(self):
        # create node
        node = self.get_node('node', enable_rest=True)
        db = NodeDBProxy(node.rest.address())
        rti = RTIProxy(node.rest.address())
        dor = DORProxy(node.rest.address())

        # create owner identity
        keystores = self.create_keystores(2)
        owner = keystores[0]
        user = keystores[1]
        db.update_identity(owner.identity)
        db.update_identity(user.identity)

        proc_id = add_test_processor_to_dor(dor, owner.identity, 'default')
        logger.info(f"proc_id={proc_id}")

        descriptor = rti.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        # create target node and join with the default node
        target_node = self.get_node('target', enable_rest=True)
        target_node.join_network(node.p2p.address())
        target_dor = DORProxy(target_node.rest.address())
        time.sleep(2)

        job_input = [
            {
                'name': 'a',
                'type': 'value',
                'value': {
                    'v': 1
                }
            },
            {
                'name': 'b',
                'type': 'value',
                'value': {
                    'v': 2
                }
            }
        ]

        job_output = [
            {
                'name': 'c',
                'owner_iid': owner.identity.id,
                'restricted_access': False,
                'content_encrypted': False,
                'target_node_iid': target_node.identity().id
            }
        ]

        job_id = rti.submit_job(proc_id, job_input, job_output, user.identity)
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        wait_for_job(rti, job_id)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        # get job info and extract object id
        descriptor, status = rti.get_job_info(job_id)
        outputs = status['output']
        output = {o['name']: o['obj_id'] for o in outputs}
        obj_id = output['c']

        # the output data object should be with nodes[1]
        obj_descriptor0 = dor.get_descriptor(obj_id)
        obj_descriptor1 = target_dor.get_descriptor(obj_id)
        assert(obj_descriptor0 is None)
        assert(obj_descriptor1 is not None)

        result = rti.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_processor_execution_reference_unrestricted(self):
        # create node
        node = self.get_node('node', enable_rest=True)
        db = NodeDBProxy(node.rest.address())
        rti = RTIProxy(node.rest.address())
        dor = DORProxy(node.rest.address())

        # create owner identity
        keystores = self.create_keystores(2)
        owner = keystores[0]
        user = keystores[1]
        db.update_identity(owner.identity)
        db.update_identity(user.identity)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

        proc_id = add_test_processor_to_dor(dor, owner.identity, 'default')
        logger.info(f"proc_id={proc_id}")

        descriptor = rti.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        # add data object
        a_obj_id_ref, a_obj_id = self.add_dummy_data_object(dor, owner.identity, False)
        logger.info(f"a_obj_id={a_obj_id}")
        assert a_obj_id == a_obj_id_ref

        job_input = [
            {
                'name': 'a',
                'type': 'reference',
                'obj_id': a_obj_id
            },
            {
                'name': 'b',
                'type': 'value',
                'value': {
                    'v': 2
                }
            }
        ]

        job_output = [
            {
                'name': 'c',
                'owner_iid': owner.identity.id,
                'restricted_access': False,
                'content_encrypted': False
            }
        ]

        job_id = rti.submit_job(proc_id, job_input, job_output, user.identity)
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        result = wait_for_job(rti, job_id)
        assert(result is True)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, node.datastore(), 'jobs', str(job_id), 'c')
        assert(os.path.isfile(output_path))

        result = rti.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_processor_execution_reference_restricted(self):
        # create node
        node = self.get_node('node', enable_rest=True)
        db = NodeDBProxy(node.rest.address())
        rti = RTIProxy(node.rest.address())
        dor = DORProxy(node.rest.address())

        # create owner identity
        keystores = self.create_keystores(2)
        owner = keystores[0]
        user = keystores[1]
        db.update_identity(owner.identity)
        db.update_identity(user.identity)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

        proc_id = add_test_processor_to_dor(dor, owner.identity, 'default')
        logger.info(f"proc_id={proc_id}")

        descriptor = rti.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        # add data object
        a_obj_id_ref, a_obj_id = self.add_dummy_data_object(dor, owner.identity, True)
        logger.info(f"a_obj_id={a_obj_id}")
        assert a_obj_id == a_obj_id_ref

        # valid signature but no access rights
        job_id, result = self.submit_job_and_wait(db, rti, proc_id, a_obj_id, owner.identity, user, True)
        assert(result is False)

        # grant access
        access = dor.grant_access(a_obj_id, owner, user.identity)
        assert(access is not None)
        assert(access[a_obj_id] == user.identity.id)

        # invalid signature
        job_id, result = self.submit_job_and_wait(db, rti, proc_id, a_obj_id, owner.identity, user, False)
        assert(result is False)

        # valid signature
        job_id, result = self.submit_job_and_wait(db, rti, proc_id, a_obj_id, owner.identity, user, True)
        assert(result is True)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, node.datastore(), 'jobs', str(job_id), 'c')
        assert(os.path.isfile(output_path))

        result = rti.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_processor_execution_reference_encrypted(self):
        # create node
        node = self.get_node('node', enable_rest=True)
        db = NodeDBProxy(node.rest.address())
        rti = RTIProxy(node.rest.address())
        dor = DORProxy(node.rest.address())

        # create owner identity
        keystores = self.create_keystores(2)
        owner = keystores[0]
        user = keystores[1]
        db.update_identity(owner.identity)
        db.update_identity(user.identity)

        # add and deploy test processor
        proc_id = add_test_processor_to_dor(dor, owner.identity, 'default')
        logger.info(f"proc_id={proc_id}")
        descriptor = rti.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        # add data object
        a_obj_id, a_content_key = self.add_encrypted_dummy_data_object(dor, owner.identity)
        logger.info(f"a_obj_id={a_obj_id}")

        # grant access
        access = dor.grant_access(a_obj_id, owner, user.identity)
        assert(access is not None)
        assert(access[a_obj_id] == user.identity.id)

        # start a separate thread to
        thread = Thread(target=self.prompt_for_request, args=[rti, owner, a_content_key])
        thread.start()

        # valid signature
        job_id, result = self.submit_job_and_wait(db, rti, proc_id, a_obj_id, owner.identity, user, True)
        assert(result is True)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, node.datastore(), 'jobs', str(job_id), 'c')
        assert(os.path.isfile(output_path))

        result = rti.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_docker_processor_execution_value(self):
        import docker
        try:  # Check if able to get docker. if not ignore test and pass
            _ = docker.from_env()
        except Exception as e:
            logger.exception("Could not find docker on this machine")
            return

        # create node
        node = self.get_node('node', enable_rest=True)
        db = NodeDBProxy(node.rest.address())
        rti = RTIProxy(node.rest.address())
        dor = DORProxy(node.rest.address())

        # create owner identity
        keystores = self.create_keystores(2)
        owner = keystores[0]
        user = keystores[1]
        db.update_identity(owner.identity)
        db.update_identity(user.identity)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert (deployed is not None)
        assert (len(deployed) == 0)

        proc_id = add_test_processor_to_dor(dor, owner.identity, 'default')
        logger.info(f"proc_id={proc_id}")

        descriptor = rti.deploy(proc_id, 'docker')
        logger.info(f"descriptor={descriptor}")
        assert (descriptor is not None)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert (deployed is not None)
        assert (len(deployed) == 1)
        assert (proc_id in deployed)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert (jobs is not None)
        assert (len(jobs) == 0)

        job_input = [
            {
                'name': 'a',
                'type': 'value',
                'value': {
                    'v': 1
                }
            },
            {
                'name': 'b',
                'type': 'value',
                'value': {
                    'v': 2
                }
            }
        ]

        job_output = [
            {
                'name': 'c',
                'owner_iid': owner.identity.id,
                'restricted_access': False,
                'content_encrypted': False
            }
        ]

        job_id = rti.submit_job(proc_id, job_input, job_output, user.identity)
        logger.info(f"job_id={job_id}")
        assert (job_id is not None)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert (jobs is not None)
        assert (len(jobs) == 1)

        result = wait_for_job(rti, job_id)
        assert (result is True)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert (jobs is not None)
        assert (len(jobs) == 0)

        output_path = os.path.join(self.wd_path, node.datastore(), 'jobs', str(job_id), 'c')
        assert os.path.isfile(output_path)

        result = rti.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert (deployed is not None)
        assert (len(deployed) == 0)

        prune_image(proc_id)


class RTIServiceTestCaseNSCC(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

    def tearDown(self):
        self.cleanup()

    def test_deployment_undeployment(self):
        # create node
        node = self.get_node('node', enable_rest=True, use_ssh_profile='nscc')
        if not node:
            logger.info("Cannot test NSCC remote execution without SSH credentials.")
            return

        # create proxies
        db = NodeDBProxy(node.rest.address())
        rti = RTIProxy(node.rest.address())
        dor = DORProxy(node.rest.address())

        # create owner identity
        keystores = self.create_keystores(2)
        owner = keystores[0]
        user = keystores[1]
        db.update_identity(owner.identity)
        db.update_identity(user.identity)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

        proc_id = add_test_processor_to_dor(dor, owner.identity, 'nscc')
        logger.info(f"proc_id={proc_id}")

        descriptor = rti.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        descriptor = rti.get_descriptor(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        result = rti.undeploy('false proc id')
        assert result is None

        result = rti.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_processor_execution_value(self):
        # create node
        node = self.get_node('node', enable_rest=True, use_ssh_profile='nscc')
        if not node:
            logger.info("Cannot test NSCC remote execution without SSH credentials.")
            return

        # create proxies
        db = NodeDBProxy(node.rest.address())
        rti = RTIProxy(node.rest.address())
        dor = DORProxy(node.rest.address())

        # create owner identity
        keystores = self.create_keystores(2)
        owner = keystores[0]
        user = keystores[1]
        db.update_identity(owner.identity)
        db.update_identity(user.identity)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

        proc_id = add_test_processor_to_dor(dor, owner.identity, 'nscc')
        logger.info(f"proc_id={proc_id}")

        descriptor = rti.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        job_input = [
            {
                'name': 'a',
                'type': 'value',
                'value': {
                    'v': 1
                }
            },
            {
                'name': 'b',
                'type': 'value',
                'value': {
                    'v': 2
                }
            }
        ]

        job_output = [
            {
                'name': 'c',
                'owner_iid': owner.identity.id,
                'restricted_access': False,
                'content_encrypted': False
            }
        ]

        job_id = rti.submit_job(proc_id, job_input, job_output, user.identity)
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        wait_for_job(rti, job_id)

        jobs = rti.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, node.datastore(), 'jobs', str(job_id), 'c')
        assert os.path.isfile(output_path)

        result = rti.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = rti.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)


if __name__ == '__main__':
    unittest.main()
