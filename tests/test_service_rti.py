import json
import logging
import os
import shutil
import tempfile
import time
import unittest
from threading import Thread

from saas.cryptography.helpers import encrypt_file
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.dor.blueprint import DORProxy
from saas.nodedb.blueprint import NodeDBProxy
from saas.rti.blueprint import RTIProxy
from saas.rti.status import State
from saas.helpers import dump_json_to_file, get_timestamp_now, prompt
from tests.base_testcase import TestCaseBase

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class RTIServiceTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        self.node = self.get_node('node', use_credentials=True, enable_rest=True)
        self.dor_proxy = DORProxy(self.node.rest.address())
        self.rti_proxy = RTIProxy(self.node.rest.address())
        self.db_proxy = NodeDBProxy(self.node.rest.address())

        # create extra keystores and make them known to the node
        self.extras = self.create_keystores(3)
        for extra in self.extras:
            signature = extra.update()
            identity = extra.identity()
            self.db_proxy.update_identity(identity, signature)

    def tearDown(self):
        self.cleanup()

    def prompt_for_request(self, owner_k, content_key):
        request = prompt("Copy and paste the request received by email")

        # we should be able to decrypt it
        request = owner_k.encryption_key().decrypt(request.encode('utf-8'), base64_encoded=True).decode('utf-8')
        request = json.loads(request)
        print(request)

        # get the ephemeral key and encrypt the content key with the ephemeral key
        key = RSAKeyPair.from_public_key_string(request['ephemeral_public_key'])
        content_key = owner_k.encryption_key().decrypt(content_key.encode('utf-8'), base64_encoded=True).decode('utf-8')
        content_key = key.encrypt(content_key.encode('utf-8'), base64_encoded=True).decode('utf-8')

        # submit the content key
        self.rti_proxy.put_permission(request['req_id'], content_key)

    def add_test_processor_to_dor(self):
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

        proc_id, _ = self.dor_proxy.add_data_object(git_proc_pointer_path, self.extras[1].identity(),
                                                    False, False, None,
                                                    data_type, data_format, created_by, created_t)

        return proc_id

    def add_dummy_data_object(self, owner, access_restricted):
        test_file_path = self.create_file_with_content('a.dat', json.dumps({'v': 1}))
        test_obj_id = 'c1cfe06853dae66d0340811947a7237d16983f5a4dbfa5608338eadfe423d3ae'

        data_type = 'JSONObject'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        obj_id, _ = self.dor_proxy.add_data_object(test_file_path, owner.identity(),
                                                   access_restricted, False, None,
                                                   data_type, data_format, created_by, created_t)

        return test_obj_id, obj_id

    def add_encrypted_dummy_data_object(self, owner):
        test_file_path = self.create_file_with_content('a.dat', json.dumps({'v': 1}))

        data_type = 'JSONObject'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        content_key = encrypt_file(test_file_path, protect_key_with=owner.encryption_public_key(), delete_source=True)

        obj_id, _ = self.dor_proxy.add_data_object(test_file_path, owner,
                                                   True, True, content_key,
                                                   data_type, data_format, created_by, created_t)

        return obj_id, content_key

    def submit_job_and_wait(self, proc_id, a_obj_id, user, generate_valid_signature):
        rti_node_info = self.db_proxy.get_node()
        if generate_valid_signature:
            a_access_token = f"{rti_node_info['iid']}:{a_obj_id}"
            a_signature = user.signing_key().sign(a_access_token.encode('utf-8'))

        else:
            a_access_token = f"invalid content"
            a_signature = user.signing_key().sign(a_access_token.encode('utf-8'))

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
                'owner_iid': self.extras[1].identity().id(),
                'restricted_access': False,
                'content_encrypted': False
            }
        ]

        job_id = self.rti_proxy.submit_job(proc_id, job_input, job_output, user.identity())
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = self.rti_proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        result = self.wait_for_job(job_id)
        return job_id, result

    def wait_for_job(self, job_id):
        while True:
            time.sleep(5)
            descriptor, status = self.rti_proxy.get_job_info(job_id)
            if descriptor and status:
                logger.info(f"descriptor={descriptor}")
                logger.info(f"status={status}")

                state = State.from_string(status['state'])
                if state == State.SUCCESSFUL:
                    return True
                elif state == State.FAILED:
                    return False

    def test_deployment_undeployment(self):
        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

        proc_id = self.add_test_processor_to_dor()
        logger.info(f"proc_id={proc_id}")

        descriptor = self.rti_proxy.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        descriptor = self.rti_proxy.get_descriptor(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        result = self.rti_proxy.undeploy('false proc id')
        assert result is None

        result = self.rti_proxy.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_processor_execution_value(self):
        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

        proc_id = self.add_test_processor_to_dor()
        logger.info(f"proc_id={proc_id}")

        descriptor = self.rti_proxy.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        jobs = self.rti_proxy.get_jobs(proc_id)
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
                'owner_iid': self.extras[2].identity().id(),
                'restricted_access': False,
                'content_encrypted': False
            }
        ]

        job_id = self.rti_proxy.submit_job(proc_id, job_input, job_output, self.extras[1].identity())
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = self.rti_proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        self.wait_for_job(job_id)

        jobs = self.rti_proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, self.node.datastore(), 'jobs', str(job_id), 'c')
        assert os.path.isfile(output_path)

        result = self.rti_proxy.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_processor_execution_reference_unrestricted(self):
        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

        proc_id = self.add_test_processor_to_dor()
        logger.info(f"proc_id={proc_id}")

        descriptor = self.rti_proxy.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        jobs = self.rti_proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        owner = self.extras[1]
        user = self.extras[2]

        # add data object
        a_obj_id_ref, a_obj_id = self.add_dummy_data_object(owner, False)
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
                'owner_iid': self.extras[1].identity().id(),
                'restricted_access': False,
                'content_encrypted': False
            }
        ]

        job_id = self.rti_proxy.submit_job(proc_id, job_input, job_output, user.identity())
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = self.rti_proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        result = self.wait_for_job(job_id)
        assert(result is True)

        jobs = self.rti_proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, self.node.datastore(), 'jobs', str(job_id), 'c')
        assert(os.path.isfile(output_path))

        result = self.rti_proxy.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_processor_execution_reference_restricted(self):
        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

        proc_id = self.add_test_processor_to_dor()
        logger.info(f"proc_id={proc_id}")

        descriptor = self.rti_proxy.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert(proc_id in deployed)

        jobs = self.rti_proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        owner = self.extras[1]
        user = self.extras[2]

        # add data object
        a_obj_id_ref, a_obj_id = self.add_dummy_data_object(owner, True)
        logger.info(f"a_obj_id={a_obj_id}")
        assert a_obj_id == a_obj_id_ref

        # valid signature but no access rights
        job_id, result = self.submit_job_and_wait(proc_id, a_obj_id, user, True)
        assert(result is False)

        # grant access
        access = self.dor_proxy.grant_access(a_obj_id, owner.signing_key(), user.identity())
        assert(access is not None)
        assert(access[a_obj_id] == user.identity().id())

        # invalid signature
        job_id, result = self.submit_job_and_wait(proc_id, a_obj_id, user, False)
        assert(result is False)

        # valid signature
        job_id, result = self.submit_job_and_wait(proc_id, a_obj_id, user, True)
        assert(result is True)

        jobs = self.rti_proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, self.node.datastore(), 'jobs', str(job_id), 'c')
        assert(os.path.isfile(output_path))

        result = self.rti_proxy.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    def test_processor_execution_reference_encrypted(self):
        keystores = self.create_keystores(2)

        # create an owner identity
        owner_signature = keystores[0].update(name="Foo Bar", email=self.node.identity().email())
        owner = keystores[0].identity()
        self.db_proxy.update_identity(owner, owner_signature)

        # create a user identity
        user_signature = keystores[1].update(name="John Doe", email=self.node.identity().email())
        user = keystores[1].identity()
        self.db_proxy.update_identity(user, user_signature)

        # add and deploy test processor
        proc_id = self.add_test_processor_to_dor()
        logger.info(f"proc_id={proc_id}")
        descriptor = self.rti_proxy.deploy(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        # add data object
        a_obj_id, a_content_key = self.add_encrypted_dummy_data_object(owner)
        logger.info(f"a_obj_id={a_obj_id}")

        # grant access
        access = self.dor_proxy.grant_access(a_obj_id, keystores[0].signing_key(), user)
        assert(access is not None)
        assert(access[a_obj_id] == user.id())

        # start a separate thread to
        thread = Thread(target=self.prompt_for_request, args=[keystores[0], a_content_key])
        thread.start()

        # valid signature
        job_id, result = self.submit_job_and_wait(proc_id, a_obj_id, keystores[1], True)
        assert(result is True)

        jobs = self.rti_proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, self.node.datastore(), 'jobs', str(job_id), 'c')
        assert(os.path.isfile(output_path))

        result = self.rti_proxy.undeploy(proc_id)
        assert result is not None
        assert result == proc_id

        deployed = self.rti_proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 0)

    # def test_docker_processor_execution_value(self):
    #     image_path, descriptor_path, cleanup_func = create_dummy_docker_processor('proc_dummy_script.py')
    #
    #     deployed = self.rti_proxy.get_deployed()
    #     logger.info(f"deployed={deployed}")
    #     assert(deployed is not None)
    #     assert(len(deployed) == 0)
    #
    #     data_type = 'Processor'
    #     data_format = 'Docker Image'
    #     created_t = 21342342
    #     created_by = 'heiko'
    #
    #     proc_id, _ = self.dor_proxy.add_data_object(image_path, self.extras[1].identity(),
    #                                                 False, False, None,
    #                                                 data_type, data_format, created_by, created_t)
    #
    #     logger.info(f"proc_id={proc_id}")
    #     cleanup_func()
    #
    #     descriptor = self.rti_proxy.deploy(proc_id)
    #     logger.info(f"descriptor={descriptor}")
    #
    #     deployed = self.rti_proxy.get_deployed()
    #     logger.info(f"deployed={deployed}")
    #     assert(deployed is not None)
    #     assert(len(deployed) == 1)
    #     assert(proc_id in deployed)
    #
    #     jobs = self.rti_proxy.get_jobs(proc_id)
    #     logger.info(f"jobs={jobs}")
    #     assert(jobs is not None)
    #     assert(len(jobs) == 0)
    #
    #     proc_input = [
    #         {
    #             'name': 'a',
    #             'type': 'value',
    #             'value': {
    #                 'v': 1
    #             }
    #         },
    #         {
    #             'name': 'b',
    #             'type': 'value',
    #             'value': {
    #                 'v': 2
    #             }
    #         }
    #     ]
    #
    #     job_id = self.rti_proxy.submit_job(proc_id, proc_input, self.extras[1].identity())
    #     logger.info(f"job_id={job_id}")
    #     assert(job_id is not None)
    #
    #     jobs = self.rti_proxy.get_jobs(proc_id)
    #     logger.info(f"jobs={jobs}")
    #     assert(jobs is not None)
    #     assert(len(jobs) == 1)
    #
    #     self.wait_for_job(proc_id, job_id)
    #
    #     jobs = self.rti_proxy.get_jobs(proc_id)
    #     logger.info(f"jobs={jobs}")
    #     assert(jobs is not None)
    #     assert(len(jobs) == 0)
    #
    #     output_path = os.path.join(self.wd_path, self.node.datastore(), 'jobs', str(job_id), 'c')
    #     assert os.path.isfile(output_path)
    #
    #     self.rti_proxy.undeploy(proc_id)
    #
    #     deployed = self.rti_proxy.get_deployed()
    #     logger.info(f"deployed={deployed}")
    #     assert(deployed is not None)
    #     assert(len(deployed) == 0)


if __name__ == '__main__':
    unittest.main()
