import json
import logging
import os
import shutil
import time
import unittest
from json import JSONDecodeError
from threading import Thread

from saas.cryptography.helpers import encrypt_file
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.dor.proxy import DORProxy
from saas.exceptions import SaaSException, RunCommandError, UnsuccessfulRequestError
from saas.helpers import get_timestamp_now, read_json_from_file, generate_random_string
from saas.keystore.assets.credentials import CredentialsAsset, GithubCredentials, SSHCredentials
from saas.keystore.keystore import Keystore
from saas.log import Logging
from saas.nodedb.proxy import NodeDBProxy
from saas.rti.adapters.base import monitor_command, run_command, run_command_async, ProcessorState
from saas.rti.proxy import RTIProxy
from saas.rti.status import State

from tests.base_testcase import TestCaseBase

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


def add_test_processor(dor: DORProxy, owner: Keystore, config: str) -> (str, GithubCredentials):
    source = 'https://github.com/cooling-singapore/saas-middleware-sdk'
    commit_id = '9bf18c3'
    proc_path = 'saasadapters/example'

    asset: CredentialsAsset = owner.get_asset('github-credentials')
    github_credentials: GithubCredentials = asset.get(source)

    meta = dor.add_gpp_data_object(source, commit_id, proc_path, config, owner.identity,
                                   github_credentials=github_credentials)
    return meta.obj_id, github_credentials


def deploy_and_wait(rti: RTIProxy, proc_id: str, github_credentials: GithubCredentials = None):
    rti.deploy(proc_id, github_credentials=github_credentials)
    while (state := rti.get_status(proc_id).state) == ProcessorState.STARTING:
        logger.info(f"Waiting for processor to deploy. {state}")
        time.sleep(1)
    logger.info(f"Processor to deployed. {state}")


class RTIRESTTestCase(unittest.TestCase, TestCaseBase):
    _wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))
    _node = None
    _rti = None
    _dor = None
    _test_proc_id = None
    _test_proc_gh_cred = None

    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    @classmethod
    def tearDownClass(cls):
        if cls._node is not None:
            shutil.rmtree(cls._wd_path, ignore_errors=True)
            cls._node.shutdown(leave_network=False)

    def setUp(self):
        self.initialise()

        if RTIRESTTestCase._node is None:
            RTIRESTTestCase._node = self.get_node('node', enable_rest=True, keep_track=False,
                                                  wd_path=RTIRESTTestCase._wd_path)
            RTIRESTTestCase._rti = RTIProxy(RTIRESTTestCase._node.rest.address())
            RTIRESTTestCase._dor = DORProxy(RTIRESTTestCase._node.rest.address())
            time.sleep(1)

            RTIRESTTestCase._test_proc_id, RTIRESTTestCase._test_proc_gh_cred = add_test_processor(
                RTIRESTTestCase._dor, RTIRESTTestCase._node.keystore, 'default')

    def tearDown(self):
        self.cleanup()

    def test_rest_get_deployed(self):
        result = self._rti.get_deployed()
        print(result)
        assert(result is not None)
        assert(len(result) == 0)

    def test_rest_deploy_descriptor_status_undeploy(self):
        # deploy the test processor
        result = self._rti.deploy(self._test_proc_id, github_credentials=self._test_proc_gh_cred)
        print(result)
        assert(result is not None)

        # get the descriptor
        result = self._rti.get_gpp(self._test_proc_id)
        print(result)
        assert(result is not None)

        # get the status
        while True:
            result = self._rti.get_status(self._test_proc_id)
            assert(result is not None)

            if result.state not in ['starting', 'waiting', 'uninitialised']:
                assert False

            if result.state == 'waiting':
                break

            time.sleep(1)

        # undeploy the test processor
        result = self._rti.undeploy(self._test_proc_id)
        print(result)
        assert(result is not None)

        # try to get the status
        try:
            self._rti.get_status(self._test_proc_id)
            assert False

        except UnsuccessfulRequestError as e:
            assert('Processor not deployed' in e.reason)

    def test_rest_submit_get_job(self):
        # create an extra identity
        wrong_user = self.create_keystores(1)[0]
        self._node.db.update_identity(wrong_user.identity)

        deploy_and_wait(self._rti, self._test_proc_id, self._test_proc_gh_cred)

        owner = self._node.keystore

        task_input = [
            {'name': 'a', 'type': 'value', 'value': {'v': 1}},
            {'name': 'b', 'type': 'value', 'value': {'v': 2}}
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # submit the job
        result = self._rti.submit_job(self._test_proc_id, task_input, task_output, owner)
        print(result)
        assert(result is not None)

        job_id = result.id

        # get information about all jobs
        result = self._rti.get_jobs(self._test_proc_id)
        print(result)
        assert(result is not None)

        # try to get the job info as the wrong user
        try:
            self._rti.get_job_info(job_id, wrong_user)
            assert False

        except UnsuccessfulRequestError as e:
            assert(e.details['reason'] == 'user is not the job owner')

        while True:
            # get information about the running job
            job = self._rti.get_job_info(job_id, owner)
            print(job)
            assert(job is not None)

            state = State(job.status['state'])
            if state == State.SUCCESSFUL or state == State.FAILED:
                break

            time.sleep(1)

        # check if we have an object id for output object 'c'
        output = {item['name']: item['obj_id'] for item in job.status['output']}
        assert('c' in output)

        # get the contents of the output data object
        download_path = os.path.join(self.wd_path, 'c.json')
        self._dor.get_content(output['c'], owner, download_path)
        assert(os.path.isfile(download_path))

        with open(download_path, 'r') as f:
            content = json.load(f)
            print(content)
            assert(content['v'] == 3)

        download_path = os.path.join(self.wd_path, 'log.tar.gz')

        # try to get the job logs as the wrong user
        try:
            self._rti.get_job_logs(job_id, wrong_user, download_path)
            assert False

        except UnsuccessfulRequestError as e:
            assert(e.details['reason'] == 'user is not the job owner')
            assert(not os.path.isfile(download_path))

        self._rti.get_job_logs(job_id, owner, download_path)
        assert(os.path.isfile(download_path))

    def test_rest_job_logs(self):
        deploy_and_wait(self._rti, self._test_proc_id, self._test_proc_gh_cred)

        owner = self._node.keystore

        task_input = [
            {'name': 'a', 'type': 'value', 'value': {'v': 1}},
            {'name': 'b', 'type': 'value', 'value': {'v': 2}}
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # submit the job
        result = self._rti.submit_job(self._test_proc_id, task_input, task_output, owner)
        print(result)
        assert(result is not None)

        job_id = result.id

        # get information about all jobs
        result = self._rti.get_jobs(self._test_proc_id)
        print(result)
        assert(result is not None)

        while True:
            # get information about the running job
            job = self._rti.get_job_info(job_id, owner)
            print(job.status)
            assert(job.status is not None)

            state = State(job.status['state'])
            if state == State.SUCCESSFUL or state == State.FAILED:
                break

            time.sleep(1)

        # check if we have an object id for output object 'c'
        output = {item['name']: item['obj_id'] for item in job.status['output']}
        assert('c' in output)

        # get the contents of the output data object
        download_path = os.path.join(self.wd_path, 'c.json')
        self._dor.get_content(output['c'], owner, download_path)
        assert(os.path.isfile(download_path))

        with open(download_path, 'r') as f:
            content = json.load(f)
            print(content)
            assert(content['v'] == 3)

    def test_rest_put_permission(self):
        pass


class UnsuccessfulJob(SaaSException):
    def __init__(self, reason: str, details: dict) -> None:
        super().__init__(f"Unsuccessful job: {reason}", details=details)


def submit_job(rti: RTIProxy, proc_id: str, task_input: list[dict], task_output: list[dict], owner: Keystore) -> str:
    result = rti.submit_job(proc_id, task_input, task_output, owner)
    job_id = result.id
    return job_id


def wait_for_job(rti: RTIProxy, job_id: str, owner: Keystore) -> dict:
    while True:
        job = rti.get_job_info(job_id, owner)

        state = State(job.status['state'])
        if state == State.SUCCESSFUL:
            return {item['name']: item['obj_id'] for item in job.status['output']}

        elif state == State.FAILED:
            reason = 'unknown'
            details = {}
            lines = job.status['error'].split('\n')
            for line in lines:
                if ': ' in line:
                    idx = line.find(': ')
                    line = [line[:idx], line[idx+2:]]
                    if line[0] == 'reason':
                        reason = line[1]

                    elif line[0] == 'details':
                        # correct JSON quotes
                        rstr = ""
                        escaped = False
                        for c in line[1]:
                            if c == "'" and not escaped:
                                c = '"'

                            elif c == "'" and escaped:
                                rstr = rstr[:-1]

                            elif c == '"':
                                c = '\\' + c

                            escaped = (c == "\\")
                            rstr += c

                        try:
                            details = json.loads(rstr)
                        except JSONDecodeError:
                            details = {
                                'as_string': line[1]
                            }
                        except Exception as e:
                            print(e)

            raise UnsuccessfulJob(f"Job failed: {reason}", details=details)

        time.sleep(1)


def submit_and_wait(rti: RTIProxy, proc_id: str, task_input: list[dict], task_output: list[dict],
                    owner: Keystore) -> (str, dict):
    job_id = submit_job(rti, proc_id, task_input, task_output, owner)
    output = wait_for_job(rti, job_id, owner)
    return job_id, output


class RTIServiceTestCase(unittest.TestCase, TestCaseBase):
    _wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))
    _node = None
    _rti = None
    _dor = None
    _db = None
    _test_proc_id = None
    _test_proc_gh_cred = None
    _known_user0 = None

    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    @classmethod
    def tearDownClass(cls):
        if cls._node is not None:
            shutil.rmtree(cls._wd_path, ignore_errors=True)
            cls._node.shutdown(leave_network=False)

    def setUp(self):
        self.initialise()

        if RTIServiceTestCase._node is None:
            RTIServiceTestCase._node = self.get_node('node', enable_rest=True, keep_track=False,
                                                     wd_path=RTIServiceTestCase._wd_path)
            RTIServiceTestCase._rti = RTIProxy(RTIServiceTestCase._node.rest.address())
            RTIServiceTestCase._dor = DORProxy(RTIServiceTestCase._node.rest.address())
            RTIServiceTestCase._db = NodeDBProxy(RTIServiceTestCase._node.rest.address())
            time.sleep(1)

            RTIServiceTestCase._test_proc_id, RTIServiceTestCase._test_proc_gh_cred = add_test_processor(
                RTIServiceTestCase._dor, RTIServiceTestCase._node.keystore, 'default')

            deploy_and_wait(
                RTIServiceTestCase._rti, RTIServiceTestCase._test_proc_id, RTIServiceTestCase._test_proc_gh_cred)

            extras = self.create_keystores(1)
            RTIServiceTestCase._known_user0 = extras[0]

            RTIServiceTestCase._node.db.update_identity(RTIServiceTestCase._known_user0.identity)

    def tearDown(self):
        self.cleanup()

    def handle_content_key_request(self, owner: Keystore, status_path: str, content_key: str):
        while True:
            time.sleep(1)

            job_status = read_json_from_file(status_path)
            if 'requests' in job_status:
                for r in job_status['requests']:
                    # we should be able to decrypt it
                    request = owner.decrypt(r['request'].encode('utf-8')).decode('utf-8')
                    request = json.loads(request)
                    print(request)

                    # get the ephemeral key and encrypt the content key with the ephemeral key
                    key = RSAKeyPair.from_public_key_string(request['ephemeral_public_key'])
                    c_key = owner.decrypt(content_key.encode('utf-8')).decode('utf-8')
                    c_key = key.encrypt(c_key.encode('utf-8'), base64_encoded=True).decode('utf-8')

                    # submit the content key
                    self._rti.put_permission(r['req_id'], c_key)

                    return

    def test_processor_execution_value(self):
        owner = self._node.keystore

        task_input = [
            {'name': 'a', 'type': 'value', 'value': {'v': 1}},
            {'name': 'b', 'type': 'value', 'value': {'v': 2}}
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # submit and wait
        job_id, output = submit_and_wait(self._rti, self._test_proc_id, task_input, task_output, owner)
        assert(output is not None)
        assert('c' in output)

    def test_processor_execution_specific_target_node(self):
        # create target node and join with the default node
        target_node = self.get_node('target', enable_rest=True)
        target_node.join_network(self._node.p2p.address())
        target_dor = DORProxy(target_node.rest.address())
        time.sleep(2)

        owner = self._node.keystore

        task_input = [
            {'name': 'a', 'type': 'value', 'value': {'v': 1}},
            {'name': 'b', 'type': 'value', 'value': {'v': 2}}
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False,
             'target_node_iid': target_node.identity.id}
        ]

        # submit and wait
        job_id, output = submit_and_wait(self._rti, self._test_proc_id, task_input, task_output, owner)
        assert(output is not None)
        assert('c' in output)

        # the output data object should be with the target node
        meta = self._dor.get_meta(output['c'])
        assert(meta is None)

        meta = target_dor.get_meta(output['c'])
        assert(meta is not None)

        target_node.shutdown()
        time.sleep(2)

    def test_processor_execution_reference_unrestricted(self):
        owner = self._node.keystore

        # add test data object
        meta = self._dor.add_data_object(self.create_file_with_content(f"{generate_random_string(4)}.json",
                                                                       json.dumps({'v': 1})),
                                         owner.identity, False, False, 'JSONObject', 'json')
        a_obj_id = meta.obj_id

        task_input = [
            {'name': 'a', 'type': 'reference', 'obj_id': a_obj_id},
            {'name': 'b', 'type': 'value', 'value': {'v': 2}}
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # submit and wait
        job_id, output = submit_and_wait(self._rti, self._test_proc_id, task_input, task_output, owner)
        assert(output is not None)
        assert('c' in output)

    def test_provenance(self):
        owner = self._node.keystore

        # add test data object
        meta = self._dor.add_data_object(self.create_file_with_content(f"{generate_random_string(4)}.json",
                                                                       json.dumps({'v': 1})),
                                         owner.identity, False, False, 'JSONObject', 'json')
        obj_id, c_hash = meta.obj_id, meta.c_hash

        obj_id_a = obj_id
        obj_id_b = obj_id
        c_hash_a = c_hash
        c_hash_b = c_hash

        # run 3 iterations
        log = []
        for i in range(3):
            task_input = [
                {'name': 'a', 'type': 'reference', 'obj_id': obj_id_a},
                {'name': 'b', 'type': 'value', 'value': {'v': 5}}
            ]

            task_output = [
                {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
            ]

            # submit and wait
            job_id, output = submit_and_wait(self._rti, self._test_proc_id, task_input, task_output, owner)
            assert (output is not None)
            assert ('c' in output)
            obj_id = output['c']

            # get the c_hash for output object 'c'
            meta = self._dor.get_meta(obj_id)
            c_hash = meta.c_hash

            log.append((c_hash_a, c_hash_b, c_hash))

            obj_id_a = obj_id_b
            obj_id_b = obj_id
            c_hash_a = c_hash_b
            c_hash_b = c_hash

        for item in log:
            print(f"{item[0]} + {item[1]} = {item[2]}")

        # get the provenance and print it
        provenance = self._dor.get_provenance(log[2][2])
        assert(provenance is not None)
        print(json.dumps(provenance.dict(), indent=2))

    def test_processor_execution_same_reference(self):
        # test for issue #110: https://github.com/cooling-singapore/saas-middleware/issues/110

        owner = self._node.keystore

        # add test data object
        meta = self._dor.add_data_object(self.create_file_with_content(f"{generate_random_string(4)}.json",
                                                                       json.dumps({'v': 1})),
                                         owner.identity, False, False, 'JSONObject', 'json')
        a_obj_id = meta.obj_id

        task_input = [
            {'name': 'a', 'type': 'reference', 'obj_id': a_obj_id},
            {'name': 'b', 'type': 'reference', 'obj_id': a_obj_id},
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # submit and wait
        job_id, output = submit_and_wait(self._rti, self._test_proc_id, task_input, task_output, owner)
        assert(output is not None)
        assert('c' in output)

        input_path_a = os.path.join(self.wd_path, self._node.datastore, 'jobs', str(job_id), 'a')
        input_path_b = os.path.join(self.wd_path, self._node.datastore, 'jobs', str(job_id), 'b')
        output_path = os.path.join(self.wd_path, self._node.datastore, 'jobs', str(job_id), 'c')
        assert(os.path.isfile(input_path_a))
        assert(os.path.isfile(input_path_b))
        assert(os.path.isfile(output_path))

    def test_processor_execution_reference_restricted(self):
        owner = self._node.keystore
        rti_node_info = self._db.get_node()

        # add test data object
        meta = self._dor.add_data_object(self.create_file_with_content(f"{generate_random_string(4)}.json",
                                                                       json.dumps({'v': 1})),
                                         owner.identity, True, False, 'JSONObject', 'json')
        a_obj_id = meta.obj_id

        user = self._known_user0

        invalid_signature = user.sign(f"invalid content".encode('utf-8'))
        task_input_invalid = [
            {'name': 'a', 'type': 'reference', 'obj_id': a_obj_id, 'user_signature': invalid_signature},
            {'name': 'b', 'type': 'reference', 'obj_id': a_obj_id, 'user_signature': invalid_signature}
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # no access rights and no valid signature
        try:
            submit_and_wait(self._rti, self._test_proc_id, task_input_invalid, task_output, user)
            assert False

        except UnsuccessfulJob as e:
            assert('Identity does not have access to data object' in e.reason)

        # grant access
        self._dor.grant_access(a_obj_id, owner, user.identity)

        # access rights but invalid signature
        try:
            submit_and_wait(self._rti, self._test_proc_id, task_input_invalid, task_output, user)
            assert False

        except UnsuccessfulJob as e:
            assert('authorisation failed' in e.details['reason'])

        # create valid and invalid task input
        valid_signature = user.sign(f"{rti_node_info.identity.id}:{a_obj_id}".encode('utf-8'))
        task_input_valid = [
            {'name': 'a', 'type': 'reference', 'obj_id': a_obj_id, 'user_signature': valid_signature},
            {'name': 'b', 'type': 'reference', 'obj_id': a_obj_id, 'user_signature': valid_signature}
        ]

        # access rights and valid signature
        try:
            job_id, output = submit_and_wait(self._rti, self._test_proc_id, task_input_valid, task_output, user)
            assert('c' in output)

        except UnsuccessfulJob:
            assert False

    def test_processor_execution_reference_encrypted(self):
        owner = self._node.keystore

        # add encrypted test data object
        obj_path = self.create_file_with_content(f"{generate_random_string(4)}.json", json.dumps({'v': 1}))
        content_key = encrypt_file(obj_path, encrypt_for=owner.identity, delete_source=True)

        meta = self._dor.add_data_object(obj_path, owner.identity, False, True, 'JSONObject', 'json')
        obj_id = meta.obj_id

        task_input = [
            {'name': 'a', 'type': 'reference', 'obj_id': obj_id},
            {'name': 'b', 'type': 'reference', 'obj_id': obj_id},
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # submit the job
        job_id = submit_job(self._rti, self._test_proc_id, task_input, task_output, owner)

        # determine the status path
        status_path = os.path.join(self._node.datastore, 'jobs', job_id, 'job_status.json')
        assert(os.path.isfile(status_path))

        # run monitoring thread
        thread = Thread(target=self.handle_content_key_request, args=[owner, status_path, content_key])
        thread.start()

        # wait for the job to finish
        output = wait_for_job(self._rti, job_id, owner)
        assert('c' in output)

    def test_docker_processor_execution_value(self):
        pass

    def test_retain_job_history_false(self):
        # create target node and join with the default node
        target_node = self.get_node('target', enable_rest=True, retain_job_history=False)
        target_rti = RTIProxy(target_node.rest.address())
        target_dor = DORProxy(target_node.rest.address())
        time.sleep(2)

        owner = target_node.keystore

        # add test proc and deploy
        proc_id, gh_cred = add_test_processor(target_dor, owner, 'default')
        deploy_and_wait(target_rti, proc_id, gh_cred)

        task_input = [
            {'name': 'a', 'type': 'value', 'value': {'v': 1}},
            {'name': 'b', 'type': 'value', 'value': {'v': 2}}
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # submit and wait
        job_id, output = submit_and_wait(target_rti, proc_id, task_input, task_output, owner)
        assert(output is not None)
        assert('c' in output)

        # check if the output path exists
        output_path = os.path.join(self.wd_path, target_node.datastore, 'jobs', str(job_id), 'c')
        assert not os.path.isfile(output_path)  # retain is False, so the path shouldn't exist!

        target_node.shutdown()
        time.sleep(2)

    def test_retain_job_history_true(self):
        # create target node and join with the default node
        target_node = self.get_node('target', enable_rest=True, retain_job_history=True)
        target_rti = RTIProxy(target_node.rest.address())
        target_dor = DORProxy(target_node.rest.address())
        time.sleep(2)

        owner = target_node.keystore

        # add test proc and deploy
        proc_id, gh_cred = add_test_processor(target_dor, owner, 'default')
        deploy_and_wait(target_rti, proc_id, gh_cred)

        task_input = [
            {'name': 'a', 'type': 'value', 'value': {'v': 1}},
            {'name': 'b', 'type': 'value', 'value': {'v': 2}}
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # submit and wait
        job_id, output = submit_and_wait(target_rti, proc_id, task_input, task_output, owner)
        assert(output is not None)
        assert('c' in output)

        # check if the output path exists
        output_path = os.path.join(self.wd_path, target_node.datastore, 'jobs', str(job_id), 'c')
        assert os.path.isfile(output_path)  # retain is False, so the path shouldn't exist!

        target_node.shutdown()
        time.sleep(2)


class RTIServiceTestCaseNSCC(unittest.TestCase, TestCaseBase):
    _wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))
    _node = None
    _rti = None
    _dor = None
    _test_proc_id = None
    _test_proc_gh_cred = None
    _nscc_ssh_cred = None

    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    @classmethod
    def tearDownClass(cls):
        if cls._node is not None:
            shutil.rmtree(cls._wd_path, ignore_errors=True)
            cls._node.shutdown(leave_network=False)

    def setUp(self):
        self.initialise()

        if RTIServiceTestCaseNSCC._node is None:
            RTIServiceTestCaseNSCC._node = self.get_node('node', enable_rest=True, keep_track=False,
                                                         wd_path=RTIServiceTestCaseNSCC._wd_path)
            RTIServiceTestCaseNSCC._rti = RTIProxy(RTIServiceTestCaseNSCC._node.rest.address())
            RTIServiceTestCaseNSCC._dor = DORProxy(RTIServiceTestCaseNSCC._node.rest.address())
            time.sleep(1)

            # extract the NSCC SSH credentials
            authority = RTIServiceTestCaseNSCC._node.keystore
            asset: CredentialsAsset = authority.get_asset('ssh-credentials')
            RTIServiceTestCaseNSCC._nscc_ssh_cred = asset.get('nscc')

            RTIServiceTestCaseNSCC._test_proc_id, RTIServiceTestCaseNSCC._test_proc_gh_cred = add_test_processor(
                RTIServiceTestCaseNSCC._dor, RTIServiceTestCaseNSCC._node.keystore, 'nscc')

    def tearDown(self):
        self.cleanup()

    def test_deployment_undeployment(self):
        # instruct the RTI to deploy the processor remotely using the SSH credentials
        self._rti.deploy(self._test_proc_id, github_credentials=self._test_proc_gh_cred,
                         ssh_credentials=self._nscc_ssh_cred)

        # wait for processor to be deployed
        while (state := ProcessorState(
                self._rti.get_status(self._test_proc_id).get('state'))) == ProcessorState.STARTING:
            logger.info(f"Waiting for processor to deploy. {state.name=}")
            time.sleep(5)
        logger.info(f"Processor to deployed. {state.name=}")

        # get the deployed processors
        result = self._rti.get_deployed()
        assert(result is not None)
        assert(len(result) == 1)
        assert(result[0].proc_id == self._test_proc_id)

        # undeploy the processor
        result = self._rti.undeploy(self._test_proc_id)
        assert(result is not None)

    def test_processor_execution_mixed(self):
        # instruct the RTI to deploy the processor remotely using the SSH credentials
        self._rti.deploy(self._test_proc_id, github_credentials=self._test_proc_gh_cred,
                         ssh_credentials=self._nscc_ssh_cred)

        # wait for processor to be deployed
        while (state := ProcessorState(
                self._rti.get_status(self._test_proc_id).get('state'))) == ProcessorState.STARTING:
            logger.info(f"Waiting for processor to deploy. {state.name=}")
            time.sleep(5)
        logger.info(f"Processor to deployed. {state.name=}")

        # add test data object
        owner = self._node.keystore
        meta = self._dor.add_data_object(self.create_file_with_content(f"{generate_random_string(4)}.json",
                                                                       json.dumps({'v': 1})),
                                         owner.identity, False, False, 'JSONObject', 'json')
        a_obj_id = meta.obj_id

        task_input = [
            {'name': 'a', 'type': 'reference', 'obj_id': a_obj_id},
            {'name': 'b', 'type': 'value', 'value': {'v': 2}}
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # submit and wait
        job_id, output = submit_and_wait(self._rti, self._test_proc_id, task_input, task_output, owner)
        assert(output is not None)
        assert('c' in output)

    def test_processor_resume_execution(self):
        # instruct the RTI to deploy the processor remotely using the SSH credentials
        self._rti.deploy(self._test_proc_id, github_credentials=self._test_proc_gh_cred,
                         ssh_credentials=self._nscc_ssh_cred)

        # wait for processor to be deployed
        while (state := ProcessorState(
                self._rti.get_status(self._test_proc_id).get('state'))) == ProcessorState.STARTING:
            logger.info(f"Waiting for processor to deploy. {state.name=}")
            time.sleep(5)
        logger.info(f"Processor to deployed. {state.name=}")

        # add test data object
        owner = self._node.keystore
        meta = self._dor.add_data_object(self.create_file_with_content(f"{generate_random_string(4)}.json",
                                                                       json.dumps({'v': 1})),
                                         owner.identity, False, False, 'JSONObject', 'json')
        a_obj_id = meta['obj_id']

        task_input = [
            {'name': 'a', 'type': 'reference', 'obj_id': a_obj_id},
            {'name': 'b', 'type': 'value', 'value': {'v': 2}}
        ]

        task_output = [
            {'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False, 'content_encrypted': False}
        ]

        # submit and wait
        job_id, output = submit_and_wait(self._rti, self._test_proc_id, task_input, task_output, owner)
        assert (output is not None)
        assert ('c' in output)

        # attempt to resume the job. note: this should work even though the job has already finished. we just
        # need to provide valid reconnect info.
        descriptor, status, reconnect_info = self._rti.get_job_info(job_id)
        assert(reconnect_info is not None)

        # manually delete the remote exitcode file (we want to pretend the process hasn't finished yet)
        exitcode_path = reconnect_info['pid_paths']['exitcode']
        run_command(f"mv {exitcode_path} {exitcode_path}.backup", ssh_credentials=self._nscc_ssh_cred)

        job_descriptor = self._rti.resume_job(self._test_proc_id, reconnect_info)
        job_id = job_descriptor.id
        logger.info(f"job_id={job_id}")
        assert (job_id is not None)

        def recreate_exitcode_file():
            # wait 10 seconds until pretending for the process to have completed
            time.sleep(10)
            print('finishing now!!!')
            run_command(f"mv {exitcode_path}.backup {exitcode_path}", ssh_credentials=self._nscc_ssh_cred)

        # the following wait would never return because the process didn't really get timed-out. it actually finished
        # and we just 'resumed' it after renaming the exitcode file. unless the exitcode file is renamed back to what
        # it was, the wait will not return. so we start a thread which will wait for some time and then move the file
        # back to where it was.
        Thread(target=recreate_exitcode_file).start()
        wait_for_job(self._rti, job_id, owner)

        output_path = os.path.join(self.wd_path, self._node.datastore, 'jobs', str(job_id), 'c')
        assert os.path.isfile(output_path)


class RTIServiceTestCaseManual(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

    def tearDown(self):
        self.cleanup()

    def test_command_monitoring(self):
        # load keystore with credentials and extract SSH credentials
        keystore: Keystore = self.create_keystores(1, use_credentials=True)[0]
        asset: CredentialsAsset = keystore.get_asset('ssh-credentials')
        ssh_credentials: SSHCredentials = asset.get('nscc')

        wd_path = self.wd_path
        command_ok = "ls"
        command_fail = "ls x"

        # (1) Local + OK
        try:
            pid, paths = run_command_async(command_ok, wd_path, 'test1')
            monitor_command(pid, paths)
            assert True
        except RunCommandError as e:
            print(e)
            assert False

        # (2) Local + Fail
        try:
            pid, paths = run_command_async(command_fail, wd_path, 'test2')
            monitor_command(pid, paths)
            assert False
        except RunCommandError as e:
            print(e)
            assert True

        # (3) Remote + OK
        try:
            pid, paths = run_command_async(command_ok, wd_path, 'test3', ssh_credentials=ssh_credentials)
            monitor_command(pid, paths, ssh_credentials=ssh_credentials)
            assert True
        except RunCommandError as e:
            print(e)
            assert False

        # (4) Remote + Fail
        try:
            pid, paths = run_command_async(command_fail, wd_path, 'test4', ssh_credentials=ssh_credentials)
            monitor_command(pid, paths, ssh_credentials=ssh_credentials)
            assert False
        except RunCommandError as e:
            print(e)
            assert True

    def test_simulate_vpn_disconnect(self):
        # load keystore with credentials and extract SSH credentials
        keystore: Keystore = self.create_keystores(1, use_credentials=True)[0]
        asset: CredentialsAsset = keystore.get_asset('ssh-credentials')
        ssh_credentials: SSHCredentials = asset.get('nscc')

        wd_path = self.wd_path
        command = "sleep 60"

        try:
            pid, paths = run_command_async(command, wd_path, 'test_sleep', ssh_credentials=ssh_credentials)
            monitor_command(pid, paths, ssh_credentials=ssh_credentials)
            assert True
        except RunCommandError as e:
            print(e)
            assert False


if __name__ == '__main__':
    unittest.main()
