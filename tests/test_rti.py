import unittest
import logging
import time
import os
import time
import json
import requests


from tests.testing_environment import TestingEnvironment
from tests.dummy_script import descriptor as dummy_script_descriptor
from saas.eckeypair import hash_file_content
from saas.utilities.general_helpers import all_in_dict
from saas.utilities.blueprint_helpers import create_authentication, create_authorisation
from saas.node import Node
from saas.dor.protocol import DataObjectRepositoryP2PProtocol

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

env = TestingEnvironment.get_instance('../config/testing-config.json')
logger = logging.getLogger(__name__)


def add_dummy_processor(sender, owner):
    url = "http://127.0.0.1:5000/repository"
    body = {
        'type': 'processor',
        'owner_public_key': owner.public_as_string(),
        'descriptor': dummy_script_descriptor
    }

    script_path = './dummy_script.py'

    authentication = create_authentication('POST:/repository', sender, body, script_path)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(script_path, 'rb') as f:
        r = requests.post(url, data=content, files={'attachment': f.read()}).json()
        return r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None


def add_docker_processor(sender, owner):
    url = "http://127.0.0.1:5000/repository"
    with open('./docker_processor/docker_descriptor.json') as f:
        docker_descriptor = json.load(f)

    body = {
        'type': 'processor',
        'owner_public_key': owner.public_as_string(),
        'descriptor': docker_descriptor
    }

    docker_path = './docker_processor/docker_processor.tar.gz'
    authentication = create_authentication('POST:/repository', sender, body, docker_path)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(docker_path, 'rb') as f:
        attachment = f.read()

    r = requests.post(url, data=content, files={'attachment': attachment}).json()
    return r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None


def delete_data_object(sender, obj_id, owner):
    url = f"http://127.0.0.1:5000/repository/{obj_id}"
    authentication = create_authentication(f"DELETE:/repository/{obj_id}", sender)
    authorisation = create_authorisation(f"DELETE:/repository/{obj_id}", owner)
    content = {
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content).json()
    return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None


def get_deployed(sender):
    url = "http://127.0.0.1:5000/processor"
    authentication = create_authentication("GET:/processor", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['deployed'] if 'deployed' in r['reply'] else None


def deploy(sender, proc_id):
    url = f"http://127.0.0.1:5000/processor/{proc_id}"
    authentication = create_authentication(f"POST:/processor/{proc_id}", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.post(url, data=content).json()
    return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None


def undeploy(sender, proc_id):
    url = f"http://127.0.0.1:5000/processor/{proc_id}"
    authentication = create_authentication(f"DELETE:/processor/{proc_id}", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    requests.delete(url, data=content).json()


def add_data_object_a(sender, owner):
    url = "http://127.0.0.1:5000/repository"
    body = {
        'type': 'data_object',
        'owner_public_key': owner.public_as_string(),
        'descriptor': {
            'data_type': 'integer',
            'data_format': 'json',
            'created_t': 21342342,
            'created_by': 'heiko'
        }
    }
    test_file_path = env.create_file_with_content('a.dat', "\"1\"")
    test_obj_id = '26c4fa19e1fe35863d85f1b43c8ffd84b49f4b80683dba7762ab3e33af258c5f'

    authentication = create_authentication('POST:/repository', sender, body, test_file_path)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(test_file_path, 'rb') as f:
        r = requests.post(url, data=content, files={'attachment': f.read()}).json()
        return test_obj_id, r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None


def submit_job_value(sender, owner, proc_id):
    url = f"http://127.0.0.1:5000/processor/{proc_id}/jobs"
    body = {
        'type': 'task',
        'descriptor': {
            'processor_id': proc_id,
            'input': [
                {
                    'name': 'a',
                    'type': 'value',
                    'data_type': 'integer',
                    'data_format': 'json',
                    'value': '1'
                },
                {
                    'name': 'b',
                    'type': 'value',
                    'data_type': 'integer',
                    'data_format': 'json',
                    'value': '2'
                }
            ],
            'output': {
                'owner_public_key': owner.public_as_string()
            }
        }
    }

    authentication = create_authentication(f"POST:/processor/{proc_id}/jobs", sender, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.post(url, data=content).json()
    return r['reply']['job_id'] if 'job_id' in r['reply'] else None


def submit_job_reference(sender, owner, proc_id, a_obj_id):
    url = "http://127.0.0.1:5000/processor/{proc_id}/jobs"
    body = {
        'type': 'task',
        'descriptor': {
            'processor_id': proc_id,
            'input': [
                {
                    'name': 'a',
                    'type': 'reference',
                    'obj_id': a_obj_id
                },
                {
                    'name': 'b',
                    'type': 'value',
                    'data_type': 'integer',
                    'data_format': 'json',
                    'value': '2'
                }
            ],
            'output': {
                'owner_public_key': owner.public_as_string()
            }
        }
    }

    authentication = create_authentication("POST:/processor/{proc_id}/jobs", sender, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.post(url, data=content).json()
    return r['reply']['job_id'] if 'job_id' in r['reply'] else None


def submit_job_wofklow(sender, owner, proc_id, obj_id_a):
    url = "http://127.0.0.1:5000/processor/workflow/jobs"
    body = {
        'type': 'workflow',
        'descriptor': {
            'name': 'c = ((a+b) + (a+b))',
            'tasks': [
                {
                    'name': 'task0',
                    'processor_id': proc_id,
                    'input': [
                        {
                            'name': 'a',
                            'type': 'reference',
                            'obj_id': obj_id_a
                        },
                        {
                            'name': 'b',
                            'type': 'value',
                            'data_type': 'integer',
                            'data_format': 'json',
                            'value': '2'
                        }
                    ],
                    'output': {
                        'owner_public_key': owner.public_as_string()
                    }
                },
                {
                    'name': 'task1',
                    'processor_id': proc_id,
                    'input': [
                        {
                            'name': 'a',
                            'type': 'reference',
                            'obj_id': obj_id_a
                        },
                        {
                            'name': 'b',
                            'type': 'value',
                            'data_type': 'integer',
                            'data_format': 'json',
                            'value': '2'
                        }
                    ],
                    'output': {
                        'owner_public_key': owner.public_as_string()
                    }
                },
                {
                    'name': 'task2',
                    'processor_id': proc_id,
                    'input': [
                        {
                            'name': 'a',
                            'type': 'reference',
                            'obj_id': 'label:task0:c'
                        },
                        {
                            'name': 'b',
                            'type': 'reference',
                            'obj_id': 'label:task1:c'
                        }
                    ],
                    'output': {
                        'owner_public_key': owner.public_as_string()
                    }
                }
            ]
        }
    }

    authentication = create_authentication("POST:/processor/workflow/jobs", sender, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.post(url, data=content).json()
    return r['reply']['job_id'] if 'job_id' in r['reply'] else None


def get_jobs(sender, proc_id):
    url = f"http://127.0.0.1:5000/processor/{proc_id}/jobs"
    authentication = create_authentication(f"GET:/processor/{proc_id}/jobs", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['jobs'] if 'jobs' in r['reply'] else None


def get_job(sender, proc_id, job_id):
    url = f"http://127.0.0.1:5000/processor/{proc_id}/jobs/{job_id}"
    authentication = create_authentication(f"GET:/processor/{proc_id}/jobs/{job_id}", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return (r['reply']['job_descriptor'], r['reply']['status']) \
        if all_in_dict(['job_descriptor', 'status'], r['reply']) else None


class RTITestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env.start_flask_app()

    @classmethod
    def tearDownClass(cls):
        env.stop_flask_app()

    def setUp(self):
        env.prepare_working_directory()
        self.keys = env.generate_keys(3)

    def tearDown(self):
        pass

    def test_deployment_undeployment(self):
        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 1
        assert 'workflow' in deployed

        proc_id = add_dummy_processor(self.keys[0], self.keys[1])
        logger.info(f"proc_id={proc_id}")

        descriptor = deploy(self.keys[0], proc_id)
        logger.info(f"descriptor={descriptor}")

        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 2
        assert 'workflow' in deployed
        assert proc_id in deployed

        undeploy(self.keys[0], proc_id)

        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 1
        assert 'workflow' in deployed

    def test_processor_execution_value(self):
        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 1
        assert 'workflow' in deployed

        proc_id = add_dummy_processor(self.keys[0], self.keys[1])
        logger.info(f"proc_id={proc_id}")

        descriptor = deploy(self.keys[0], proc_id)
        logger.info(f"descriptor={descriptor}")

        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 2
        assert 'workflow' in deployed
        assert proc_id in deployed

        jobs = get_jobs(self.keys[0], proc_id)
        logger.info(f"jobs={jobs}")
        assert jobs is not None
        assert len(jobs) == 0

        job_id = submit_job_value(self.keys[0], self.keys[1], proc_id)
        logger.info(f"job_id={job_id}")
        assert job_id is not None

        jobs = get_jobs(self.keys[0], proc_id)
        logger.info(f"jobs={jobs}")
        assert jobs is not None
        assert len(jobs) == 1

        while True:
            time.sleep(1)
            descriptor, status = get_job(self.keys[0], proc_id, job_id)
            logger.info(f"descriptor={descriptor}")
            logger.info(f"status={status}")
            if isinstance(status, dict) and 'status' in status and status['status'] != 'running':
                break

        jobs = get_jobs(self.keys[0], proc_id)
        logger.info(f"jobs={jobs}")
        assert jobs is not None
        assert len(jobs) == 0

        undeploy(self.keys[0], proc_id)

        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 1
        assert 'workflow' in deployed

    def test_processor_execution_reference(self):
        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 1
        assert 'workflow' in deployed

        proc_id = add_dummy_processor(self.keys[0], self.keys[1])
        logger.info(f"proc_id={proc_id}")

        descriptor = deploy(self.keys[0], proc_id)
        logger.info(f"descriptor={descriptor}")

        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 2
        assert 'workflow' in deployed
        assert proc_id in deployed

        jobs = get_jobs(self.keys[0], proc_id)
        logger.info(f"jobs={jobs}")
        assert jobs is not None
        assert len(jobs) == 0

        a_obj_id_ref, a_obj_id = add_data_object_a(self.keys[0], self.keys[1])
        logger.info(f"a_obj_id={a_obj_id}")
        assert a_obj_id == a_obj_id_ref

        job_id = submit_job_reference(self.keys[0], self.keys[1], proc_id, a_obj_id)
        logger.info(f"job_id={job_id}")
        assert job_id is not None

        jobs = get_jobs(self.keys[0], proc_id)
        logger.info(f"jobs={jobs}")
        assert jobs is not None
        assert len(jobs) == 1

        while True:
            time.sleep(1)
            descriptor, status = get_job(self.keys[0], proc_id, job_id)
            logger.info(f"descriptor={descriptor}")
            logger.info(f"status={status}")
            if isinstance(status, dict) and 'status' in status and status['status'] != 'running':
                break

        jobs = get_jobs(self.keys[0], proc_id)
        logger.info(f"jobs={jobs}")
        assert jobs is not None
        assert len(jobs) == 0

        undeploy(self.keys[0], proc_id)

        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 1
        assert 'workflow' in deployed

    def test_processor_workflow(self):
        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 1
        assert 'workflow' in deployed

        proc_id = add_dummy_processor(self.keys[0], self.keys[1])
        logger.info(f"proc_id={proc_id}")

        descriptor = deploy(self.keys[0], proc_id)
        logger.info(f"descriptor={descriptor}")

        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 2
        assert 'workflow' in deployed
        assert proc_id in deployed

        jobs = get_jobs(self.keys[0], proc_id)
        logger.info(f"jobs={jobs}")
        assert jobs is not None
        assert len(jobs) == 0

        a_obj_id_ref, obj_id_a = add_data_object_a(self.keys[0], self.keys[1])
        logger.info(f"obj_id_a={obj_id_a}")
        assert obj_id_a == a_obj_id_ref

        job_id = submit_job_wofklow(self.keys[0], self.keys[1], proc_id, obj_id_a)
        logger.info(f"job_id={job_id}")
        assert job_id is not None

        # jobs = get_jobs(self.keys[0], proc_id)
        # logger.info(f"jobs={jobs}")
        # assert jobs is not None
        # assert len(jobs) == 1

        while True:
            time.sleep(1)
            descriptor, status = get_job(self.keys[0], proc_id, job_id)
            logger.info(f"descriptor={descriptor}")
            logger.info(f"status={status}")
            if isinstance(status, dict) and 'status' in status and status['status'] != 'running':
                break

        jobs = get_jobs(self.keys[0], proc_id)
        logger.info(f"jobs={jobs}")
        assert jobs is not None
        assert len(jobs) == 0

        undeploy(self.keys[0], proc_id)

        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 1
        assert 'workflow' in deployed


class RTIDockerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env.start_flask_app()

    @classmethod
    def tearDownClass(cls):
        env.stop_flask_app()

    def setUp(self):
        env.prepare_working_directory()
        self.keys = env.generate_keys(3)

    def tearDown(self):
        pass

    def test_processor_execution_value(self):
        deployed = get_deployed(self.keys[0])
        logger.info(f"deployed={deployed}")
        assert deployed
        assert len(deployed) == 1
        assert 'workflow' in deployed

        proc_id = add_docker_processor(self.keys[0], self.keys[1])
        logger.info(f"proc_id={proc_id}")

        # descriptor = deploy(self.keys[0], proc_id)
        # logger.info(f"descriptor={descriptor}")
        #
        # job_id = submit_job_value(self.keys[0], self.keys[1], proc_id)
        # logger.info(f"job_id={job_id}")
        # assert job_id is not None
        #
        # jobs = get_jobs(self.keys[0], proc_id)
        # logger.info(f"jobs={jobs}")
        # assert jobs is not None
        # assert len(jobs) == 1
        #
        # while True:
        #     time.sleep(1)
        #     descriptor, status = get_job(self.keys[0], proc_id, job_id)
        #     logger.info(f"descriptor={descriptor}")
        #     logger.info(f"status={status}")
        #     if isinstance(status, dict) and 'status' in status and status['status'] != 'running':
        #         break
        #
        # jobs = get_jobs(self.keys[0], proc_id)
        # logger.info(f"jobs={jobs}")
        # assert jobs is not None
        # assert len(jobs) == 0
        #
        # undeploy(self.keys[0], proc_id)
        #
        # deployed = get_deployed(self.keys[0])
        # logger.info(f"deployed={deployed}")
        # assert deployed
        # assert len(deployed) == 1
        # assert 'workflow' in deployed


if __name__ == '__main__':
    unittest.main()
