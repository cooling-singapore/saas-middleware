import json
import logging
import os
import time
import unittest

import pip

from saas.cryptography.eckeypair import ECKeyPair
from saas.dor.blueprint import DORProxy
from saas.rti.adapters.adapters import import_with_auto_install
from saas.rti.adapters.workflow import TaskWrapper
from saas.rti.blueprint import RTIProxy
from saas.rti.status import State
from saas.utilities.general_helpers import dump_json_to_file, get_timestamp_now
from tests.base_testcase import TestCaseBase

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


def create_test_processor(output_directory):
    git_spec_path = os.path.join(output_directory, f"git_spec.json")
    dump_json_to_file({
        'source': 'https://github.com/cooling-singapore/saas-processor-template',
        'commit_id': '876b082',
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
    }, git_spec_path)

    descriptor = {
        'created_t': get_timestamp_now(),
        'created_by': 'test_user'
    }

    return git_spec_path, descriptor


class RTIServiceTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        self.node = self.get_node('node', enable_rest=True)
        self.proxy = RTIProxy(self.node.rest.address(), self.node.identity())

        self.keys = []
        for i in range(3):
            self.keys.append(ECKeyPair.create_new())
        logger.info(f"keys[0].iid={self.keys[0].iid}")
        logger.info(f"keys[1].iid={self.keys[1].iid}")
        logger.info(f"keys[2].iid={self.keys[2].iid}")

    def tearDown(self):
        self.cleanup()

    def deploy_test_processor(self, deployment="native"):
        proxy = DORProxy(self.node.rest.address(), self.node.identity())

        git_spec_path, descriptor = create_test_processor(self.wd_path)

        proc_id = proxy.add_processor(git_spec_path, self.keys[1], descriptor)
        self.proxy.deploy(proc_id, deployment)
        return proc_id

    def add_dummy_data_object(self, owner):
        proxy = DORProxy(self.node.rest.address(), self.node.identity())

        test_file_path = self.create_file_with_content('a.dat', json.dumps({'v': 1}))
        test_obj_id = 'c1cfe06853dae66d0340811947a7237d16983f5a4dbfa5608338eadfe423d3ae'

        data_type = 'JSONObject'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        return test_obj_id, proxy.add_data_object(test_file_path, owner, data_type, data_format, created_by, created_t)

    def wait_for_job(self, proc_id, job_id):
        while True:
            time.sleep(5)
            descriptor, status = self.proxy.get_job_info(proc_id, job_id)
            if descriptor and status:
                logger.info(f"descriptor={descriptor}")
                logger.info(f"status={status}")

                state = State.from_string(status['state'])
                if state == State.SUCCESSFUL:
                    break
                elif state == State.FAILED:
                    raise RuntimeError('Job failed')

    def test_deployment_undeployment(self):
        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert('workflow' in deployed)

        proc_id = self.deploy_test_processor()
        logger.info(f"proc_id={proc_id}")

        descriptor = self.proxy.get_descriptor(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert(descriptor is not None)

        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 2)
        assert('workflow' in deployed)
        assert(proc_id in deployed)

        self.proxy.undeploy(proc_id)

        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert('workflow' in deployed)

    def test_processor_execution_value(self):
        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert('workflow' in deployed)

        proc_id = self.deploy_test_processor()
        logger.info(f"proc_id={proc_id}")

        descriptor = self.proxy.get_descriptor(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert (descriptor is not None)

        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 2)
        assert('workflow' in deployed)
        assert(proc_id in deployed)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        proc_input = [
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

        job_id = self.proxy.submit_job(proc_id, proc_input, self.keys[1])
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        self.wait_for_job(proc_id, job_id)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, self.node.datastore(), 'jobs', str(job_id), 'c')
        assert os.path.isfile(output_path)

        self.proxy.undeploy(proc_id)

        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert('workflow' in deployed)

    def test_processor_execution_reference(self):
        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert('workflow' in deployed)

        proc_id = self.deploy_test_processor()
        logger.info(f"proc_id={proc_id}")

        descriptor = self.proxy.get_descriptor(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert (descriptor is not None)

        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 2)
        assert('workflow' in deployed)
        assert(proc_id in deployed)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        a_obj_id_ref, a_obj_id = self.add_dummy_data_object(self.keys[1])
        logger.info(f"a_obj_id={a_obj_id}")
        assert a_obj_id == a_obj_id_ref

        proc_input = [
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

        job_id = self.proxy.submit_job(proc_id, proc_input, self.keys[1])
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        self.wait_for_job(proc_id, job_id)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, self.node.datastore(), 'jobs', str(job_id), 'c')
        assert(os.path.isfile(output_path))

        self.proxy.undeploy(proc_id)

        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert('workflow' in deployed)

    def test_processor_workflow(self):
        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert('workflow' in deployed)

        proc_id = self.deploy_test_processor()
        logger.info(f"proc_id={proc_id}")

        descriptor = self.proxy.get_descriptor(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert (descriptor is not None)

        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 2)
        assert('workflow' in deployed)
        assert(proc_id in deployed)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        a_obj_id_ref, obj_id_a = self.add_dummy_data_object(self.keys[1])
        logger.info(f"obj_id_a={obj_id_a}")
        assert obj_id_a == a_obj_id_ref

        tasks = [
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
                        'value': {
                            'v': 2
                        }
                    }
                ],
                'output': {
                    'owner_public_key': self.keys[1].public_as_string()
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
                        'value': {
                            'v': 2
                        }
                    }
                ],
                'output': {
                    'owner_public_key': self.keys[1].public_as_string()
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
                    'owner_public_key': self.keys[1].public_as_string()
                }
            }

        ]

        job_id = self.proxy.submit_workflow('c = ((a+b) + (a+b))', tasks)
        logger.info(f"job_id={job_id}")
        assert job_id is not None

        self.wait_for_job(proc_id, job_id)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        self.proxy.undeploy(proc_id)

        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert('workflow' in deployed)

    def test_docker_processor_execution_value(self):
        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert('workflow' in deployed)

        proc_id = self.deploy_test_processor("docker")
        logger.info(f"proc_id={proc_id}")

        descriptor = self.proxy.get_descriptor(proc_id)
        logger.info(f"descriptor={descriptor}")
        assert (descriptor is not None)

        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 2)
        assert('workflow' in deployed)
        assert(proc_id in deployed)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        proc_input = [
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

        job_id = self.proxy.submit_job(proc_id, proc_input, self.keys[1])
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 1)

        self.wait_for_job(proc_id, job_id)

        jobs = self.proxy.get_jobs(proc_id)
        logger.info(f"jobs={jobs}")
        assert(jobs is not None)
        assert(len(jobs) == 0)

        output_path = os.path.join(self.wd_path, self.node.datastore(), 'jobs', str(job_id), 'c')
        assert os.path.isfile(output_path)

        self.proxy.undeploy(proc_id)

        deployed = self.proxy.get_deployed()
        logger.info(f"deployed={deployed}")
        assert(deployed is not None)
        assert(len(deployed) == 1)
        assert('workflow' in deployed)

    def test_import_dependency(self):
        try:
            package = 'h5py'
            pip.main(['uninstall', '-y', package])

            import_with_auto_install(package)
            import h5py

            output_path = os.path.join(self.wd_path, 'test.hdf5')
            f = h5py.File(output_path, "w")
            f.close()

        except Exception as e:
            logger.error(e)
            assert False


class WorkflowTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        self.node = self.get_node('node', enable_rest=True)
        self.rti_proxy = RTIProxy(self.node.rest.address(), self.node.identity())
        self.dor_proxy = DORProxy(self.node.rest.address(), self.node.identity())
        self.owner = ECKeyPair.create_new()

    def tearDown(self):
        self.cleanup()

    # FIXME: Looks like duplicated code
    def deploy_dummy_processor(self):
        proxy = DORProxy(self.node.rest.address(), self.node.identity())

        git_spec_path, descriptor = create_test_processor(self.wd_path)

        proc_id = proxy.add_processor(git_spec_path, self.owner, descriptor)
        return proc_id, self.rti_proxy.deploy(proc_id)

    def test_deploy_dummy_processor(self):
        proc_id, descriptor = self.deploy_dummy_processor()
        print(proc_id)
        print(descriptor)
        assert(proc_id is not None)
        assert(descriptor is not None)

        deployed = self.rti_proxy.get_deployed()
        print(deployed)
        assert(deployed is not None)
        assert(len(deployed) == 2)
        assert(proc_id in deployed)

    def test_task_wrapper(self):
        proc_id, descriptor = self.deploy_dummy_processor()
        print(proc_id)
        print(descriptor)
        assert(proc_id is not None)
        assert(descriptor is not None)

        task_descriptor = {
            'name': 'test',
            'processor_id': proc_id,
            'input': [
                {
                    'name': 'a',
                    'type': 'value',
                    'value': {'v': 1.0}
                },
                {
                    'name': 'b',
                    'type': 'value',
                    'value': {'v': 2.0}
                }
            ],
            'output': {
                'owner_public_key': self.owner.public_as_string()
            }
        }

        task = TaskWrapper(self.node, task_descriptor)
        task.start()

        while not task.is_done:
            time.sleep(1)

        assert(task.is_successful is True)

        outputs = task.get_outputs()
        print(outputs)
        assert(outputs is not None)
        assert('c' in outputs)

        descriptor = self.dor_proxy.get_descriptor(outputs['c'])
        print(descriptor)
        assert(descriptor is not None)

        obj_path = os.path.join(self.wd_path, outputs['c'])
        self.dor_proxy.get_content(outputs['c'], self.owner, obj_path)
        with open(obj_path, 'r') as f:
            obj = json.loads(f.read())
            print(obj)
            assert(obj is not None)
            assert('v' in obj)
            assert(obj['v'] == 3.0)


if __name__ == '__main__':
    unittest.main()
