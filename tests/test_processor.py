import json
import os
import unittest
import tempfile
import shutil

from saas.node import Node
from saas.rti.adapters import RTIDockerProcessorAdapter
from saas.rti.rti import RuntimeInfrastructure


class DockerProcessor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.descriptor_path = os.path.realpath('./docker_processor/docker_descriptor.json')
        cls.image_path = os.path.realpath('./docker_processor/docker_processor.tar.gz')

        with open(cls.descriptor_path) as f:
            cls.docker_descriptor = json.load(f)

    def setUp(self):
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()
        self.data_dir = os.path.join(self.test_dir, 'data')
        self.working_dir = os.path.join(self.data_dir, 'jobs', 'test')

        os.makedirs(self.working_dir)
        self.a_data_path = os.path.join(self.working_dir, "a")
        with open(self.a_data_path, 'w') as f:
            json.dump(2, f)

    def tearDown(self):
        # Remove the directory after the test
        shutil.rmtree(self.test_dir)

    def test_docker_processor_execute(self):
        test_task_descriptor = {"input": [{"name": "a", "data_type": "integer", "data_format": "json"}]}

        node = Node('test', self.data_dir, '127.0.0.1:5000')
        node.initialise_identity('test')
        node.start_server(('127.0.0.1', 5050))
        node.initialise_registry(('127.0.0.1', 5050))

        rti = RuntimeInfrastructure(node)
        processor = RTIDockerProcessorAdapter(self.docker_descriptor, self.image_path, rti)

        processor.startup()
        processor.execute(test_task_descriptor, self.working_dir, None)

        b_data_path = os.path.join(self.working_dir, "b")
        with open(b_data_path, 'r') as f:
            b_result = json.load(f)
        self.assertEqual('4', b_result)

        processor.shutdown()
        node.stop_server()


if __name__ == '__main__':
    unittest.main()
