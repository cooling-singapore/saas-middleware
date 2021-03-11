import json
import os
import tempfile
import unittest

from saas.node import Node
from saas.rti.adapters import RTIDockerProcessorAdapter
from tests.test_rti import create_dummy_docker_processor


class DockerProcessor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        image_path, descriptor_path, cleanup_func = create_dummy_docker_processor('proc_dummy_script.py')
        cls.image_path = image_path
        cls.descriptor_path = descriptor_path
        cls.cleanup_docker_files = cleanup_func

        with open(cls.descriptor_path) as f:
            cls.docker_descriptor = json.load(f)

    @classmethod
    def tearDownClass(cls):
        cls.cleanup_docker_files()

    def setUp(self):
        # Create a temporary directory
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = os.path.join(self.temp_dir.name, 'data')
        self.working_dir = os.path.join(self.data_dir, 'jobs', 'test')

        os.makedirs(self.working_dir)
        self.a_data_path = os.path.join(self.working_dir, "a")
        with open(self.a_data_path, 'w') as f:
            json.dump({'v': 1}, f)

        self.b_data_path = os.path.join(self.working_dir, "b")
        with open(self.b_data_path, 'w') as f:
            json.dump({'v': 2}, f)

    def tearDown(self):
        # Remove the directory after the test
        self.temp_dir.cleanup()

    def test_docker_processor_execute(self):
        node = Node('test', self.data_dir, '127.0.0.1:5000')
        node.initialise_identity('test')
        node.start_server(('127.0.0.1', 5050))
        node.initialise_registry(('127.0.0.1', 5050))

        processor = RTIDockerProcessorAdapter('test', self.docker_descriptor, self.image_path, node.rti)

        processor.startup()
        processor.execute(None, self.working_dir, None)

        c_data_path = os.path.join(self.working_dir, "c")
        with open(c_data_path, 'r') as f:
            c = json.load(f)
            c_result = c.get('v')
        self.assertEqual(3, c_result)

        processor.shutdown()
        node.stop_server()


if __name__ == '__main__':
    unittest.main()
