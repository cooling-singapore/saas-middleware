import json
import os
import sys
import time
import logging
import importlib
import socket

from threading import Lock, Thread
import docker
import docker.errors
import requests
import subprocess

from saas.cryptography.eckeypair import ECKeyPair
from saas.dor.blueprint import DORProxy
from saas.rti.status import State
from saas.utilities.general_helpers import dump_json_to_file, load_json_from_file

logger = logging.getLogger('rti.adapters')


def import_with_auto_install(package):
    try:
        return importlib.import_module(package)

    except ImportError:
        # pip.main doesn't seem to work on a GCE instance, call python3 directly instead
        # pip.main(['install', package])
        subprocess.check_output(['python3', '-m', 'pip', 'install', package])

    return importlib.import_module(package)


def find_open_port():
    """
    Use socket's built in ability to find an open port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        port = s.getsockname()[1]
    return port


class RTIProcessorAdapter(Thread):
    def __init__(self, proc_id, node):
        Thread.__init__(self, daemon=True)

        self._node = node
        self._proc_id = proc_id
        self._mutex = Lock()
        self._pending = []
        self._is_active = True

    def startup(self):
        return True

    def shutdown(self):
        return True

    def pre_execute(self, task_or_wf_descriptor, working_directory, status):
        return True

    def post_execute(self, task_or_wf_descriptor, working_directory, status):
        return True

    def execute(self, job_descriptor, working_directory, status):
        pass

    def add(self, job_descriptor, status):
        with self._mutex:
            if self._is_active:
                self._pending.append((job_descriptor, status))
                return True
            else:
                return False

    def get_pending(self):
        with self._mutex:
            return [job_descriptor for job_descriptor, _ in self._pending]

    def fetch_data_object(self, obj_id, input_content_path):
        return self._node.dor.fetch(obj_id, input_content_path)

    def push_output_data_object(self, output_descriptor, output_content_path, owner, task_descriptor):
        output_name = output_descriptor['name']
        data_type = output_descriptor['data_type']
        data_format = output_descriptor['data_format']
        # TODO: this should be changed to something meaningful
        created_by = 'unknown'

        proxy = DORProxy(self._node.rest.address(), self._node.identity())
        return proxy.add_data_object(output_content_path, owner, data_type, data_format, created_by,
                                     recipe=proxy.create_recipe(task_descriptor, output_name))

    def stop(self):
        logger.info(f"adapter {self._proc_id} received stop signal.")
        self._is_active = False

    def _wait_for_pending_job(self):
        while True:
            with self._mutex:
                # if the adapter has become inactive, return immediately.
                if not self._is_active:
                    return None

                # if there is a job, return it
                elif len(self._pending) > 0:
                    return self._pending.pop(0)

            time.sleep(0.2)

    def run(self):
        logger.info(f"adapter {self._proc_id} starting up...")
        self.startup()

        logger.info(f"adapter {self._proc_id} started up.")
        while self._is_active:
            # wait for a pending job (or for adapter to become inactive)
            job_descriptor, status = self._wait_for_pending_job()
            if not job_descriptor or not status:
                break

            # perform pre-execute routine
            task_or_wf_descriptor = job_descriptor['descriptor']
            wd_path = self._node.rti.get_job_wd(str(job_descriptor['id']))
            if not self.pre_execute(task_or_wf_descriptor, wd_path, status):
                status.update_state(State.FAILED)
                continue

            # instruct processor adapter to execute the job
            if not self.execute(task_or_wf_descriptor, wd_path, status):
                status.update_state(State.FAILED)
                continue

            # perform post-execute routine
            if not self.post_execute(task_or_wf_descriptor, wd_path, status):
                status.update_state(State.FAILED)
                continue

            status.update_state(State.SUCCESSFUL)

        logger.info(f"adapter {self._proc_id} shutting down...")
        self.shutdown()

        logger.info(f"adapter {self._proc_id} shut down.")


class RTITaskProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, proc_id, node):
        super().__init__(proc_id, node)

        self._input_interface = {}
        self._output_interface = {}

    def parse_io_interface(self, descriptor):
        for item in descriptor['input']:
            self._input_interface[item['name']] = item

        for item in descriptor['output']:
            self._output_interface[item['name']] = item

    def pre_execute(self, task_descriptor, working_directory, status):
        # fetch input data objects
        return self._fetch_input_data_objects(task_descriptor['input'], working_directory, status)

    def post_execute(self, task_descriptor, working_directory, status):
        # determine output object owner
        owner = ECKeyPair.from_public_key_string(task_descriptor['output']['owner_public_key'])
        if not owner:
            error = f"worker[{self.name}]: owner identity cannot be created from " \
                    f"public key '{task_descriptor['owner_public_key']}'"
            logger.error(error)
            status.update('error', error)
            return False

        # push output data objects to DOR
        if not self._push_output_data_objects(owner, working_directory, task_descriptor, status):
            return False

        return True

    def _fetch_input_data_objects(self, input_interface, wd_path, status):
        status.update('stage', 'fetch input data objects')

        successful = True
        for input_descriptor in input_interface:
            input_content_path = os.path.join(wd_path, input_descriptor['name'])
            status.update_all({
                'input': input_descriptor,
                'input_content_path': input_content_path
            })

            # get the content and the descriptor for this input
            if input_descriptor['type'] == 'reference':
                status.update('input_status', 'pending fetch data object')
                obj_id = input_descriptor['obj_id']

                c_hash = self.fetch_data_object(obj_id, input_content_path)
                while not c_hash:
                    logger.warning(f"worker[{self.name}]: input data object '{obj_id}' not available. waiting...")
                    time.sleep(10)
                    c_hash = self.fetch_data_object(obj_id, input_content_path)

                status.update('input_status', 'data object fetched')
            else:
                status.update('input_status', 'storing value')
                dump_json_to_file(input_descriptor['value'], input_content_path)
                dump_json_to_file({
                    # 'data_type': input_descriptor['data_type'],
                    # 'data_format': input_descriptor['data_format']
                    'data_type': 'JSONObject',
                    'data_format': 'json'
                }, f"{input_content_path}.descriptor")
                status.update('input_status', 'value stored')

            # verify that the input data type and format matches the object data type and format
            obj_descriptor = load_json_from_file(f"{input_content_path}.descriptor")
            proc_in_descriptor = self._input_interface[input_descriptor['name']]
            if proc_in_descriptor['data_type'] != obj_descriptor['data_type'] or \
                    proc_in_descriptor['data_format'] != obj_descriptor['data_format']:
                error = f"worker[{proc_in_descriptor['name']}]: mismatching data type or format for " \
                        f"input '{input_descriptor['name']}': " \
                        f"input={(proc_in_descriptor['data_type'], proc_in_descriptor['data_format'])} " \
                        f"object={(obj_descriptor['data_type'], obj_descriptor['data_format'])}"
                logger.error(error)
                status.update('error', error)
                successful = False
                break

        # clean up transient status information
        status.remove_all(['input', 'input_content_path', 'input_status'])
        return successful

    def _push_output_data_objects(self, owner, wd_path, task_descriptor, status):
        status.update('stage', 'push output data objects')

        successful = True
        for output_descriptor in self._output_interface.values():
            output_content_path = os.path.join(wd_path, output_descriptor['name'])
            status.update_all({
                'output': output_descriptor,
                'output_content_path': output_content_path,
                'output_status': 'pending add'
            })

            if not os.path.isfile(output_content_path):
                error = f"worker[{self.name}]: output data object '{output_descriptor['name']}' not available."
                logger.error(error)
                status.update('error', error)
                successful = False
                break

            # push the output data object to the DOR
            obj_id = self.push_output_data_object(output_descriptor, output_content_path, owner, task_descriptor)

            # output_name = output_descriptor['name']
            # data_type = output_descriptor['data_type']
            # data_format = output_descriptor['data_format']
            # # TODO: this should be changed to something meaningful
            # created_by = 'unknown'
            #
            # proxy = DORProxy(self.node.rest.address(), self.node.identity())
            # obj_id = proxy.add_data_object(output_content_path, owner, data_type, data_format, created_by,
            #                                recipe=proxy.create_recipe(task_descriptor, output_name))

            if not obj_id:
                error = f"worker[{self.name}]: failed to add data object '{output_descriptor['name']}'to DOR."
                logger.error(error)
                status.update('error', error)
                successful = False
                break

            status.update_all({
                f"output:{output_descriptor['name']}": obj_id,
                'output_status': 'added'
            })

        # clean up transient status information
        status.remove_all(['output', 'output_content_path', 'output_status'])
        return successful


class RTIDockerProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, descriptor, content_path, node):
        super().__init__(proc_id, node)
        self._node = node
        self.descriptor = descriptor
        self.processor_name = self.descriptor['name']
        self.processor_version = self.descriptor['version']
        self.content_path = content_path

        self.port = None
        self.docker_image_id = None
        self.docker_container_id = None
        self.docker_container_name = f'{self.processor_name}-{self.processor_version}'

    @property
    def uri(self):
        if self.port is not None:
            return f'http://localhost:{self.port}'
        else:
            raise ValueError('Port has not been initialised.')

    def startup(self):
        client = docker.from_env()

        # Load image to docker
        with open(self.content_path, 'rb') as docker_package:
            image_list = client.images.load(docker_package)
            docker_image = image_list[0]
        self.docker_image_id = docker_image.id

        # check if there are any containers running with the same name, from the same image, and remove it
        containers = client.containers.list(filters={'name': self.docker_container_name})
        if len(containers) == 1 and containers[0].image.id == self.docker_image_id:
            logger.info(
                "[RTIDockerProcessorAdapter] startup: removing docker processor container with the same name"
                " '{}'".format(self.processor_name))
            container = containers[0]
            container.stop()
            container.wait()
            container.remove()

        # bind rti.jobs_path to jobs_path in Docker
        jobs_path = os.path.realpath(self._node.rti.get_job_wd())
        self.port = find_open_port()
        container = client.containers.run(self.docker_image_id,
                                          name=self.docker_container_name,
                                          ports={'5000/tcp': self.port},
                                          volumes={jobs_path: {'bind': '/jobs_path', 'mode': 'rw'}},
                                          detach=True)

        self.docker_container_id = container.id
        self.parse_io_interface(self.descriptor)

        while True:
            if container.status != 'running':
                time.sleep(1)
                container.reload()  # refresh container attrs
            else:  # check if server is responding to requests
                r = requests.get(f'{self.uri}/descriptor')
                if r.status_code == 200:
                    break

        client.close()
        logger.info("[RTIDockerProcessorAdapter] startup: started docker processor '{}'".format(self.processor_name))

    def shutdown(self):
        client = docker.from_env()

        # Kill and remove docker container
        try:
            container = client.containers.get(self.docker_container_id)
        except docker.errors.NotFound:
            logger.warning(
                f"[RTIDockerProcessorAdapter] shutdown: could not find docker processor '{self.processor_name}'")
        else:
            container.stop()
            container.wait()
            container.remove()

        # Remove image from docker
        client.images.remove(self.docker_image_id)

        client.close()
        logger.info(f"[RTIDockerProcessorAdapter] shutdown: shutdown docker processor '{self.processor_name}'")

    def execute(self, task_descriptor, working_directory, status_logger):
        try:
            job_id = os.path.basename(working_directory)
            r = requests.post(f'{self.uri}/execute', json={'job_id': job_id,
                                                           'task_descriptor': task_descriptor})
            status_code = r.status_code
        except Exception as e:
            logger.warning(
                f"[RTIDockerProcessorAdapter] execute: execute failed for docker processor '{self.processor_name}'")
            return False
        else:
            return r.status_code == 200


class RTINativeProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, descriptor, content_path, rti):
        super().__init__(proc_id, rti)
        self.local_git_path = os.path.join(rti.node.datastore_path, '_git_repos', proc_id)
        self.git_spec = self._read_git_spec(content_path)

        self.processor_path = None
        self.processor_descriptor = None

    @staticmethod
    def _read_git_spec(git_spec_path):
        with open(git_spec_path, 'rb') as f:
            git_spec = json.load(f)
        return git_spec

    @property
    def log_dir(self):
        log_dir = os.path.join(self.rti.node.datastore_path, 'logs')
        if not os.path.exists(log_dir):
            os.mkdir(log_dir)
        return log_dir

    def startup(self):
        deploy_git_processor(self.local_git_path, self.git_spec, self.log_dir)
        processor_path, processor_descriptor = get_processor(self.local_git_path, self.git_spec)

        self.processor_path = processor_path
        self.processor_descriptor = processor_descriptor

        self.parse_io_interface(processor_descriptor)

    def execute(self, task_descriptor, working_directory, status_logger):
        venv_py_path = os.path.join(self.local_git_path, 'venv', 'bin', 'python')
        subprocess.run([venv_py_path, self.processor_path, working_directory], check=True)
        return True
