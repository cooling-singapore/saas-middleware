import os
import sys
import time
import logging
import importlib
import socket
import pip

from threading import Lock, Thread
import docker
import docker.errors
import requests

from saas.eckeypair import ECKeyPair
from saas.utilities.general_helpers import dump_json_to_file, load_json_from_file
from saas.utilities.blueprint_helpers import request_dor_add

logger = logging.getLogger('RTI.adapters')


def import_with_auto_install(package):
    try:
        return importlib.import_module(package)

    except ImportError:
        pip.main(['install', package])

    return importlib.import_module(package)


def find_open_port():
    """
    Use socket's built in ability to find an open port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        port = s.getsockname()[1]
    return port


class StatusLogger:
    """
    StatusLogger keeps information (key-value pairs) for a job and syncs its contents to disk. This class is
    basically just a wrapper of a dictionary providing convenient functions.
    """

    def __init__(self, path):
        self.path = path
        self.content = {}
        self.update_all({
            'status': 'running',
            'stage': 'initialisation'
        })

    def update(self, key, value):
        """
        Update the job status with a given key and value. The updated job status is synced to disk.
        """
        self.content[key] = value
        dump_json_to_file(self.content, self.path)

    def update_all(self, content):
        """
        Update the job status with given content (i.e., dictionary). The updated job status is synced to disk.
        """
        self.content.update(content)
        dump_json_to_file(self.content, self.path)

    def get(self, key=None):
        """
        Returns the value for a given key.
        """
        return self.content[key] if key else self.content

    def remove_all(self, keys):
        """
        Removes multiple entries (if they exists) using a list of key.
        """
        for key in keys:
            self.content.pop(key, None)
        dump_json_to_file(self.content, self.path)


class RTIProcessorAdapter(Thread):

    def __init__(self, proc_id, rti):
        super().__init__(daemon=True)

        self.proc_id = proc_id
        self.mutex = Lock()
        self.rti = rti
        self.pending = []
        self.is_active = True

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
        self.mutex.acquire()
        if self.is_active:
            self.pending.append((job_descriptor, status))
            self.mutex.release()
            return True
        else:
            self.mutex.release()
            return False

    def stop(self):
        logger.info(f"adapter {self.proc_id} received stop signal.")
        self.is_active = False

    def run(self):
        logger.info(f"adapter {self.proc_id} starting up...")
        self.startup()

        logger.info(f"adapter {self.proc_id} started up.")
        while self.is_active:
            # get the next job
            self.mutex.acquire()
            while self.is_active and not self.pending:
                self.mutex.release()
                time.sleep(5)
                self.mutex.acquire()

            # with or without job, is not is_active, then we quit
            if not self.is_active:
                self.mutex.release()
                break

            # there should be a job in the pending queue
            job_descriptor, status = self.pending.pop(0)
            self.mutex.release()

            # # create working directory
            wd_path = os.path.join(self.rti.jobs_path, str(job_descriptor['id']))
            # subprocess.check_output(['mkdir', '-p', wd_path])
            #
            # # dump the job descriptor
            # job_descriptor_path = os.path.join(wd_path, 'job_descriptor.json')
            # dump_json_to_file(job_descriptor, job_descriptor_path)
            #
            # # create status logger
            # status_path = os.path.join(wd_path, 'job_status.json')
            # status = StatusLogger(status_path)

            task_or_wf_descriptor = job_descriptor['descriptor']

            # perform pre-execute routine
            if not self.pre_execute(task_or_wf_descriptor, wd_path, status):
                status.update('status', 'failed')
                continue

            # instruct processor adapter to execute the job
            if not self.execute(task_or_wf_descriptor, wd_path, status):
                status.update('status', 'failed')
                continue

            # perform post-execute routine
            if not self.post_execute(task_or_wf_descriptor, wd_path, status):
                status.update('status', 'failed')
                continue

            status.update('status', 'successful')

        logger.info(f"adapter {self.proc_id} shutting down...")
        self.shutdown()

        logger.info(f"adapter {self.proc_id} shut down.")


class RTITaskProcessorAdapter(RTIProcessorAdapter):

    def __init__(self, proc_id, rti):
        super().__init__(proc_id, rti)

        self.input_interface = {}
        self.output_interface = {}

    def parse_io_interface(self, descriptor):
        for item in descriptor['input']:
            self.input_interface[item['name']] = item

        for item in descriptor['output']:
            self.output_interface[item['name']] = item

    def pre_execute(self, task_descriptor, working_directory, status):
        # fetch input data objects
        return self.fetch_input_data_objects(task_descriptor['input'], working_directory, status)

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
        if not self.push_output_data_objects(owner, working_directory, status):
            return False

        return True

    def fetch_input_data_objects(self, input_interface, wd_path, status):
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

                c_hash = self.rti.node.dor.fetch(obj_id, input_content_path)
                while not c_hash:
                    logger.warning(f"worker[{self.name}]: input data object '{obj_id}' not available. waiting...")
                    time.sleep(10)
                    c_hash = self.rti.node.dor.fetch(obj_id, input_content_path)

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
            proc_in_descriptor = self.input_interface[input_descriptor['name']]
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

    def push_output_data_objects(self, owner, wd_path, status):
        status.update('stage', 'push output data objects')

        successful = True
        for output_descriptor in self.output_interface.values():
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

            data_type = output_descriptor['data_type']
            data_format = output_descriptor['data_format']

            obj_id = request_dor_add(self.rti.node.rest_api_address, self.rti.node.key, owner, output_content_path,
                                     data_type, data_format)

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
    def __init__(self, proc_id, descriptor, content_path, rti):
        super().__init__(proc_id, rti)
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
        jobs_path = os.path.realpath(self.rti.jobs_path)
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
            logger.warning(f"[RTIDockerProcessorAdapter] shutdown: could not find docker processor '{self.processor_name}'")
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
            logger.warning(f"[RTIDockerProcessorAdapter] execute: execute failed for docker processor '{self.processor_name}'")
            return False
        else:
            return r.status_code == 200


class RTIPackageProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, descriptor, content_path, rti):
        super().__init__(proc_id, rti)


class RTIScriptProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, content_path, rti):
        super().__init__(proc_id, rti)

        logger.info(f"[RTIScriptProcessorAdapter] init: content_path={content_path}")
        self.script = load_json_from_file(content_path)
        self.module = None

    def startup(self):
        package_path = self.script['package_path']
        descriptor_path = self.script['descriptor_path']
        module_name = self.script['module_name']
        dependencies = self.script['dependencies']

        for package in dependencies:
            logger.info(f"[RTIScriptProcessorAdapter] importing dependency '{package}'")
            import_with_auto_install(package)

        logger.info(f"[RTIScriptProcessorAdapter] startup: package_path={package_path} module_name={module_name}")
        sys.path.insert(1, package_path)

        self.module = importlib.import_module(module_name)
        logger.info(f"[RTIScriptProcessorAdapter] startup: imported module '{module_name}'")

        descriptor = load_json_from_file(descriptor_path)
        self.parse_io_interface(descriptor)

    def shutdown(self):
        pass

    def execute(self, task_descriptor, working_directory, status_logger):
        return self.module.function(task_descriptor, working_directory, status_logger)
