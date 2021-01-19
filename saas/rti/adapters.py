import os
import sys
import time
import logging
import subprocess
import importlib

from threading import Lock, Thread
import docker

from saas.eckeypair import ECKeyPair
from saas.utilities.general_helpers import dump_json_to_file, load_json_from_file, create_symbolic_link, get_timestamp_now
from saas.utilities.blueprint_helpers import request_dor_add

logger = logging.getLogger('RTI.adapters')


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
    def __init__(self, rti):
        super().__init__(daemon=True)

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

    def add(self, job_descriptor):
        self.mutex.acquire()
        if self.is_active:
            self.pending.append(job_descriptor)
            self.mutex.release()
            return True
        else:
            self.mutex.release()
            return False

    def stop(self):
        self.is_active = False

    def run(self):
        self.startup()

        while self.is_active:
            # get the next job
            self.mutex.acquire()
            while not self.pending:
                self.mutex.release()
                time.sleep(5)
                self.mutex.acquire()
            job_descriptor = self.pending.pop(0)
            self.mutex.release()

            # create working directory
            wd_path = os.path.join(self.rti.jobs_path, str(job_descriptor['id']))
            subprocess.check_output(['mkdir', '-p', wd_path])

            # dump the job descriptor
            job_descriptor_path = os.path.join(wd_path, 'job_descriptor.json')
            dump_json_to_file(job_descriptor, job_descriptor_path)

            # create status logger
            status_path = os.path.join(wd_path, 'job_status.json')
            status = StatusLogger(status_path)

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

        self.shutdown()


class RTITaskProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, rti):
        super().__init__(rti)

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
                    'data_type': input_descriptor['data_type'],
                    'data_format': input_descriptor['data_format']
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


def find_open_port():
    """
    Use socket's built in ability to find an open port.
    """
    import socket
    sock = socket.socket()
    sock.bind(('', 0))

    _, port = sock.getsockname()

    return port


class RTIDockerProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, descriptor, content_path, rti):
        super().__init__(rti)
        self.processor_name = descriptor['name']
        self.processor_version = descriptor['version']
        self.content_path = content_path

        self.port = find_open_port()
        self.uri = f'http://localhost:{self.port}'

        self.docker_image_id = None
        self.docker_container_id = None

    def startup(self):
        client = docker.from_env()

        # Load image to docker
        with open(self.content_path, 'rb') as docker_package:
            image_list = client.images.load(docker_package)
            docker_image = image_list[0]
        self.docker_image_id = docker_image.id

        # bind rti.jobs_path to jobs_path in Docker
        jobs_path = os.path.realpath(self.rti.jobs_path)
        container = client.containers.run(self.docker_image_id,
                                          name=f'{self.processor_name}-{self.processor_version}',
                                          ports={'5000/tcp': self.port},
                                          volumes={jobs_path: {'bind': '/jobs_path', 'mode': 'rw'}},
                                          detach=True)

        self.docker_container_id = container.id

        logger.info("[RTIDockerProcessorAdapter] startup: started docker processor '{}'".format(self.processor_name))

    def shutdown(self):
        client = docker.from_env()

        # Kill and remove docker container
        container_list = client.containers.list(filters={'id': self.docker_container_id})
        if len(container_list):
            container = container_list[0]
            container.remove(force=True)

        # Remove image from docker
        client.images.remove(self.docker_image_id)

        logger.info("[RTIDockerProcessorAdapter] startup: shutdown docker processor '{}'".format(self.processor_name))

    def execute(self, task_descriptor, working_directory, status_logger):
        import requests
        try:
            r = requests.post(f'{self.uri}/execute', json=task_descriptor)
        except Exception as e:
            return False
        else:
            return r.status_code == 200


class RTIPackageProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, descriptor, content_path, rti):
        super().__init__(rti)


class RTIScriptProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, content_path, rti):
        super().__init__(rti)

        head_tail = os.path.split(content_path)
        script_path = os.path.join(head_tail[0], f"{proc_id}.py")
        create_symbolic_link(content_path, script_path)

        self.module_path = head_tail[0]
        self.module_name = proc_id
        self.module = None

    def startup(self):
        sys.path.insert(1, self.module_path)
        self.module = importlib.import_module(self.module_name)
        logger.info(f"[RTIScriptProcessorAdapter] startup: imported module '{self.module_name}'")
        self.parse_io_interface(self.module.descriptor)

    def shutdown(self):
        pass

    def execute(self, task_descriptor, working_directory, status_logger):
        return self.module.function(task_descriptor, working_directory, status_logger)
