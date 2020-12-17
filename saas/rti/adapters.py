import os
import sys
import time
import logging
import subprocess
import importlib

from threading import Lock, Thread

from saas.eckeypair import ECKeyPair
from saas.utilities.general_helpers import dump_json_to_file, load_json_from_file, create_symbolic_link
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
            error = "worker[{}]: owner identity cannot be created from public key '{}'.".format(
                self.name, task_descriptor['owner_public_key'])
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
                    logger.warning("worker[{}]: input data object '{}' not available. waiting...".format(self.name,
                                                                                                         obj_id))
                    time.sleep(10)
                    c_hash = self.rti.node.dor.fetch(obj_id, input_content_path)

                status.update('input_status', 'data object fetched')
            else:
                status.update('input_status', 'storing value')
                dump_json_to_file(input_descriptor['value'], input_content_path)
                dump_json_to_file({
                    'data_type': input_descriptor['data_type'],
                    'data_format': input_descriptor['data_format']
                }, "{}.descriptor".format(input_content_path))
                status.update('input_status', 'value stored')

            # verify that the input data type and format matches the object data type and format
            obj_descriptor = load_json_from_file("{}.descriptor".format(input_content_path))
            proc_in_descriptor = self.input_interface[input_descriptor['name']]
            if proc_in_descriptor['data_type'] != obj_descriptor['data_type'] or \
                    proc_in_descriptor['data_format'] != obj_descriptor['data_format']:
                error = "worker[{}]: mismatching data type or format for input '{}': input={} object={}".format(
                    proc_in_descriptor['name'], input_descriptor['name'],
                    (proc_in_descriptor['data_type'], proc_in_descriptor['data_format']),
                    (obj_descriptor['data_type'], obj_descriptor['data_format']))
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
                error = "worker[{}]: output data object '{}' not available.".format(
                    self.name, output_descriptor['name'])
                logger.error(error)
                status.update('error', error)
                successful = False
                break

            data_type = output_descriptor['data_type']
            data_format = output_descriptor['data_format']

            obj_id = request_dor_add(self.rti.node.rest_api_address, self.rti.node.key, owner, output_content_path,
                                     data_type, data_format)

            if not obj_id:
                error = "worker[{}]: failed to add data object '{}'to DOR.".format(
                    self.name, output_descriptor['name'])
                logger.error(error)
                status.update('error', error)
                successful = False
                break

            status.update_all({
                "output:{}".format(output_descriptor['name']): obj_id,
                'output_status': 'added'
            })

        # clean up transient status information
        status.remove_all(['output', 'output_content_path', 'output_status'])
        return successful


class RTIDockerProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, descriptor, content_path, rti):
        super().__init__(rti)


class RTIPackageProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, descriptor, content_path, rti):
        super().__init__(rti)


class RTIScriptProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, content_path, rti):
        super().__init__(rti)

        head_tail = os.path.split(content_path)
        script_path = os.path.join(head_tail[0], "{}.py".format(proc_id))
        create_symbolic_link(content_path, script_path)

        self.module_path = head_tail[0]
        self.module_name = proc_id
        self.module = None

    def startup(self):
        sys.path.insert(1, self.module_path)
        self.module = importlib.import_module(self.module_name)
        logger.info("[RTIScriptProcessorAdapter] startup: imported module '{}'".format(self.module_name))
        self.parse_io_interface(self.module.descriptor)

    def shutdown(self):
        pass

    def execute(self, task_descriptor, working_directory, status_logger):
        return self.module.function(task_descriptor, working_directory, status_logger)
