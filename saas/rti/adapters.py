import os
import sys
import time
import logging
import subprocess
import importlib

from threading import Lock, Thread

from saas.utilities.general_helpers import dump_json_to_file, create_symbolic_link

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
        # self.name = name
        self.rti = rti
        self.pending = []
        self.is_active = True

    def startup(self):
        pass

    def shutdown(self):
        pass

    def execute(self, job_descriptor, working_directory, status_logger):
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
            job_descriptor['status_logger'] = status

            # obtain input data objects
            status.update('stage', 'fetch input data objects')
            task_descriptor = job_descriptor['descriptor']
            for input_descriptor in task_descriptor['input']:
                input_content_path = os.path.join(wd_path, input_descriptor['name'])
                status.update_all({
                    'input': input_descriptor,
                    'input_content_path': input_content_path
                })
                if input_descriptor['type'] == 'reference':
                    status.update('input_status', 'pending fetch')
                    obj_id = input_descriptor['value']

                    c_hash = self.rti.node.dor.fetch(obj_id, input_content_path)
                    while not c_hash:
                        logger.warning("worker[{}]: data object '{}' not available. waiting...".format(self.name,
                                                                                                       obj_id))
                        time.sleep(10)
                        c_hash = self.rti.node.dor.fetch(obj_id, input_content_path)

                    status.update('input_status', 'fetched')
                else:
                    status.update('input_status', 'storing value')
                    dump_json_to_file(input_descriptor['value'], input_content_path)
                    status.update('input_status', 'value stored')

            # clean up transient status information
            status.remove_all(['input', 'input_content_path', 'input_status'])

            # instruct processor adapter to execute the job
            if self.execute(task_descriptor, wd_path, status):
                # if successful, push the output data objects to the DOR
                # TODO: needs to be implemented
                status.update('status', 'successful')

        self.shutdown()


class RTIDockerProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, descriptor, content_path, rti):
        super().__init__(rti)


class RTIPackageProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, descriptor, content_path, rti):
        super().__init__(rti)


class RTIWorkflowProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, rti):
        super().__init__(rti)


class RTIScriptProcessorAdapter(RTIProcessorAdapter):
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

    def shutdown(self):
        pass

    def execute(self, task_descriptor, working_directory, status_logger):
        return self.module.function(task_descriptor, working_directory, status_logger)
