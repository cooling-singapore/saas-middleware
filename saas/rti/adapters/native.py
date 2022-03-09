import json
import os
import threading
import time

from jsonschema import validate

from saascore.exceptions import SaaSException
from saascore.keystore.assets import credentials
from saascore.log import Logging

import saas.rti.adapters.base as base
from saas.rti.status import StatusLogger
from saas.schemas import GitProcessorPointer

logger = Logging.get('rti.adapters.native')


class RTINativeProcessorAdapter(base.RTIProcessorAdapter):
    def __init__(self, proc_id: str, gpp: dict, obj_content_path: str, jobs_path: str, node,
                 ssh_credentials: credentials.SSHCredentials = None,
                 github_credentials: credentials.GithubCredentials = None,
                 retain_remote_wdirs: bool = False) -> None:
        super().__init__(proc_id, gpp, jobs_path, node)

        # set credentials
        self._ssh_credentials = ssh_credentials
        self._github_credentials = github_credentials
        self._retain_remote_wdirs = retain_remote_wdirs

        # create the proc-temp directory if doesn't already exist
        self._proc_temp_path = os.path.join(node.datastore, 'proc-temp')
        os.makedirs(self._proc_temp_path, exist_ok=True)

        # create paths
        local_repo_path = os.path.join(node.datastore, 'proc-repositories', proc_id)
        local_adapter_path = os.path.join(local_repo_path, self._gpp['proc_path'])
        self._paths = {
            'local_repo': local_repo_path,
            'local_adapter': local_adapter_path,
            'remote_repo': local_repo_path.replace(os.environ['HOME'], '~'),
            'remote_adapter': local_adapter_path.replace(os.environ['HOME'], '~')
        }
        self._paths['repo'] = self._paths['remote_repo'] if self._ssh_credentials else self._paths['local_repo']
        self._paths['adapter'] = self._paths['remote_adapter'] if self._ssh_credentials else self._paths['local_adapter']
        self._paths['install.sh'] = os.path.join(self._paths['adapter'], 'install.sh')
        self._paths['execute.sh'] = os.path.join(self._paths['adapter'], 'execute.sh')

        # read the git processor pointer (gpp)
        with open(obj_content_path, 'rb') as f:
            self._gpp = json.load(f)
            validate(instance=self._gpp, schema=GitProcessorPointer.schema())

    def startup(self) -> None:
        url = self._gpp['source']
        commit_id = self._gpp['commit_id']

        # check if the repository has already been cloned
        if base.check_if_path_exists(self._paths['repo'], ssh_credentials=self._ssh_credentials, timeout=10):
            logger.debug(f"repository already exists {'REMOTE:' if self._ssh_credentials else 'LOCAL:'}"
                         f"{self._paths['repo']} -> skip cloning")
        else:
            # do we have git credentials?
            if self._github_credentials:
                insert = f"{self._github_credentials.login}:{self._github_credentials.personal_access_token}@"
                index = url.find('github.com')
                url = url[:index] + insert + url[index:]

            # clone the repository
            logger.debug(f"repository does not exist {'REMOTE:' if self._ssh_credentials else 'LOCAL:'}"
                         f"{self._paths['repo']} -> clone")

            base.run_command(f"git clone {url} {self._paths['repo']}", ssh_credentials=self._ssh_credentials)

        # checkout the commit
        logger.debug(f"checkout commit {commit_id}")
        base.run_command(f"cd {self._paths['repo']} && git checkout {commit_id}",
                         ssh_credentials=self._ssh_credentials, timeout=10)

        # make scripts executable
        logger.debug(f"make executable {'REMOTE:' if self._ssh_credentials else 'LOCAL:'}{self._paths['install.sh']}")
        base.run_command(f"chmod u+x {self._paths['install.sh']}", ssh_credentials=self._ssh_credentials, timeout=10)

        logger.debug(f"make executable {'REMOTE:' if self._ssh_credentials else 'LOCAL:'}{self._paths['execute.sh']}")
        base.run_command(f"chmod u+x {self._paths['execute.sh']}", ssh_credentials=self._ssh_credentials, timeout=10)

        # run install script
        logger.debug(f"running {'REMOTE:' if self._ssh_credentials else 'LOCAL:'}{self._paths['install.sh']}")
        pid, paths = base.run_command_async(f"cd {self._paths['adapter']} && {self._paths['install.sh']} "
                                            f"{self._gpp['proc_config']}",
                                            local_output_path=self._paths['local_adapter'],
                                            name='install_sh',
                                            ssh_credentials=self._ssh_credentials)

        base.monitor_command(pid, paths, ssh_credentials=self._ssh_credentials)

    def shutdown(self) -> None:
        pass

    def execute(self, job_id: str, task_descriptor: dict, local_working_directory: str, status: StatusLogger) -> None:
        paths = {
            'local_wd': local_working_directory,
            'remote_wd': local_working_directory.replace(os.environ['HOME'], '~')
        }
        paths['wd'] = paths['remote_wd'] if self._ssh_credentials else paths['local_wd']

        # make sure the wd path exists (locally and remotely, if applicable)
        status.update('task', f"create working directory at LOCAL:{paths['local_wd']}")
        os.makedirs(paths['local_wd'], exist_ok=True)

        # if ssh_auth IS present, then we perform a remote execution -> copy input data to remote working directory
        if self._ssh_credentials is not None:
            status.update('task', f"create working directory at REMOTE:{paths['remote_wd']}")
            base.run_command(f"mkdir -p {paths['remote_wd']}", ssh_credentials=self._ssh_credentials, timeout=10)

            # copy the input data objects to the remote working directory
            for obj_name in self._input_interface:
                local_path = os.path.join(local_working_directory, obj_name)
                status.update('task', f"copy '{obj_name}': LOCAL:{local_path} -> REMOTE:{paths['remote_wd']}")
                base.scp_local_to_remote(local_path, paths['remote_wd'], self._ssh_credentials)

        # run install script
        task_msg = f"starting {'REMOTE:' if self._ssh_credentials else 'LOCAL:'}{self._paths['execute.sh']}"
        status.update('task', task_msg)
        logger.debug(task_msg)
        pid, pid_paths = base.run_command_async(f"cd {self._paths['adapter']} && {self._paths['execute.sh']} "
                                                f"{self._gpp['proc_config']} {paths['wd']}",
                                                local_output_path=paths['local_wd'],
                                                name='execute_sh',
                                                ssh_credentials=self._ssh_credentials)

        # create the context information for this job
        context = {
            'task_descriptor': task_descriptor,
            'paths': paths,
            'job_id': job_id,
            'status': status,
            'threads': {}
        }

        base.monitor_command(pid, pid_paths, ssh_credentials=self._ssh_credentials, triggers={
                                 'trigger:output': {'func': self._handle_trigger_output, 'context': context},
                                 'trigger:progress': {'func': self._handle_trigger_progress, 'context': context}
                             })

        # wait for all outputs to be processed
        while True:
            remaining = len(context['threads'])
            if remaining == 0:
                break

            status.update('task', f"wait for all outputs to be processed: remaining={remaining}")
            time.sleep(1)

        # if ssh credentials are present, then we perform a remote execution -> delete the remote working directory
        if not self._retain_remote_wdirs and self._ssh_credentials is not None:
            status.update('task', f"delete working directory REMOTE:{paths['remote_wd']}")
            base.run_command(f"rm -rf {paths['remote_wd']}", ssh_credentials=self._ssh_credentials)

        status.remove('task')

    def _handle_trigger_output(self, line: str, context: dict) -> None:
        obj_name = line.split(':')[2]
        context['obj_name'] = obj_name
        context['threads'][obj_name] = threading.Thread(target=self._process_output, kwargs=context)
        context['threads'][obj_name].start()

    def _handle_trigger_progress(self, line: str, context: dict) -> None:
        status: StatusLogger = context['status']
        status.update('progress', line.split(':')[2])

    def _process_output(self, **context) -> None:
        obj_name = context['obj_name']
        job_id = context['job_id']
        task_descriptor = context['task_descriptor']
        paths = context['paths']
        status: StatusLogger = context['status']

        status.update(f"process_output:{obj_name}", 'started')

        # if ssh_auth IS present, then we perform a remote execution
        # -> copy output data to local working directory
        if self._ssh_credentials is not None:
            status.update(f"process_output:{obj_name}", 'retrieve')

            remote_path = os.path.join(paths['remote_wd'], obj_name)
            status.update('task', f"copy data objects: {remote_path} -> {paths['local_wd']}")

            base.scp_remote_to_local(remote_path, paths['local_wd'], self._ssh_credentials)
            status.remove('task')

        # upload the data object to the target DOR
        try:
            status.update(f"process_output:{obj_name}", 'push')
            self._push_data_object(job_id, obj_name, task_descriptor, paths['local_wd'], status)
            status.update(f"process_output:{obj_name}", 'done')

        except SaaSException as e:
            status.update(f"process_output:{obj_name}", f"failed: id={e.id} reason={e.reason}")

        # remove this thread
        context['threads'].pop(obj_name)
