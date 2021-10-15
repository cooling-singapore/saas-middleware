import json
import os
import subprocess
import threading
import time

from jsonschema import validate

from saas.exceptions import RunCommandError, SaaSException
from saas.helpers import run_command, scp_local_to_remote, scp_remote_to_local, monitor_command
from saas.keystore.assets.credentials import GithubCredentials
from saas.logging import Logging
from saas.rti.adapters.adapters import RTIProcessorAdapter
from saas.rti.exceptions import AdapterRuntimeError, SSHConnectionError
from saas.rti.status import StatusLogger
from saas.schemas import git_proc_pointer_schema

logger = Logging.get('rti.adapters.native')


class RTINativeProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, proc_id: str, gpp: dict, obj_content_path: str, jobs_path: str, node,
                 ssh_credentials: dict = None,
                 github_credentials: GithubCredentials = None) -> None:
        super().__init__(proc_id, gpp, jobs_path, node)

        # set credentials
        self._ssh_credentials = ssh_credentials
        self._github_credentials = github_credentials

        # substitute home path with $HOME - check if $HOME is actually present
        self._repo_home = os.path.join(node.datastore(), 'proc-repositories', proc_id)
        if os.environ['HOME'] in self._repo_home:
            self._repo_home = self._repo_home.replace(os.environ['HOME'], "$HOME")
        else:
            raise Exception(f"Unexpected datastore path encountered without $HOME prefix: datastore={self._repo_home} "
                            f"home={os.environ['HOME']}")
        logger.info(f"native processor adapter for proc_id={proc_id} using repository home at {self._repo_home}")

        # read the git processor pointer (gpp)
        with open(obj_content_path, 'rb') as f:
            self._gpp = json.load(f)
            validate(instance=self._gpp, schema=git_proc_pointer_schema)

        # set the processor path
        self._processor_path = os.path.join(self._repo_home, self._gpp['proc_path'])

    def startup(self) -> None:
        # test the ssh connection (if applicable)
        self._test_ssh_connection()

        url = self._gpp['source']
        commit_id = self._gpp['commit_id']

        # check if the repository has already been cloned
        if self._path_exists(self._repo_home):
            logger.debug(f"repository already exists at {self._repo_home} -> skip cloning")
        else:
            # do we have git credentials?
            github_cred = self._node.keystore.get_asset('github-credentials')
            if github_cred:
                # do we have credentials for this repo?
                cred = github_cred.get(url)
                if cred:
                    insert = f"{cred.login}:{cred.personal_access_token}@"
                    index = url.find('github.com')
                    url = url[:index] + insert + url[index:]

            # clone the repository
            logger.debug(f"repository does not exist at {self._repo_home} -> clone")
            self._execute_command(f"git clone {url} {self._repo_home}")

        # checkout the commit
        logger.debug(f"checkout commit {commit_id}")
        self._execute_command(f"cd {self._repo_home} && git checkout {commit_id}")

        for script in ['install.sh', 'execute.sh']:
            script_path = os.path.join(self._processor_path, script)
            logger.debug(f"make {script} executable: path={script_path}")
            self._execute_command(f"chmod u+x {script_path}")

        # run install script
        logger.debug(f"running install.sh...")
        self._execute_command(f"./install.sh {self._gpp['proc_config']}",
                              cwd=self._processor_path,
                              console_log_prefix=os.path.join(self._processor_path, "install.sh"))

    def shutdown(self) -> None:
        pass

    def execute(self, job_id: str, task_descriptor: dict, local_working_directory: str, status: StatusLogger) -> None:
        # specify the working directory
        working_directory = local_working_directory.replace(os.environ['HOME'], '$HOME')

        # if ssh_auth IS present, then we perform a remote execution -> copy input data to remote working directory
        if self._ssh_credentials is not None:
            # test the connection
            status.update('task', f"test SSH connection")
            self._test_ssh_connection()

            # create the remote working directory
            status.update('task', f"create remote working directory at {working_directory}")
            self._execute_command(f"mkdir -p {working_directory}")

            # copy the input data objects to the remote working directory
            for obj_name in self._input_interface:
                local_path = os.path.join(local_working_directory, obj_name)
                status.update('task', f"copy data objects: {local_path} -> {working_directory}")
                scp_local_to_remote(local_path, working_directory,
                                    login=self._ssh_credentials['login'],
                                    host=self._ssh_credentials['host'],
                                    ssh_key_path=self._ssh_credentials['key_path'])

        # run execute script
        status.update('task', f"run execute.sh: config={self._gpp['proc_config']} "
                              f"working_directory={working_directory} "
                              f"processor_path={self._processor_path}")

        # create the context information for this job
        context = {
            'task_descriptor': task_descriptor,
            'local_working_directory': local_working_directory,
            'working_directory': working_directory,
            'job_id': job_id,
            'status': status,
            'threads': {}
        }

        # run the execute.sh script while monitoring its output
        self._monitor_command(f"./execute.sh {self._gpp['proc_config']} {working_directory}", context,
                              cwd=self._processor_path,
                              stdout_path=os.path.join(local_working_directory, "execute.sh.stdout"),
                              stderr_path=os.path.join(local_working_directory, "execute.sh.stderr"))

        # wait for all outputs to be processed
        status.update('task', f"wait for all outputs to be processed")
        while len(context['threads']) > 0:
            time.sleep(0.1)

        # if ssh_auth IS present, then we perform a remote execution -> copy output data to local working directory
        if self._ssh_credentials is not None:
            # delete remote working directory
            status.update('task', f"delete remote working directory: {working_directory}")
            self._execute_command(f"rm -rf {working_directory}")

            msg = f"delete remote working directory at {working_directory}"
            status.update('status', msg)

        status.remove('task')

    def _test_ssh_connection(self) -> None:
        if self._ssh_credentials:
            command = ['ssh', '-i', self._ssh_credentials['key_path'],
                       f"{self._ssh_credentials['login']}@{self._ssh_credentials['host']}", 'exit']
            result = run_command(command, suppress_exception=True)
            if result.returncode != 0:
                raise SSHConnectionError({
                    'command': command,
                    'result': result
                })

    def _monitor_command(self, command: str, context: dict,
                         stdout_path: str, stderr_path: str, cwd: str = None) -> None:

        command = f"cd {cwd} && {command}" if cwd else command
        command = ['ssh', '-i', self._ssh_credentials['key_path'],
                   f"{self._ssh_credentials['login']}@{self._ssh_credentials['host']}", command
                   ] if self._ssh_credentials else ['bash', '-c', command]

        triggers = {
            'trigger:output': {'func': self._handle_trigger_output, 'context': context},
            'trigger:progress': {'func': self._handle_trigger_progress, 'context': context}
        }

        monitor_command(command, triggers, stdout_path=stdout_path, stderr_path=stderr_path)

    def _execute_command(self, command: str, cwd: str = None,
                         console_log_prefix: str = None) -> subprocess.CompletedProcess:
        try:
            command = f"cd {cwd} && {command}" if cwd else command
            command = ['ssh', '-i', self._ssh_credentials['key_path'],
                       f"{self._ssh_credentials['login']}@{self._ssh_credentials['host']}", command
                       ] if self._ssh_credentials else ['bash', '-c', command]

            result = run_command(command)

            if console_log_prefix:
                self._echo_to_file(f"{console_log_prefix}.stdout", result.stdout.decode('utf-8'))
                self._echo_to_file(f"{console_log_prefix}.stderr", result.stderr.decode('utf-8'))

            return result

        except RunCommandError as e:
            if console_log_prefix:
                self._echo_to_file(f"{console_log_prefix}.stdout", e.details['result'].stdout.decode('utf-8'))
                self._echo_to_file(f"{console_log_prefix}.stderr", e.details['result'].stderr.decode('utf-8'))

            raise AdapterRuntimeError({
                'command': command,
                'cwd': cwd,
                'nested': {
                    'id': e.id,
                    'reason': e.reason,
                    'details': e.details
                }
            })

    def _path_exists(self, path: str) -> bool:
        command = ['ssh', '-i', self._ssh_credentials['key_path'],
                   f"{self._ssh_credentials['login']}@{self._ssh_credentials['host']}", f"ls {path}"
                   ] if self._ssh_credentials else ['bash', '-c', f"ls {path}"]

        result = run_command(command, suppress_exception=True)
        return result.returncode == 0

    def _echo_to_file(self, path: str, content: str) -> None:
        self._execute_command(f"echo \"{content}\" > {path}")

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
        working_directory = context['working_directory']
        local_working_directory = context['local_working_directory']
        status: StatusLogger = context['status']

        status.update(f"process_output:{obj_name}", 'started')

        # if ssh_auth IS present, then we perform a remote execution
        # -> copy output data to local working directory
        if self._ssh_credentials is not None:
            status.update(f"process_output:{obj_name}", 'retrieve')

            remote_path = os.path.join(working_directory, obj_name)
            status.update('task', f"copy data objects: {remote_path} -> {local_working_directory}")
            scp_remote_to_local(remote_path, local_working_directory,
                                login=self._ssh_credentials['login'],
                                host=self._ssh_credentials['host'],
                                ssh_key_path=self._ssh_credentials['key_path'])

        # upload the data object to the target DOR
        try:
            status.update(f"process_output:{obj_name}", 'push')
            self._push_data_object(job_id, obj_name, task_descriptor, local_working_directory, status)
            status.update(f"process_output:{obj_name}", 'done')

        except SaaSException as e:
            status.update(f"process_output:{obj_name}", f"failed: id={e.id} reason={e.reason}")

        # remove this thread
        context['threads'].pop(obj_name)
