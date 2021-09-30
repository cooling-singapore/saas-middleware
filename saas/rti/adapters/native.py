import json
import logging
import os
import subprocess

from jsonschema import validate

from saas.exceptions import RunCommandError
from saas.helpers import run_command, scp_local_to_remote, scp_remote_to_local
from saas.keystore.assets.credentials import SSHCredentials, GithubCredentials
from saas.rti.adapters.adapters import RTIProcessorAdapter
from saas.rti.exceptions import AdapterRuntimeError, SSHConnectionError
from saas.rti.status import StatusLogger
from saas.schemas import git_proc_pointer_schema

logger = logging.getLogger('rti.adapters.native')


class RTINativeProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, proc_id: str, proc_descriptor: dict, obj_content_path: str, jobs_path: str, node,
                 ssh_credentials: SSHCredentials = None,
                 github_credentials: GithubCredentials = None) -> None:
        super().__init__(proc_id, proc_descriptor, jobs_path, node)

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

    def execute(self, task_descriptor: dict, local_working_directory: str, status_logger: StatusLogger) -> None:
        # specify the working directory
        working_directory = local_working_directory.replace(os.environ['HOME'], '$HOME')

        # if ssh_auth IS present, then we perform a remote execution -> copy input data to remote working directory
        if self._ssh_credentials is not None:
            # test the connection
            self._test_ssh_connection()

            # create the remote working directory
            status_logger.update('task', f"create remote working directory at {working_directory}")
            self._execute_command(f"mkdir -p {working_directory}")

            # copy the input data objects to the remote working directory
            for obj_name in self._input_interface:
                local_path = os.path.join(local_working_directory, obj_name)
                status_logger.update('task', f"copy data objects: {local_path} -> {working_directory}")
                scp_local_to_remote(local_path, working_directory,
                                    login=self._ssh_credentials.login,
                                    host=self._ssh_credentials.host,
                                    ssh_key_path=self._ssh_credentials.key_path)

        # run execute script
        status_logger.update('task', f"run execute.sh: config={self._gpp['proc_config']} "
                                     f"working_directory={working_directory} "
                                     f"processor_path={self._processor_path}")
        self._execute_command(f"./execute.sh {self._gpp['proc_config']} {working_directory}",
                              cwd=self._processor_path,
                              console_log_prefix=os.path.join(working_directory, "execute.sh"))

        # if ssh_auth IS present, then we perform a remote execution -> copy output data to local working directory
        if self._ssh_credentials is not None:
            # copy the output data objects to the local working directory
            for obj_name in self._output_interface:
                remote_path = os.path.join(working_directory, obj_name)
                status_logger.update('task', f"copy data objects: {remote_path} -> {local_working_directory}")
                scp_remote_to_local(remote_path, local_working_directory,
                                    login=self._ssh_credentials.login,
                                    host=self._ssh_credentials.host,
                                    ssh_key_path=self._ssh_credentials.key_path)

            # delete remote working directory
            status_logger.update('task', f"delete remote working directory: {working_directory}")
            self._execute_command(f"rm -rf {working_directory}")

            msg = f"delete remote working directory at {working_directory}"
            status_logger.update('status', msg)

        status_logger.remove('task')

    def _test_ssh_connection(self):
        if self._ssh_credentials:
            command = ['ssh', '-i', self._ssh_credentials.key_path,
                       f"{self._ssh_credentials.login}@{self._ssh_credentials.host}", 'exit']
            result = run_command(command, suppress_exception=True)
            if result.returncode != 0:
                raise SSHConnectionError({
                    'command': command,
                    'result': result
                })

    def _execute_command(self, command: str, cwd: str = None, console_log_prefix: str = None) -> subprocess.CompletedProcess:
        try:
            command = f"cd {cwd} && {command}" if cwd else command
            command = ['ssh', '-i', self._ssh_credentials.key_path,
                       f"{self._ssh_credentials.login}@{self._ssh_credentials.host}", command
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
        command = ['ssh', '-i', self._ssh_credentials.key_path,
                   f"{self._ssh_credentials.login}@{self._ssh_credentials.host}", f"ls {path}"
                   ] if self._ssh_credentials else ['bash', '-c', f"ls {path}"]

        result = run_command(command, suppress_exception=True)
        return result.returncode == 0

    def _echo_to_file(self, path: str, content: str) -> None:
        self._execute_command(f"echo \"{content}\" > {path}")
