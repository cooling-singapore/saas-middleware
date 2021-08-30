import json
import logging
import os
import subprocess
import traceback

from jsonschema import validate

from saas.keystore.assets.credentials import SSHCredentials, GithubCredentials
from saas.rti.adapters.adapters import RTITaskProcessorAdapter
from saas.rti.status import StatusLogger
from saas.schemas import git_proc_pointer_schema

logger = logging.getLogger('rti.adapters.native')


class RTINativeProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, proc_descriptor, obj_content_path, node,
                 ssh_credentials: SSHCredentials = None,
                 github_credentials: GithubCredentials = None):
        super().__init__(proc_id, proc_descriptor, node)

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

    def startup(self):
        # clone the repository
        self._clone_repository()

        # install the processor
        self._install()

    def execute(self, task_descriptor: dict, local_working_directory: str, status_logger: StatusLogger):
        try:
            # specify the working directory
            working_directory = local_working_directory.replace(os.environ['HOME'], '$HOME')

            # if ssh_auth IS present, then we perform a remote execution -> copy input data to remote working directory
            if self._ssh_credentials is not None:
                # create the remote working directory
                msg = f"create remote working directory at {working_directory}"
                status_logger.update('status', msg)
                logger.info(msg)
                result = self._execute_command(f"mkdir -p {working_directory}")
                if result.returncode != 0:
                    raise Exception(
                        f"Failed to create remote working directory at {working_directory}: {result}")

                # copy the input data objects to the remote working directory
                for obj_name in self._input_interface:
                    local_path = os.path.join(local_working_directory, obj_name)
                    msg = f"copy local:{local_path} -> remote:{working_directory}"
                    status_logger.update('status', msg)
                    logger.info(msg)
                    result = self._copy_local_to_remote(local_path, working_directory)
                    if result.returncode != 0:
                        raise Exception(f"Failed to copy local:{local_path} -> remote:{working_directory}: {result}")

            # run execute script
            msg = f"running execute.sh: config={self._gpp['proc_config']} working_directory={working_directory} "\
                  f"processor_path={self._processor_path}"
            status_logger.update('status', msg)
            logger.info(msg)
            result = self._execute_command(f"./execute.sh {self._gpp['proc_config']} {working_directory}",
                                           cwd=self._processor_path)
            self._write_to_file(os.path.join(working_directory, "execute.sh.stdout"), result.stdout.decode('utf-8'))
            self._write_to_file(os.path.join(working_directory, "execute.sh.stderr"), result.stderr.decode('utf-8'))
            if result.returncode != 0:
                raise Exception(f"Could not successfully run execute script: {result}")

            # if ssh_auth IS present, then we perform a remote execution -> copy output data to local working directory
            if self._ssh_credentials is not None:
                # copy the output data objects to the local working directory
                for obj_name in self._output_interface:
                    remote_path = os.path.join(working_directory, obj_name)
                    msg = f"copy remote:{remote_path} -> local:{local_working_directory}"
                    status_logger.update('status', msg)
                    logger.info(msg)
                    result = self._copy_remote_to_local(remote_path, local_working_directory)
                    if result.returncode != 0:
                        raise Exception(f"Failed to copy remote:{remote_path} -> local:{local_working_directory}: {result}")

                # delete remote working directory
                msg = f"delete remote working directory at {working_directory}"
                status_logger.update('status', msg)
                logger.info(msg)
                result = self._execute_command(f"rm -rf {working_directory}")
                if result.returncode != 0:
                    raise Exception(
                        f"Failed to delete remote working directory at {working_directory}: {result}")

            status_logger.remove('status')
            logger.info(f"running execute.sh was SUCCESSFUL")
            return True

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            status_logger.update('trace', trace)

            status_logger.remove('status')
            logger.info(f"running execute.sh was UNSUCCESSFUL: {trace}")
            return False

    def _clone_repository(self):
        url = self._gpp['source']
        commit_id = self._gpp['commit_id']

        # check if the repository has already been cloned
        if self._path_exists(self._repo_home):
            logger.info(f"repository already exists at {self._repo_home}.")
        else:
            logger.info(f"cloning repository {url} to {self._repo_home}.")

            # do we have git credentials?
            github_cred = self._node.keystore.get_asset('github-credentials')
            if github_cred:
                # do we have credentials for this repo?
                cred = github_cred.get(url)
                if cred:
                    insert = f"{cred.login}:{cred.personal_access_token}@"
                    index = url.find('github.com')
                    url = url[:index] + insert + url[index:]

            command = f"git clone {url} {self._repo_home}"
            logger.debug(f"attemping to execute: {command}")
            result = self._execute_command(command)
            if result.returncode != 0:
                raise Exception(f"Failed to clone repository: {result}")

        # checkout the commit
        logger.info(f"checkout commit {commit_id}")
        result = self._execute_command(f"cd {self._repo_home} && git checkout {commit_id}")
        if result.returncode != 0:
            raise Exception(f"Failed to checkout commit with id={commit_id}")

    def _install(self):
        logger.info(f"check if install.sh and execute.sh scripts exist")
        for script in ['install.sh', 'execute.sh']:
            # check if the script exists
            script_path = os.path.join(self._processor_path, script)
            if not self._path_exists(script_path):
                raise FileNotFoundError(f"Could not find '{script}' script at {script_path}")

            # make script executable
            result = self._execute_command(f"chmod u+x {script_path}")
            if result.returncode != 0:
                raise Exception(f"Could not make '{script}' script at {script_path} executable: {result}")

        # run install script
        logger.info(f"running install.sh...")
        result = self._execute_command(f"./install.sh {self._gpp['proc_config']}", cwd=self._processor_path)
        self._write_to_file(os.path.join(self._processor_path, "install.sh.stdout"), result.stdout.decode('utf-8'))
        self._write_to_file(os.path.join(self._processor_path, "install.sh.stderr"), result.stderr.decode('utf-8'))
        if result.returncode != 0:
            raise Exception(f"Could not successfully run install script at {script_path}: {result}")

        logger.info("done running install.sh")

    def _run_script(self, working_directory, script_name, args=None):
        # check if script exists
        script_path = os.path.join(self._processor_path, script_name)
        if not self._path_exists(script_path):
            raise FileNotFoundError(f"Could not find script at {script_path}")

        # make script executable
        result = self._execute_command(f"chmod u+x {script_path}")
        if result.returncode != 0:
            raise Exception(f"Could not make script at {script_path} executable: {result}")

        # run script
        result = self._execute_command(f"./{script_name} {self._gpp['proc_config']}"
                                       f"{args if args else ''}", cwd=self._processor_path)
        self._write_to_file(os.path.join(working_directory, f"{script_name}.stdout"), result.stdout.decode('utf-8'))
        self._write_to_file(os.path.join(working_directory, f"{script_name}.stderr"), result.stderr.decode('utf-8'))
        if result.returncode != 0:
            raise Exception(f"Could not execute script at {script_path}: {result}")

    def _path_exists(self, path):
        result = self._execute_command(f"ls {path}")
        return result.returncode == 0

    def _execute_command(self, command, cwd=None):
        command = f"cd {cwd} && {command}" if cwd else command
        command = ['ssh', '-i', self._ssh_credentials.key_path,
                   f"{self._ssh_credentials.login}@{self._ssh_credentials.host}", command] \
            if self._ssh_credentials else ['bash', '-c', command]

        return subprocess.run(command, capture_output=True)

    def _copy_local_to_remote(self, local_path, remote_path):
        remote_path = remote_path.replace("$HOME", ".")
        return subprocess.run(['scp', '-i', self._ssh_credentials.key_path, local_path,
                               f"{self._ssh_credentials.login}@{self._ssh_credentials.host}:{remote_path}"],
                              capture_output=True)

    def _copy_remote_to_local(self, remote_path, local_path):
        remote_path = remote_path.replace("$HOME", ".")
        return subprocess.run(['scp', '-i', self._ssh_credentials.key_path,
                               f"{self._ssh_credentials.login}@{self._ssh_credentials.host}:{remote_path}", local_path],
                              capture_output=True)

    def _write_to_file(self, path, content):
        return self._execute_command(f"echo \"{content}\" > {path}")
