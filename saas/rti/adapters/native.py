import os
import time

import saas.rti.adapters.base as base

from saas.core.logging import Logging
from saas.core.schemas import GithubCredentials, SSHCredentials
from saas.rti.context import JobContext
from saas.dor.schemas import GitProcessorPointer

logger = Logging.get('rti.adapters.native')


class RTINativeProcessorAdapter(base.RTIProcessorAdapter):
    def __init__(self, proc_id: str, gpp: GitProcessorPointer, jobs_path: str, node,
                 ssh_credentials: SSHCredentials = None,
                 github_credentials: GithubCredentials = None,
                 retain_remote_wdirs: bool = False,
                 job_concurrency: bool = False) -> None:
        super().__init__(proc_id, gpp, jobs_path, node, job_concurrency)

        # set credentials
        self._ssh_credentials = ssh_credentials
        self._github_credentials = github_credentials
        self._retain_remote_wdirs = retain_remote_wdirs

        # create the proc-temp directory if doesn't already exist
        self._proc_temp_path = os.path.join(node.datastore, 'proc-temp')
        os.makedirs(self._proc_temp_path, exist_ok=True)

        # create paths
        local_repo_path = os.path.join(node.datastore, 'proc-repositories', proc_id)
        local_adapter_path = os.path.join(local_repo_path, self._gpp.proc_path)

        self._paths = {
            'local_repo': local_repo_path,
            'local_adapter': local_adapter_path,
            'remote_repo': '~'+local_repo_path.replace(os.environ['HOME'], ''),
            'remote_adapter': '~'+local_adapter_path.replace(os.environ['HOME'], '')
        }
        self._paths['repo'] = self._paths['remote_repo'] if self._ssh_credentials else self._paths['local_repo']
        self._paths['adapter'] = \
            self._paths['remote_adapter'] if self._ssh_credentials else self._paths['local_adapter']
        self._paths['install.sh'] = os.path.join(self._paths['adapter'], 'install.sh')
        self._paths['execute.sh'] = os.path.join(self._paths['adapter'], 'execute.sh')

    def startup(self) -> None:
        url = self._gpp.source
        commit_id = self._gpp.commit_id

        # do we have git credentials?
        if self._github_credentials:
            insert = f"{self._github_credentials.login}:{self._github_credentials.personal_access_token}@"
            index = url.find('github.com')
            url = url[:index] + insert + url[index:]

        # clone the repository and checkout the commit id
        logger.debug(f"clone repository to {'REMOTE:' if self._ssh_credentials else 'LOCAL:'} {self._paths['repo']} "
                     f"and checkout {commit_id}")
        _dir, _name = os.path.split(self._paths['repo'])
        base.run_command(f"mkdir -p {_dir} && "  # create the parent directory of the repo (if it doesn't exist) 
                         f"cd {_dir} && "  # go to the parent directory
                         f"rm -rf {_name} && "  # delete the repo (if it exists)
                         f"git clone {url} {_name} && "  # clone the repo from the URL
                         f"cd {_name} && "  # go to the repo directory
                         f"git checkout {commit_id}",  # and checkout the correct commit
                         ssh_credentials=self._ssh_credentials)

        time.sleep(2)

        # remove \r characters in install.sh
        base.run_command(f"sed -i.old 's/\\r$//' {self._paths['install.sh']} && "  # remove \r characters
                         f"sed -i.old 's/\\r$//' {self._paths['execute.sh']} && "  # remove \r characters
                         f"chmod ug+x {self._paths['install.sh']} && "  # make executable
                         f"chmod ug+x {self._paths['execute.sh']}",  # make executable
                         ssh_credentials=self._ssh_credentials)

        time.sleep(2)

        # run install script
        logger.debug(f"running {'REMOTE:' if self._ssh_credentials else 'LOCAL:'}{self._paths['install.sh']}")
        pid, paths = base.run_command_async(f"cd {self._paths['adapter']} && "  # go to the adapter directory
                                            f"chmod u+x {self._paths['install.sh']} && "  # ensure it's executable
                                            f"{self._paths['install.sh']} {self._gpp.proc_config}",  # execute
                                            local_output_path=self._paths['local_adapter'],
                                            name='install_sh',
                                            ssh_credentials=self._ssh_credentials)

        base.monitor_command(pid, paths, ssh_credentials=self._ssh_credentials)

    def shutdown(self) -> None:
        pass

    def execute(self, local_working_directory: str, context: JobContext) -> None:
        _home = base.get_home_directory(self._ssh_credentials)
        paths = {
            'local_wd': local_working_directory,
            'remote_wd': _home + local_working_directory.replace(os.environ['HOME'], '')
        }
        paths['wd'] = paths['remote_wd'] if self._ssh_credentials else paths['local_wd']

        # make sure the wd path exists (locally and remotely, if applicable)
        context.make_note('task', f"create working directory at LOCAL:{paths['local_wd']}")
        os.makedirs(paths['local_wd'], exist_ok=True)

        # if ssh_auth IS present, then we perform a remote execution -> copy input data to remote working directory
        if self._ssh_credentials is not None:
            context.make_note('task', f"create working directory at REMOTE:{paths['remote_wd']}")
            base.run_command(f"mkdir -p {paths['remote_wd']}", ssh_credentials=self._ssh_credentials, timeout=10)

            # copy the input data objects to the remote working directory
            for obj_name in self._input_interface:
                local_path = os.path.join(local_working_directory, obj_name)
                context.make_note('task', f"copy '{obj_name}': LOCAL:{local_path} -> REMOTE:{paths['remote_wd']}")
                base.scp_local_to_remote(local_path, paths['remote_wd'], self._ssh_credentials)

        # run execute script
        task_msg = f"starting {'REMOTE:' if self._ssh_credentials else 'LOCAL:'}{self._paths['execute.sh']}"
        context.make_note('task', task_msg)
        logger.debug(task_msg)
        pid, pid_paths = base.run_command_async(f"cd {self._paths['adapter']} && "
                                                f"chmod ug+x {self._paths['execute.sh']} && "
                                                f"{self._paths['execute.sh']} {self._gpp.proc_config} {paths['wd']}",
                                                local_output_path=paths['local_wd'],
                                                name='execute_sh',
                                                ssh_credentials=self._ssh_credentials)

        # make this job resumable
        context.add_reconnect_info(paths, pid, pid_paths)

    def connect_and_monitor(self, context: JobContext) -> None:
        # monitor the output of a process
        base.monitor_command(context.reconnect_info.pid, context.reconnect_info.pid_paths,
                             ssh_credentials=self._ssh_credentials,
                             triggers={
                                 'trigger:output': {'func': self._handle_trigger_output, 'context': context},
                                 'trigger:progress': {'func': self._handle_trigger_progress, 'context': context},
                                 'trigger:message': {'func': self._handle_trigger_message, 'context': context}
                             }, context=context)

        # wait for all outputs to be processed (or an exception to appear)
        while context.n_tasks() > 0:
            # do we have an exception?
            if context.exception():
                raise context.exception()

            context.make_note('task', f"wait for all outputs to be processed: remaining={context.n_tasks()}")
            time.sleep(1)

        # if ssh credentials are present, then we perform a remote execution -> delete the remote working directory
        if not self._retain_remote_wdirs and self._ssh_credentials is not None:
            remote_wd = context.reconnect_info.paths['remote_wd']
            context.make_note('task', f"delete working directory REMOTE:{remote_wd}")
            base.run_command(f"rm -rf {remote_wd}", ssh_credentials=self._ssh_credentials)

        context.remove_note('task')

    def delete(self) -> None:
        logger.info(f"[adapter:{self._proc_id}] deleting adapter contents at "
                    f"{'REMOTE' if self._ssh_credentials else 'LOCAL'}:{self._paths['repo']}.")
        base.run_command(f"rm -rf {self._paths['repo']}", ssh_credentials=self._ssh_credentials)

    def _handle_trigger_output(self, line: str, context: JobContext) -> None:
        obj_name = line.split(':')[2]
        context.add_task(target=self._process_output, args=(obj_name, context,))

    def _handle_trigger_progress(self, line: str, context: JobContext) -> None:
        progress = line.split(':')[2]
        context.progress = int(progress)

    def _handle_trigger_message(self, line: str, context: JobContext) -> None:
        temp = line.split(':', 3)
        severity = temp[2]
        message = temp[3]
        context.message(severity, message)

    def _process_output(self, obj_name: str, context: JobContext) -> None:
        context.make_note(f"process_output:{obj_name}", 'started')

        # if ssh_auth IS present, then we perform a remote execution
        # -> copy output data to local working directory
        paths = context.reconnect_info.paths
        if self._ssh_credentials is not None:
            context.make_note(f"process_output:{obj_name}", 'retrieve')

            remote_path = os.path.join(paths['remote_wd'], obj_name)
            context.make_note('task', f"copy data objects: {remote_path} -> {paths['local_wd']}")

            base.scp_remote_to_local(remote_path, paths['local_wd'], self._ssh_credentials)
            context.remove_note('task')

        # upload the data object to the target DOR
        context.make_note(f"process_output:{obj_name}", 'push')
        self._push_data_object(obj_name, paths['local_wd'], context)
        context.make_note(f"process_output:{obj_name}", 'done')
