import os
import time
from stat import S_IREAD, S_IWRITE
from threading import Thread
from typing import Any, Dict

from saas.core.logging import Logging
from saas.core.schemas import GithubCredentials, SSHCredentials
from saas.dor.schemas import GitProcessorPointer
from saas.rti.adapters.base import RTIProcessorAdapter, ProcessorStateWrapper, JobContext, determine_home_path, \
    run_command, scp_local_to_remote, run_command_async, monitor_command, scp_remote_to_local, is_cygwin

from saas.rti.schemas import JobStatus

logger = Logging.get('rti.adapters.native')


def handle_trigger_output(line: str, context: JobContext) -> None:
    obj_name = line.split(':')[2]
    context.add_pending_output(obj_name)


def handle_trigger_progress(line: str, context: JobContext) -> None:
    progress = line.split(':')[2]
    context.update_progress(int(progress))


def handle_trigger_message(line: str, context: JobContext) -> None:
    temp = line.split(':', 3)
    severity = temp[2]
    message = temp[3]
    context.update_message(severity, message)


class OutputProcessor(Thread):
    def __init__(self, owner, context: JobContext, ssh_credentials: SSHCredentials = None):
        super().__init__(name=f"OutputProcessor.{context.job_id()}")
        self._owner = owner
        self._context = context
        self._ssh_credentials = ssh_credentials

        reconnect_info: Dict[str, Any] = context.get_note('reconnect_info')
        self._paths = reconnect_info['paths']

        self._shutdown = False

    def shutdown(self) -> None:
        self._shutdown = True

    def proces_pending(self) -> None:
        # is there are any pending output?
        pending = self._context.get_pending_outputs()
        for obj_name in pending:
            # if we have ssh_credentials, then we perform a remote execution
            # -> copy output data to local working directory
            if self._ssh_credentials is not None:
                remote_path = os.path.join(self._paths['remote_wd'], obj_name)
                logger.info(f"[job:{self._context.job_id()}] copy data objects: "
                            f"{remote_path} -> {self._paths['local_wd']}")

                scp_remote_to_local(remote_path, self._paths['local_wd'], self._ssh_credentials)

            # upload the data object to the target DOR
            logger.info(f"[job:{self._context.job_id()}] push data object to DOR")
            self._owner.push_data_object(obj_name, self._paths['local_wd'], self._context)

    def run(self):
        # keep looping until we are told to shut down
        while not self._shutdown:
            # process any pending output
            self.proces_pending()

            # wait a bit unless we have received the shutdown signal
            if not self._shutdown:
                time.sleep(5)


class RTINativeProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, proc_id: str, gpp: GitProcessorPointer, state_wrapper: ProcessorStateWrapper,
                 node, jobs_path: str, job_concurrency: bool,
                 ssh_credentials: SSHCredentials = None, github_credentials: GithubCredentials = None) -> None:

        super().__init__(proc_id, gpp, state_wrapper, node, jobs_path, job_concurrency)

        # set credentials
        self._ssh_credentials = ssh_credentials
        self._github_credentials = github_credentials

        if self._ssh_credentials:
            # write the key to disk and change file permissions
            self._ssh_credentials.key_path = os.path.join(self._node.datastore, 'rti', f"{proc_id}.ssh_key")
            with open(self._ssh_credentials.key_path, 'w') as f:
                # Make sure that key file ends with a `\n` character or ssh would return "invalid format"
                f.write(f"{ssh_credentials.key}\n")
            os.chmod(self._ssh_credentials.key_path, S_IREAD | S_IWRITE)

            # test if the remote is cygwin
            self._ssh_credentials.is_cygwin = is_cygwin(ssh_credentials)

            # determine remote home path
            self._ssh_credentials.home_path = determine_home_path(ssh_credentials)

            logger.info(f"[adapter:{self._proc_short_id}] using SSH credentials: "
                        f"{self._ssh_credentials.login}@{self._ssh_credentials.host} -> "
                        f"remote machines uses cygwin: {self._ssh_credentials.is_cygwin} "
                        f"home_path: {self._ssh_credentials.home_path}")

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
        logger.debug(f"[adapter:{self._proc_short_id}] clone repository to "
                     f"{'REMOTE:' if self._ssh_credentials else 'LOCAL:'} {self._paths['repo']} "
                     f"and checkout {commit_id}")
        _dir, _name = os.path.split(self._paths['repo'])
        run_command(f"mkdir -p {_dir} && "  # create the parent directory of the repo (if it doesn't exist) 
                    f"cd {_dir} && "  # go to the parent directory
                    f"rm -rf {_name} && "  # delete the repo (if it exists)
                    f"git clone {url} {_name} && "  # clone the repo from the URL
                    f"cd {_name} && "  # go to the repo directory
                    f"git checkout {commit_id}",  # and checkout the correct commit
                    ssh_credentials=self._ssh_credentials)

        time.sleep(2)

        # remove \r characters in install.sh
        run_command(f"sed -i.old 's/\\r$//' {self._paths['install.sh']} && "  # remove \r characters
                    f"sed -i.old 's/\\r$//' {self._paths['execute.sh']} && "  # remove \r characters
                    f"chmod ug+x {self._paths['install.sh']} && "  # make executable
                    f"chmod ug+x {self._paths['execute.sh']}",  # make executable
                    ssh_credentials=self._ssh_credentials)

        time.sleep(2)

        # run install script
        logger.debug(f"[adapter:{self._proc_short_id}] running "
                     f"{'REMOTE:' if self._ssh_credentials else 'LOCAL:'}{self._paths['install.sh']}")
        pid, paths = run_command_async(f"cd {self._paths['adapter']} && "  # go to the adapter directory
                                       f"chmod u+x {self._paths['install.sh']} && "  # ensure it's executable
                                       f"{self._paths['install.sh']} {self._gpp.proc_config}",  # execute
                                       local_output_path=self._paths['local_adapter'],
                                       name='install_sh',
                                       ssh_credentials=self._ssh_credentials)

        monitor_command(pid, paths, ssh_credentials=self._ssh_credentials)

    def shutdown(self) -> None:
        # if we have ssh credentials, delete the key file
        if self._ssh_credentials is not None:
            os.remove(self._ssh_credentials.key_path)
            self._ssh_credentials.key_path = None

    def begin_job_execution(self, local_working_directory: str, context: JobContext) -> None:
        # _home = get_home_directory(self._ssh_credentials)
        if self._ssh_credentials is not None:
            remote_working_directory = \
                self._ssh_credentials.home_path + local_working_directory.replace(os.environ['HOME'], '')
            paths = {
                'local_wd': local_working_directory,
                'remote_wd': remote_working_directory,
                'wd': remote_working_directory
            }

        else:
            paths = {
                'local_wd': local_working_directory,
                'wd': local_working_directory
            }

        # make sure the wd path exists (locally and remotely, if applicable)
        context.put_note('task', f"create working directory at LOCAL:{paths['local_wd']}")
        os.makedirs(paths['local_wd'], exist_ok=True)

        # if ssh_auth IS present, then we perform a remote execution -> copy input data to remote working directory
        if self._ssh_credentials is not None:
            context.put_note('task', f"create working directory at REMOTE:{paths['remote_wd']}")
            run_command(f"mkdir -p {paths['remote_wd']}", ssh_credentials=self._ssh_credentials, timeout=10)

            # copy the input data objects to the remote working directory
            for obj_name in self._input_interface:
                local_path = os.path.join(local_working_directory, obj_name)
                context.put_note('task', f"copy '{obj_name}': LOCAL:{local_path} -> REMOTE:{paths['remote_wd']}")
                scp_local_to_remote(local_path, paths['remote_wd'], self._ssh_credentials)

        # run execute script
        task_msg = f"starting {'REMOTE:' if self._ssh_credentials else 'LOCAL:'}{self._paths['execute.sh']}"
        context.put_note('task', task_msg)
        logger.debug(f"[adapter:{self._proc_short_id}] {task_msg}")
        pid, pid_paths = run_command_async(f"cd {self._paths['adapter']} && "
                                           f"chmod ug+x {self._paths['execute.sh']} && "
                                           f"{self._paths['execute.sh']} {self._gpp.proc_config} {paths['wd']}",
                                           local_output_path=paths['local_wd'],
                                           name='execute_sh',
                                           ssh_credentials=self._ssh_credentials)

        # put a note with reconnect information
        context.put_note('reconnect_info', {
            'paths': paths,
            'pid': pid,
            'pid_paths': pid_paths
        })

        context.update_state(JobStatus.State.RUNNING)
        logger.info(f"[job:{context.job_id()}:{context.state().value}] triggering execution successful")

    def monitor_job_execution(self, context: JobContext) -> None:
        # get reconnect information
        reconnect_info: Dict[str, Any] = context.get_note('reconnect_info')

        # start output object processor thread
        output_processor = OutputProcessor(self, context, self._ssh_credentials)
        output_processor.start()

        # monitor the output of a process
        monitor_command(reconnect_info['pid'], reconnect_info['pid_paths'],
                        ssh_credentials=self._ssh_credentials,
                        triggers={
                             'trigger:output': {'func': handle_trigger_output, 'context': context},
                             'trigger:progress': {'func': handle_trigger_progress, 'context': context},
                             'trigger:message': {'func': handle_trigger_message, 'context': context}
                        }, context=context)

        # tell the output processor to shut down and then wait for the thread to finish
        output_processor.shutdown()
        output_processor.join()

        # process any pending output that might be left
        output_processor.proces_pending()

        # if ssh credentials are present, then we perform a remote execution -> delete the remote working directory
        if self._ssh_credentials is not None:
            remote_wd = reconnect_info['paths']['remote_wd']
            context.put_note('task', f"delete working directory REMOTE:{remote_wd}")
            run_command(f"rm -rf {remote_wd}", ssh_credentials=self._ssh_credentials)

        context.remove_note('task')

    def cancel_job_execution(self, context: JobContext) -> None:
        context.update_state(JobStatus.State.CANCELLED)

    def delete(self) -> None:
        logger.info(f"[adapter:{self._proc_short_id}] deleting adapter contents at "
                    f"{'REMOTE' if self._ssh_credentials else 'LOCAL'}:{self._paths['repo']}.")
        run_command(f"rm -rf {self._paths['repo']}", ssh_credentials=self._ssh_credentials)
