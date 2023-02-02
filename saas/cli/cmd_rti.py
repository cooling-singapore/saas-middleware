import json
import os
from json import JSONDecodeError
from typing import List, Union

import jsonschema
from InquirerPy.base import Choice
from pydantic import ValidationError
from tabulate import tabulate

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_if_missing, prompt_for_string, prompt_for_selection, \
    get_nodes_by_service, prompt_for_confirmation, load_keystore, extract_address, label_data_object
from saas.core.helpers import get_timestamp_now
from saas.dor.proxy import DORProxy
from saas.dor.service import GPP_DATA_TYPE
from saas.core.logging import Logging
from saas.nodedb.proxy import NodeDBProxy
from saas.rest.exceptions import UnsuccessfulRequestError
from saas.rti.proxy import RTIProxy
from saas.rti.schemas import Processor, ProcessorStatus, Task, Job
from saas.dor.schemas import GPPDataObject, ProcessorDescriptor

logger = Logging.get('cli.rti')


def _require_rti(args: dict) -> RTIProxy:
    prompt_if_missing(args, 'address', prompt_for_string,
                      message="Enter the node's REST address",
                      default='127.0.0.1:5001')

    db = NodeDBProxy(extract_address(args['address']))
    if db.get_node().rti_service is False:
        raise CLIRuntimeError(f"Node at {args['address'][0]}:{args['address'][1]} does "
                              f"not provide a RTI service. Aborting.")

    return RTIProxy(extract_address(args['address']))


class RTIProcDeploy(CLICommand):
    def __init__(self) -> None:
        super().__init__('deploy', 'deploys a processor', arguments=[
            Argument('--type', dest='type', action='store', choices=['native', 'docker'],
                     help=f"indicate the type of deployment: 'native' or 'docker'."),
            Argument('--ssh-profile', dest='ssh-profile', action='store',
                     help=f"indicate the SSH profile to be used (if any)."),
            Argument('proc-id', metavar='proc-id', type=str, nargs='?',
                     help="the id of the GPP data object of the processor to be deployed")
        ])

    def execute(self, args: dict) -> None:
        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=False)

        # discover nodes by service
        nodes, _ = get_nodes_by_service(extract_address(args['address']))
        if len(nodes) == 0:
            raise CLIRuntimeError("Could not find any nodes with DOR service in the network. Try again later.")

        # lookup all the GPP data objects
        choices = []
        custodian = {}
        gpp = {}
        for node in nodes:
            dor = DORProxy(node.rest_address)
            result = dor.search(data_type=GPP_DATA_TYPE)
            for item in result:
                meta: GPPDataObject = dor.get_meta(item.obj_id)
                choices.append(Choice(meta.obj_id, f"{meta.obj_id} [{meta.gpp.proc_descriptor.name}] "
                                                   f"{meta.gpp.proc_config}:{meta.gpp.commit_id}"))
                custodian[item.obj_id] = node
                gpp[item.obj_id] = meta.gpp

        # do we have any processors to choose from?
        if len(choices) == 0:
            raise CLIRuntimeError("No processors found for deployment. Aborting.")

        # do we have a processor id?
        if args['proc-id'] is None:
            args['proc-id'] = prompt_for_selection(choices, "Select the processor you would like to deploy:",
                                                   allow_multiple=False)

        # do we have a custodian for this processor id?
        if args['proc-id'] not in custodian:
            raise CLIRuntimeError(f"Custodian of processor {args['proc-id']} not found. Aborting.")

        # do we have a type?
        if not args['type']:
            args['type'] = prompt_for_selection([
                Choice('native', 'Native Deployment'),
                Choice('docker', 'Docker Deployment')
            ], message="Select the deployment type:", allow_multiple=False)

        # should we use an SSH profile?
        ssh_credentials = None
        if args['ssh-profile'] is None:
            if prompt_for_confirmation("Use an SSH profile for deployment?", default=False):
                # get the SSH credentials
                choices = []
                for key in keystore.ssh_credentials.list():
                    ssh_cred = keystore.ssh_credentials.get(key)
                    choices.append(Choice(ssh_cred, f"{key}: {ssh_cred.login}@{ssh_cred.host}"))

                # do we have any profiles to choose from?
                if len(choices) == 0:
                    raise CLIRuntimeError("No SSH profiles found. Aborting.")

                ssh_credentials = prompt_for_selection(
                    choices, "Select the SSH profile to be used for deployment:", allow_multiple=False)

        else:
            # do we have these SSH credentials?
            ssh_credentials = keystore.ssh_credentials.get(args['ssh_profile'])
            if ssh_credentials is None:
                raise CLIRuntimeError(f"SSH profile '{args['ssh_profile']}' found. Aborting.")

        # check if we have Github credentials for this URL
        url = gpp[args['proc-id']].source
        github_credentials = keystore.github_credentials.get(url)
        if github_credentials is not None:
            if not prompt_for_confirmation(f"Found Github credentials '{github_credentials.login}' for {url}. "
                                           f"Use for deployment?", default=True):
                github_credentials = None

        # deploy the processor
        print(f"Deploying processor {args['proc-id']}...", end='')
        try:
            rti.deploy(args['proc-id'], keystore,
                       deployment=args['type'],
                       gpp_custodian=custodian[args['proc-id']].identity.id,
                       ssh_credentials=ssh_credentials,
                       github_credentials=github_credentials)
            print(f"Done")
        except UnsuccessfulRequestError as e:
            print(f"{e.reason} details: {e.details}")


class RTIProcUndeploy(CLICommand):
    def __init__(self):
        super().__init__('undeploy', 'undeploys a processor', arguments=[
            Argument('proc-id', metavar='proc-id', type=str, nargs='*',
                     help="the ids of the processors to be undeployed")
        ])

    def execute(self, args: dict) -> None:
        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=False)

        # get the deployed processors
        deployed = {proc.proc_id: proc for proc in rti.get_deployed()}
        if len(deployed) == 0:
            raise CLIRuntimeError(f"No processors deployed at {args['address']}. Aborting.")

        # do we have a proc_id?
        if not args['proc-id']:
            choices = [Choice(proc.proc_id, f"{proc.gpp.proc_descriptor.name} {proc.gpp.proc_config}:"
                                            f"{proc.gpp.commit_id}") for proc in rti.get_deployed()]
            if not choices:
                raise CLIRuntimeError(f"No processors deployed at {args['address']}")

            args['proc-id'] = prompt_for_selection(choices, message="Select the processor:", allow_multiple=True)

        # do we have a selection?
        if len(args['proc-id']) == 0:
            raise CLIRuntimeError(f"No processors selected. Aborting.")

        # are the processors deployed?
        for proc_id in args['proc-id']:
            if proc_id not in deployed:
                print(f"Processor {proc_id} is not deployed at {args['address']}. Skipping.")
                continue

            # undeploy the processor
            print(f"Undeploy processor {proc_id}...", end='')
            try:
                rti.undeploy(proc_id, keystore)
                print(f"Done")
            except UnsuccessfulRequestError as e:
                print(f"{e.reason} details: {e.details}")


class RTIProcList(CLICommand):
    def __init__(self) -> None:
        super().__init__('list', 'retrieves a list of all deployed processors', arguments=[])

    def execute(self, args: dict) -> None:
        rti = _require_rti(args)
        deployed = rti.get_deployed()
        if len(deployed) == 0:
            print(f"No processors deployed at {args['address']}")
        else:
            print(f"Found {len(deployed)} processor(s) deployed at {args['address'][0]}:{args['address'][1]}:")
            for item in deployed:
                gpp = rti.get_gpp(item.proc_id)
                print(f"{item.proc_id}: [{gpp.proc_descriptor.name}] {gpp.proc_config}:{gpp.commit_id}")


class RTIProcShow(CLICommand):
    def __init__(self) -> None:
        super().__init__('show', 'show details of a deployed processor', arguments=[
            Argument('--proc-id', dest='proc-id', action='store',
                     help=f"the id of the processor")
        ])

    def execute(self, args: dict) -> None:
        rti = _require_rti(args)

        # do we have a proc_id?
        if not args['proc-id']:
            choices = [Choice(proc.proc_id, f"{proc.gpp.proc_descriptor.name} {proc.gpp.proc_config}:"
                                            f"{proc.gpp.commit_id}") for proc in rti.get_deployed()]
            if not choices:
                raise CLIRuntimeError(f"No processors deployed at {args['address']}")

            args['proc-id'] = prompt_for_selection(choices, message="Select the processor:", allow_multiple=False)

        # get the GPP for the proc
        gpp = rti.get_gpp(args['proc-id'])
        print(json.dumps(gpp.proc_descriptor.dict(), indent=4))


class RTIProcStatus(CLICommand):
    def __init__(self) -> None:
        super().__init__('status', 'retrieves the status of all deployed processor and their active and pending '
                                   'jobs (if any)',
                         arguments=[])

    def execute(self, args: dict) -> None:
        rti = _require_rti(args)

        deployed = rti.get_deployed()
        if len(deployed) == 0:
            print(f"No processors deployed at {args['address']}")
        else:
            print(f"Found {len(deployed)} processor(s) deployed at {args['address']}:")
            for item in deployed:
                proc_id = item.proc_id

                status: ProcessorStatus = rti.get_status(proc_id)
                print(f"{proc_id}:{item.gpp.proc_descriptor.name} [{status.state.upper()}] "
                      f"pending={[job.id for job in status.pending]} "
                      f"active={status.active.id if status.active else '(none)'}")


class RTIJobSubmit(CLICommand):
    def __init__(self) -> None:
        super().__init__('submit', 'submit a new job', arguments=[
            Argument('--job', dest='job', action='store',
                     help=f"path to the job descriptor")
        ])

    def _prepare(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address:",
                          default="127.0.0.1:5001")

        self._address = extract_address(args['address'])
        self._db = NodeDBProxy(extract_address(args['address']))
        self._rti = RTIProxy(extract_address(args['address']))
        self._dor = None

        # create identity choices
        self._identity_choices = {}
        for identity in self._db.get_identities().values():
            self._identity_choices[identity.id] = Choice(identity, f"{identity.name}/{identity.email}/{identity.id}")

        # create node choices
        self._node_choices = []
        for node in self._db.get_network():
            # does the node have a DOR?
            if node.dor_service is False:
                continue

            # use the fist eligible node
            if self._dor is None:
                self._dor = DORProxy(node.rest_address)

            # get the identity of the node
            identity = self._db.get_identity(node.identity.id)

            # add the choice
            self._node_choices.append(
                Choice(node, f"{identity.name}/{identity.id} at {node.rest_address}/{node.p2p_address}")
            )

        # create processor choices
        self._proc_choices = {}
        for proc in self._rti.get_deployed():
            self._proc_choices[proc.proc_id] = Choice(proc, f"{proc.proc_id}: [{proc.gpp.proc_descriptor.name}] "
                                                            f"{proc.gpp.proc_config}:{proc.gpp.commit_id}")
        if not self._proc_choices:
            raise CLIRuntimeError(f"No processors deployed at {self._address[0]}:{self._address[1]}. Aborting.")

    def _create_job_input(self, proc_descriptor: ProcessorDescriptor) -> List[Union[Task.InputReference,
                                                                                    Task.InputValue]]:
        job_input = []
        for item in proc_descriptor.input:
            selection = prompt_for_selection([Choice('value', 'by-value'), Choice('reference', 'by-reference')],
                                             f"How to set input '{item.name}' ({item.data_type}:{item.data_format})?")

            if selection == 'value':
                while True:
                    if item.data_schema:
                        print(f"Input '{item.name}' uses schema for validation:\n{item.data_schema}")
                        content = prompt_for_string(f"Enter a valid JSON object:")
                    else:
                        content = prompt_for_string(f"Input '{item.name}' has no schema for validation. "
                                                    f"Enter a valid JSON object:")

                    try:
                        content = json.loads(content)
                    except JSONDecodeError as e:
                        print(f"Problem while parsing JSON object: {e.msg}. Try again.")
                        continue

                    if item.data_schema:
                        try:
                            jsonschema.validate(instance=content, schema=item.data_schema)

                        except jsonschema.exceptions.ValidationError as e:
                            logger.error(e.message)
                            continue

                        except jsonschema.exceptions.SchemaError as e:
                            logger.error(e.message)
                            raise CLIRuntimeError(f"Schema used for input is not valid", details={
                                'schema': item.data_schema
                            })

                    job_input.append(Task.InputValue(name=item.name, type='value', value=content))
                    break

            else:
                # get the data object choices for this input item
                object_choices = []
                for found in self._dor.search(data_type=item.data_type, data_format=item.data_format):
                    object_choices.append(Choice(found.obj_id, label_data_object(found)))

                # do we have any matching objects?
                if len(object_choices) == 0:
                    raise CLIRuntimeError(f"No data objects found that match data type/format ({item.data_type}/"
                                          f"{item.data_format}) of input '{item.name}'. Aborting.")

                # select an object
                obj_id = prompt_for_selection(object_choices,
                                              message=f"Select the data object to be used for input '{item.name}':",
                                              allow_multiple=False)

                job_input.append(Task.InputReference(name=item.name, type='reference', obj_id=obj_id))

        return job_input

    def _create_job_output(self, proc_descriptor: ProcessorDescriptor) -> List[Task.Output]:
        # select the owner for the output data objects
        owner = prompt_for_selection(list(self._identity_choices.values()),
                                     message="Select the owner for the output data objects:",
                                     allow_multiple=False)

        # select the target node for the output data objects
        target = prompt_for_selection(self._node_choices,
                                      message="Select the destination node for the output data objects:",
                                      allow_multiple=False)

        # confirm if access should be restricted
        restricted_access = prompt_for_confirmation("Should access to output data objects be restricted?",
                                                    default=False)

        # create the job output
        job_output = []
        for item in proc_descriptor.output:
            job_output.append(Task.Output(
                name=item.name, owner_iid=owner.id, restricted_access=restricted_access, content_encrypted=False,
                target_node_iid=target.identity.id
            ))

        return job_output

    def execute(self, args: dict) -> None:
        keystore = load_keystore(args, ensure_publication=True)

        # prepare a number of things...
        self._prepare(args)

        # do we have a job descriptor?
        if args['job']:
            # does the file exist?
            if not os.path.isfile(args['job']):
                raise CLIRuntimeError(f"No job descriptor at '{args['job']}'. Aborting.")

            try:
                # read the job descriptor
                job_descriptor = Job.parse_file(args['job'])
            except ValidationError:
                raise CLIRuntimeError(f"Invalid job descriptor. Aborting.")

            # is the processor deployed?
            if job_descriptor.task.proc_id not in self._proc_choices:
                raise CLIRuntimeError(f"Processor {job_descriptor.task.proc_id} is not "
                                      f"deployed at {self._address[0]}:{self._address[1]}. Aborting.")

            proc_id = job_descriptor.task.proc_id
            job_input = job_descriptor.task.input
            job_output = job_descriptor.task.output

        # if we don't have a job descriptor then we obtain all the information interactively
        else:
            # select the processor
            proc: Processor = prompt_for_selection(choices=list(self._proc_choices.values()),
                                                   message="Select the processor for the job:",
                                                   allow_multiple=False)

            # get the descriptor for this processor
            print(f"Processor descriptor: {json.dumps(proc.gpp.proc_descriptor.dict(), indent=4)}")

            # create the job input and output
            proc_id = proc.proc_id
            job_input = self._create_job_input(proc.gpp.proc_descriptor)
            job_output = self._create_job_output(proc.gpp.proc_descriptor)

        # submit the job
        new_job_descriptor = self._rti.submit_job(proc_id, job_input, job_output, with_authorisation_by=keystore)
        print(f"Job submitted: job-id={new_job_descriptor.id}")


class RTIJobList(CLICommand):
    def __init__(self):
        super().__init__('list', 'retrieve a list of all jobs by the user (or all jobs if the user is the node owner)',
                         arguments=[])

    def execute(self, args: dict) -> None:
        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=True)

        try:
            jobs = rti.get_jobs_by_user(keystore)

            if jobs:
                print(f"Found {len(jobs)} jobs:")

                # get all deployed procs
                deployed: list[Processor] = rti.get_deployed()
                deployed: dict[str, Processor] = {proc.proc_id: proc for proc in deployed}

                # headers
                lines = [
                    ['JOB ID', 'OWNER', 'PROC NAME', 'STATE'],
                    ['------', '-----', '---------', '-----']
                ]

                for job in jobs:
                    proc_name = deployed[job.task.proc_id].gpp.proc_descriptor.name \
                        if job.task.proc_id in deployed else 'unknown'

                    status = rti.get_job_status(job.id, with_authorisation_by=keystore)

                    lines.append([job.id, job.task.user_iid, proc_name, status.state])

                print(tabulate(lines, tablefmt="plain"))
                print()

            else:
                print("No jobs found.")

        except UnsuccessfulRequestError as e:
            print(e.reason)


class RTIJobStatus(CLICommand):
    def __init__(self):
        super().__init__('status', 'retrieve the status of a job', arguments=[
            Argument('job-id', metavar='job-id', type=str, nargs='?',
                     help=f"the id of the job")
        ])

    def execute(self, args: dict) -> None:
        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have a job id?
        if not args['job-id']:
            # get all deployed procs
            deployed: list[Processor] = rti.get_deployed()
            deployed: dict[str, Processor] = {proc.proc_id: proc for proc in deployed}

            # get all jobs by this user and select
            choices = []
            for job in rti.get_jobs_by_user(keystore):
                proc_name = deployed[job.task.proc_id].gpp.proc_descriptor.name \
                    if job.task.proc_id in deployed else 'unknown'
                choices.append(Choice(job.id, f"{job.id} at '{proc_name}'"))

            if not choices:
                raise CLIRuntimeError(f"No jobs found.")

            args['job-id'] = prompt_for_selection(choices, message="Select job:", allow_multiple=False)

        try:
            status = rti.get_job_status(args['job-id'], with_authorisation_by=keystore)
            print(f"Status: {json.dumps(status.dict(), indent=4)}")

        except UnsuccessfulRequestError:
            print(f"Job {args['job-id']} not found.")


class RTIJobCancel(CLICommand):
    def __init__(self):
        super().__init__('cancel', 'attempts to cancel a job', arguments=[
            Argument('job-id', metavar='job-id', type=str, nargs='?', help=f"the id of the job")
        ])

    def execute(self, args: dict) -> None:
        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have a job id?
        if not args['job-id']:
            # get all deployed procs
            deployed: list[Processor] = rti.get_deployed()
            deployed: dict[str, Processor] = {proc.proc_id: proc for proc in deployed}

            # get all jobs by this user and select
            choices = []
            for job in rti.get_jobs_by_user(keystore):
                proc_name = deployed[job.task.proc_id].gpp.proc_descriptor.name \
                    if job.task.proc_id in deployed else 'unknown'
                choices.append(Choice(job.id, f"{job.id} at '{proc_name}'"))

            if not choices:
                raise CLIRuntimeError(f"No jobs found.")

            args['job-id'] = prompt_for_selection(choices, message="Select job:", allow_multiple=False)

        try:
            status = rti.cancel_job(args['job-id'], keystore)
            print(f"Done. Status: {status}")

        except UnsuccessfulRequestError as e:
            print(f"{e.reason} details={e.details}")


class RTIJobLogs(CLICommand):
    def __init__(self):
        super().__init__('logs', 'retrieve the logs of a job', arguments=[
            Argument('job-id', metavar='job-id', type=str, nargs='?', help=f"the id of the job"),
            Argument('destination', metavar='destination', type=str, nargs=1, help="directory where to store the logs")

        ])

    def execute(self, args: dict) -> None:
        # do we have a valid destination directory?
        if not args['destination']:
            raise CLIRuntimeError(f"No download path provided")
        elif not os.path.isdir(args['destination'][0]):
            raise CLIRuntimeError(f"Destination path provided is not a directory")

        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have a job id?
        if not args['job-id']:
            # get all deployed procs
            deployed: list[Processor] = rti.get_deployed()
            deployed: dict[str, Processor] = {proc.proc_id: proc for proc in deployed}

            # get all jobs by this user and select
            choices = []
            for job in rti.get_jobs_by_user(keystore):
                proc_name = deployed[job.task.proc_id].gpp.proc_descriptor.name \
                    if job.task.proc_id in deployed else 'unknown'
                choices.append(Choice(job.id, f"{job.id} at '{proc_name}'"))

            if not choices:
                raise CLIRuntimeError(f"No jobs found.")

            args['job-id'] = prompt_for_selection(choices, message="Select job:", allow_multiple=False)

        try:
            download_path = os.path.join(args['destination'][0], f"{args['job-id']}.{get_timestamp_now()}.tar.gz")
            rti.get_job_logs(args['job-id'], keystore, download_path)
            print(f"Done. Logs downloaded to {download_path}")

        except UnsuccessfulRequestError as e:
            print(f"{e.reason} details={e.details}")
