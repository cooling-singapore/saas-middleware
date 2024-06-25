import datetime
import json
import os
from json import JSONDecodeError
from typing import List, Union, Optional, Dict

import jsonschema
from InquirerPy.base import Choice
from pydantic import ValidationError
from tabulate import tabulate

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_if_missing, prompt_for_string, prompt_for_selection, \
    get_nodes_by_service, prompt_for_confirmation, load_keystore, extract_address, label_data_object, shorten_id, \
    label_identity
from saas.dor.proxy import DORProxy
from saas.core.logging import Logging
from saas.helpers import determine_default_rest_address
from saas.nodedb.proxy import NodeDBProxy
from saas.rest.exceptions import UnsuccessfulRequestError
from saas.rti.proxy import RTIProxy
from saas.rti.schemas import Processor, Task, JobStatus, Job
from saas.dor.schemas import ProcessorDescriptor, DataObject

logger = Logging.get('cli')


def _require_rti(args: dict) -> RTIProxy:
    prompt_if_missing(args, 'address', prompt_for_string,
                      message="Enter the node's REST address",
                      default=determine_default_rest_address())

    db = NodeDBProxy(extract_address(args['address']))
    if db.get_node().rti_service is False:
        raise CLIRuntimeError(f"Node at {args['address'][0]}:{args['address'][1]} does "
                              f"not provide a RTI service. Aborting.")

    return RTIProxy(extract_address(args['address']))


def proc_info(proc: Processor) -> str:
    if proc.gpp:
        return (f"{shorten_id(proc.id)}: {proc.gpp.proc_descriptor.name} [{proc.state}] "
                f"{proc.gpp.repository}@{proc.gpp.commit_id[:6]}...")
    else:
        return f"{shorten_id(proc.id)} [{proc.state}] (no GPP available yet)"


def job_label(job: Job, status: JobStatus, deployed: Dict[str, Processor]) -> str:
    proc_name = deployed[job.task.proc_id].gpp.proc_descriptor.name \
        if job.task.proc_id in deployed else '(unknown processor)'

    result = f"{job.id} [{status.state}] {shorten_id(job.task.user_iid)}@{proc_name}"
    if job.task.description:
        result = result + f" {job.task.description}"
    return result


class RTIProcDeploy(CLICommand):
    def __init__(self) -> None:
        super().__init__('deploy', 'deploys a processor', arguments=[
            Argument('proc-id', metavar='proc-id', type=str, nargs='?',
                     help="the id of the PDI data object of the processor to be deployed")
        ])

    def execute(self, args: dict) -> Optional[dict]:
        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=False)

        # discover nodes by service
        nodes, _ = get_nodes_by_service(extract_address(args['address']))
        if len(nodes) == 0:
            raise CLIRuntimeError("Could not find any nodes with DOR service in the network. Try again later.")

        # lookup all the PDI data objects
        choices = []
        custodian = {}
        for node in nodes:
            dor = DORProxy(node.rest_address)
            result = dor.search(data_type='ProcessorDockerImage')
            for item in result:
                pdi: DataObject = dor.get_meta(item.obj_id)
                proc_descriptor = ProcessorDescriptor.parse_obj(pdi.tags['proc_descriptor'])

                choices.append(Choice(pdi.obj_id, f"{proc_descriptor.name} <{shorten_id(pdi.obj_id)}> "
                                                  f"{pdi.tags['repository']}:{pdi.tags['commit_id'][:6]}..."))
                custodian[item.obj_id] = node

        # do we have any processors to choose from?
        if len(choices) == 0:
            raise CLIRuntimeError("No processors found for deployment. Aborting.")

        # do we have a processor id?
        if args['proc-id'] is None:
            args['proc-id'] = prompt_for_selection(choices, "Select the processor you would like to deploy:",
                                                   allow_multiple=False)

        # do we have a custodian for this processor id?
        if args['proc-id'] not in custodian:
            raise CLIRuntimeError(f"Custodian of processor {shorten_id(args['proc-id'])} not found. Aborting.")

        # deploy the processor
        print(f"Deploying processor {shorten_id(args['proc-id'])}...", end='')
        result = {}
        try:
            result['proc'] = rti.deploy(args['proc-id'], keystore)
            print("Done")

        except UnsuccessfulRequestError as e:
            print(f"{e.reason} details: {e.details}")

        return result


class RTIProcUndeploy(CLICommand):
    def __init__(self):
        super().__init__('undeploy', 'undeploys a processor', arguments=[
            Argument('proc-id', metavar='proc-id', type=str, nargs='*',
                     help="the ids of the processors to be undeployed")
        ])

    def execute(self, args: dict) -> Optional[dict]:
        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=False)

        # get the deployed processors
        deployed = {proc.id: proc for proc in rti.get_all_procs()}
        if len(deployed) == 0:
            raise CLIRuntimeError(f"No processors deployed at {args['address']}. Aborting.")

        # do we have a proc_id?
        if not args['proc-id']:
            choices = [Choice(proc.id, proc_info(proc)) for proc in rti.get_all_procs()]
            if not choices:
                raise CLIRuntimeError(f"No processors deployed at {args['address']}")

            args['proc-id'] = prompt_for_selection(choices, message="Select the processor:", allow_multiple=True)

        # do we have a selection?
        if len(args['proc-id']) == 0:
            raise CLIRuntimeError("No processors selected. Aborting.")

        # are the processors deployed?
        result = {}
        for proc_id in args['proc-id']:
            if proc_id not in deployed:
                print(f"Processor {proc_id} is not deployed at {args['address']}. Skipping.")
                continue

            # are there any jobs pending for this processor?
            jobs = rti.get_jobs_by_proc(proc_id)
            if len(jobs) > 0:
                if not prompt_for_confirmation(f"Processor {proc_id} has pending/active jobs. Proceed to undeploy "
                                               f"processor? If yes, all pending/active jobs will be purged.",
                                               default=False):
                    continue

            # undeploy the processor
            print(f"Undeploying processor {proc_id}...", end='')
            try:
                result[proc_id] = rti.undeploy(proc_id, keystore)
                print("Done")
            except UnsuccessfulRequestError as e:
                print(f"{e.reason} details: {e.details}")

        return result


class RTIProcList(CLICommand):
    def __init__(self) -> None:
        super().__init__('list', 'retrieves a list of all deployed processors', arguments=[])

    def execute(self, args: dict) -> Optional[dict]:
        rti = _require_rti(args)
        deployed = rti.get_all_procs()
        if len(deployed) == 0:
            print(f"No processors deployed at {args['address']}")
        else:
            print(f"Found {len(deployed)} processor(s) deployed at {args['address']}:")
            for proc in deployed:
                print(f"- {proc_info(proc)}")

        return {
            'deployed': deployed
        }


class RTIProcShow(CLICommand):
    def __init__(self) -> None:
        super().__init__('show', 'show details of a deployed processor', arguments=[
            Argument('--proc-id', dest='proc-id', action='store',
                     help="the id of the processor")
        ])

    def execute(self, args: dict) -> Optional[dict]:
        rti = _require_rti(args)

        # do we have a proc_id?
        if not args['proc-id']:
            choices = [Choice(proc.id, proc_info(proc)) for proc in rti.get_all_procs()]
            if not choices:
                raise CLIRuntimeError(f"No processors deployed at {args['address']}")

            args['proc-id'] = prompt_for_selection(choices, message="Select the processor:", allow_multiple=False)

        # get the proc and the jobs
        proc = rti.get_proc(args['proc-id'])
        jobs = rti.get_jobs_by_proc(proc.id)

        # print detailed information
        print("Processor Information:")
        print(f"- Id: {proc.id}")
        print(f"- State: {proc.state}")
        if proc.gpp:
            proc_desc = proc.gpp.proc_descriptor
            print(f"- Name: {proc_desc.name}")
            print(f"- Image: {proc.image_name}")
            input_items = '\n   '.join([f"{i.name} -> {i.data_type}:{i.data_format}" for i in proc_desc.input])
            print(f"- Input:\n   {input_items}")
            output_items = '\n   '.join([f"{i.name} -> {i.data_type}:{i.data_format}" for i in proc_desc.output])
            print(f"- Output:\n   {output_items}")
        else:
            print(f"- Image: {proc.image_name}")
        print(f"- Error: {proc.error if proc.error else '(none)'}")
        print(f"- Jobs: {[job.id for job in jobs] if len(jobs) > 0 else '(none)'}")

        return {
            'processor': proc,
            'jobs': jobs
        }


class RTIJobSubmit(CLICommand):
    def __init__(self) -> None:
        super().__init__('submit', 'submit a new job', arguments=[
            Argument('--task', dest='task', action='store',
                     help="path to the task descriptor")
        ])

    def _prepare(self, args: dict) -> None:
        address = extract_address(args['address'])

        # create identity choices
        self._db = NodeDBProxy(address)
        self._identity_choices = {}
        for identity in self._db.get_identities().values():
            self._identity_choices[identity.id] = Choice(identity, label_identity(identity))

        # create node choices
        self._dor = None
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
                Choice(node, f"{shorten_id(identity.id)}: {identity.name} at "
                             f"{node.rest_address[0]}:{node.rest_address[1]}")
            )

        # create processor choices
        self._rti = RTIProxy(address)
        no_gpp_procs = []
        self._proc_choices = {}
        for proc in self._rti.get_all_procs():
            if proc.gpp is None:
                no_gpp_procs.append(shorten_id(proc.id))
            else:
                self._proc_choices[proc.id] = Choice(proc, proc_info(proc))

        # do we have processors without GPPs?
        if len(no_gpp_procs) > 0:
            print(f"Ignoring processors without GPP (they are probably still deploying): {', '.join(no_gpp_procs)}")

        # do we have processor choices?
        if not self._proc_choices:
            raise CLIRuntimeError(f"No processors deployed at {address[0]}:{address[1]}. Aborting.")

    def _create_job_input(self, proc_desc: ProcessorDescriptor) -> List[Union[Task.InputReference, Task.InputValue]]:
        job_input = []
        for item in proc_desc.input:
            print(f"Specify input interface item "
                  f"\033[1m'{item.name}'\033[0m with data type/format "
                  f"\033[1m{item.data_type}/{item.data_format}\033[0m")
            selection = prompt_for_selection([Choice('value', 'by-value'), Choice('reference', 'by-reference')],
                                             "How to specify?")

            if selection == 'value':
                while True:
                    if item.data_schema:
                        print(f"JSON schema available: \033[1m yes\033[0m\n{json.dumps(item.data_schema, indent=2)}")
                    else:
                        print("JSON schema available: \033[1m no\033[0m")
                    content = prompt_for_string("Enter a valid JSON object:")

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
                            raise CLIRuntimeError("Schema used for input is not valid", details={
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

                job_input.append(Task.InputReference(name=item.name, type='reference', obj_id=obj_id,
                                                     user_signature=None, c_hash=None))

        return job_input

    def _create_job_output(self, proc_desc: ProcessorDescriptor) -> List[Task.Output]:
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
        for item in proc_desc.output:
            job_output.append(Task.Output(
                name=item.name, owner_iid=owner.id, restricted_access=restricted_access, content_encrypted=False,
                target_node_iid=target.identity.id
            ))

        return job_output

    def execute(self, args: dict) -> Optional[dict]:
        keystore = load_keystore(args, ensure_publication=True)

        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address:",
                          default=determine_default_rest_address())

        # do some preparation
        self._prepare(args)

        # do we have a task descriptor?
        if args['task']:
            # does the file exist?
            if not os.path.isfile(args['task']):
                raise CLIRuntimeError(f"No task descriptor at '{args['task']}'. Aborting.")

            # read the job descriptor
            try:
                task = Task.parse_file(args['task'])
            except ValidationError as e:
                raise CLIRuntimeError(f"Invalid task descriptor: {e.errors()}. Aborting.")

            # is the processor deployed?
            if task.proc_id not in self._proc_choices:
                raise CLIRuntimeError(f"Processor {task.proc_id} is not deployed at {args['address']}. "
                                      f"Aborting.")

            proc_id = task.proc_id
            job_input = task.input
            job_output = task.output

        # if we don't have a job descriptor then we obtain all the information interactively
        else:
            # select the processor
            proc: Processor = prompt_for_selection(choices=list(self._proc_choices.values()),
                                                   message="Select the processor for the job:",
                                                   allow_multiple=False)

            # get the descriptor for this processor
            # print(f"Processor descriptor: {json.dumps(proc.gpp.proc_descriptor.dict(), indent=4)}")

            # create the job input and output
            proc_id = proc.id
            job_input = self._create_job_input(proc.gpp.proc_descriptor)
            job_output = self._create_job_output(proc.gpp.proc_descriptor)

        # submit the job
        job = self._rti.submit_job(proc_id, job_input, job_output, with_authorisation_by=keystore)
        print(f"Job submitted: {job.id}")

        return {
            'job': job
        }


class RTIJobList(CLICommand):
    def __init__(self):
        super().__init__('list', 'retrieve a list of all jobs by the user (or all jobs if the user is the node owner)',
                         arguments=[
                             Argument('--period', dest='period', action='store',
                                      help="time period to consider using format <number><unit> where unit can be one "
                                           "of these ('h': hours, 'd': days, 'w': weeks). Default is '1d', i.e., one "
                                           "day.")
                         ])

    def execute(self, args: dict) -> Optional[dict]:
        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=True)

        # determine time period
        if 'period' in args and args['period'] is not None:
            try:
                unit = args['period'][-1:]
                number = int(args['period'][:-1])
                multiplier = {'h': 1, 'd': 24, 'w': 7*24}
                period = number * multiplier[unit]
                print(f"Listing all jobs submitted within time period of {number}{unit} -> {period} hours")

            except Exception:
                print(f"Invalid time period '{args['period']}. Listing currently active jobs only.")
                period = None
        else:
            print("No time period provided. Listing currently active jobs only.")
            period = None

        # get all jobs in that time period
        try:
            jobs = rti.get_jobs_by_user(keystore, period=period)
            if jobs:
                # get all deployed procs
                deployed: dict[str, Processor] = {proc.id: proc for proc in rti.get_all_procs()}

                # headers
                lines = [
                    ['SUBMITTED', 'JOB ID', 'OWNER', 'PROC NAME', 'STATE', 'DESCRIPTION'],
                    ['---------', '------', '-----', '---------', '-----', '-----------']
                ]

                # prepare lines unsorted
                unsorted = []
                for job in jobs:
                    proc_name = deployed[job.task.proc_id].gpp.proc_descriptor.name \
                        if job.task.proc_id in deployed else 'unknown'

                    status = rti.get_job_status(job.id, with_authorisation_by=keystore)

                    unsorted.append([job.t_submitted, job.id, shorten_id(job.task.user_iid), proc_name, status.state,
                                     job.task.description if job.task.description else 'none'])

                # sort and add to lines
                for line in sorted(unsorted, key=lambda x: x[0]):
                    line[0] = datetime.datetime.fromtimestamp(line[0]/1000.0).strftime('%Y-%m-%d %H:%M:%S')
                    lines.append(line)

                print(tabulate(lines, tablefmt="plain"))
                print()

            else:
                print("No jobs found.")

            return {
                'jobs': jobs
            }

        except UnsuccessfulRequestError as e:
            print(e.reason)


class RTIJobStatus(CLICommand):
    def __init__(self):
        super().__init__('status', 'retrieve the status of a job', arguments=[
            Argument('job-id', metavar='job-id', type=str, nargs='?', help="the id of the job"),
            Argument('--period', dest='period', action='store',
                     help="time period to consider using format <number><unit> where unit can be one "
                          "of these ('h': hours, 'd': days, 'w': weeks). Default is '1d', i.e., one "
                          "day.")

        ])

    def execute(self, args: dict) -> Optional[dict]:
        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have a job id?
        if not args['job-id']:
            # get all deployed procs
            deployed: Dict[str, Processor] = {proc.id: proc for proc in rti.get_all_procs()}

            # ask for time period
            if 'period' not in args or args['period'] is None:
                args['period'] = prompt_for_string("Enter a valid time period (or leave blank for active jobs only):",
                                                   default='1d', allow_empty=True)

            # interpret time period
            if args['period'] == '':
                print("No time period provided. Listing currently active jobs only.")
                period = None
            else:
                try:
                    unit = args['period'][-1:]
                    number = int(args['period'][:-1])
                    multiplier = {'h': 1, 'd': 24, 'w': 7 * 24}
                    period = number * multiplier[unit]
                    print(f"Listing all jobs submitted within time period of {number}{unit} -> {period} hours")

                except Exception:
                    print(f"Invalid time period '{args['period']}. Listing currently active jobs only.")
                    period = None

            # get all jobs by this user and select
            choices = []
            for job in rti.get_jobs_by_user(keystore, period=period):
                status = rti.get_job_status(job.id, with_authorisation_by=keystore)
                choices.append(Choice(job.id, job_label(job, status, deployed)))

            if not choices:
                raise CLIRuntimeError("No jobs found.")

            args['job-id'] = prompt_for_selection(choices, message="Select job:", allow_multiple=False)

        result = {}
        try:
            status = rti.get_job_status(args['job-id'], with_authorisation_by=keystore)
            result['status'] = status
            print(f"Job status:\n{json.dumps(status.dict(), indent=4)}")

        except UnsuccessfulRequestError:
            print(f"No status for job {args['job-id']}.")

        return result


class RTIJobCancel(CLICommand):
    def __init__(self):
        super().__init__('cancel', 'attempts to cancel a job', arguments=[
            Argument('job-id', metavar='job-id', type=str, nargs='?', help="the id of the job"),
            Argument('--purge', dest="purge", action='store_const', const=True,
                     help="Attempts to cancel the job and, regardless of the outcome, "
                          "removes the job from the database.")
        ])

    def execute(self, args: dict) -> Optional[dict]:
        rti = _require_rti(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have a job id?
        if not args['job-id']:
            # get all deployed procs
            deployed: dict[str, Processor] = {proc.id: proc for proc in rti.get_all_procs()}

            # get all jobs by this user and select
            choices = []
            for job in rti.get_jobs_by_user(keystore):
                # don't show jobs that are not running
                status = rti.get_job_status(job.id, with_authorisation_by=keystore)
                if status.state not in [JobStatus.State.SUCCESSFUL.value, JobStatus.State.FAILED.value,
                                        JobStatus.State.CANCELLED.value]:
                    choices.append(Choice(job.id, job_label(job, status, deployed)))

            if not choices:
                raise CLIRuntimeError("No active jobs found.")

            args['job-id'] = prompt_for_selection(choices, message="Select job:", allow_multiple=False)

        result = {}
        try:
            if args.get('purge'):
                status = rti.purge_job(args['job-id'], with_authorisation_by=keystore)
                print(f"Job {args['job-id']} purged. Last status:\n{json.dumps(status.dict(), indent=4)}")
            else:
                status = rti.cancel_job(args['job-id'], with_authorisation_by=keystore)
                print(f"Job {args['job-id']} cancelled. Last status:\n{json.dumps(status.dict(), indent=4)}")

            result['status'] = status

        except UnsuccessfulRequestError:
            print(f"Job {args['job-id']} not found.")

        return result
