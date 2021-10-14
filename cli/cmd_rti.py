import json
import logging
import os
from typing import Optional

from cli.helpers import CLICommand, Argument, prompt_if_missing, prompt_for_string, prompt_for_selection
from saas.dor.blueprint import DORProxy
from saas.helpers import read_json_from_file, validate_json
from saas.nodedb.blueprint import NodeDBProxy
from saas.rti.blueprint import RTIProxy
from saas.schemas import task_descriptor_schema

logger = logging.getLogger('cli.rti')


class RTIProcDeploy(CLICommand):
    def __init__(self):
        super().__init__('deploy', 'deploys a processor', arguments=[
            Argument('--proc-id', dest='proc-id', action='store', required=False,
                     help=f"the id of the processor to be deployed"),
            Argument('--type', dest='type', action='store', choices=['native', 'docker'],
                     help=f"indicate the type of deployment: 'native' or 'docker'.")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address:",
                          default="127.0.0.1:5001")

        # do we have a processor id?
        if args['proc-id'] is None:
            # find a node with a DOR (that's because the target node may well be an execution node without DOR)
            db = NodeDBProxy(args['address'].split(':'))
            dor_node = None
            for node in db.get_network():
                if node['dor_service']:
                    dor_node = node
                    break

            # do we have a DOR node?
            if dor_node is None:
                print("Could not find a node with a DOR service in the network. Try again later.")
                return None

            # lookup all the data objects that are GPPs
            choices = []
            dor = DORProxy(dor_node['rest_address'].split(':'))
            result = dor.search(patterns=['Git-Processor-Pointer'])
            for obj_id, tags in result.items():
                tags = {tag.split('=')[0]: tag.split('=')[1] for tag in tags}
                if tags['data-type'] == 'Git-Processor-Pointer':
                    choices.append({
                        'label': f"{tags['name']} from {tags['repository']} at {tags['path']}",
                        'proc-id': obj_id
                    })

            # do we have processors?
            if len(choices) == 0:
                print("No processors found for deployment. Aborting.")
                return None

            selection = prompt_for_selection(choices,
                                             "Select the processor you would like to deploy:",
                                             allow_multiple=False)
            args['proc-id'] = selection['proc-id']

        # do we have a type?
        prompt_if_missing(args, 'type', prompt_for_selection, items=[
            {'label': 'Native Deployment', 'type': 'native'},
            {'label': 'Docker Deployment', 'type': 'docker'}
        ], message="Select the deployment type:")

        # deploy the processor
        rti = RTIProxy(args['address'].split(':'))
        print(f"Deploying processor {args['proc-id']}...", end='')
        descriptor = rti.deploy(args['proc-id'], deployment=args['type'])
        if descriptor:
            print(f"Done")
        else:
            print(f"Failed")


class RTIProcUndeploy(CLICommand):
    def __init__(self):
        super().__init__('undeploy', 'undeploys a processor', arguments=[
            Argument('--proc-id', dest='proc-id', action='store', required=False,
                     help=f"the id of the processor to be undeployed")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address:",
                          default="127.0.0.1:5001")

        # get the deployed processors
        rti = RTIProxy(args['address'].split(':'))
        deployed = rti.get_deployed()
        if len(deployed) == 0:
            print(f"No processors deployed at {args['address']}. Aborting.")
            return None

        # create choices
        choices = []
        for proc_id in deployed:
            descriptor = rti.get_descriptor(proc_id)
            choices.append({
                'label': f"{descriptor['name']}/{proc_id}",
                'proc-id': proc_id
            })

        # do we have a processor id?
        prompt_if_missing(args, 'proc-id', prompt_for_selection,
                          items=choices,
                          message="Select the processor you would like to undeploy:")

        # is the processor deployed
        if args['proc-id'] not in deployed:
            print(f"Processor {args['proc-id']} is not deployed at {args['address']}. Aborting.")
            return None

        # undeploy the processor
        print(f"Undeploy processor...", end='')
        result = rti.undeploy(args['proc-id'])
        if result == args['proc-id']:
            print("Done")
        else:
            print("Failed")


class RTIProcList(CLICommand):
    def __init__(self):
        super().__init__('list', 'retrieves a list of all deployed processors', arguments=[])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address:",
                          default="127.0.0.1:5001")

        rti = RTIProxy(args['address'].split(':'))
        deployed = rti.get_deployed()
        if len(deployed) == 0:
            print(f"No processors deployed at {args['address']}")
        else:
            print(f"Found {len(deployed)} processor(s) deployed at {args['address']}:")
            for proc_id in deployed:
                descriptor = rti.get_descriptor(proc_id)
                print(f"{proc_id}: {json.dumps(descriptor, indent=4)}")


class RTIJobSubmit(CLICommand):
    def __init__(self):
        super().__init__('submit', 'submit a new job', arguments=[
            Argument('--job', dest='job', action='store',
                     help=f"path to the job descriptor")
        ])

    def _prepare(self, address: str):
        self._address = address
        self._db = NodeDBProxy(address.split(':'))
        self._rti = RTIProxy(address.split(':'))
        self._dor = None

        # create identity choices
        self._identity_choices = []
        for identity in self._db.get_identities().values():
            self._identity_choices.append({
                'label': f"{identity.name}/{identity.email}/{identity.id}",
                'identity': identity
            })

        # create node choices
        self._node_choices = []
        for node in self._db.get_network():
            # does the node have a DOR?
            if node['dor_service'] is False:
                continue

            # use the fist eligible node
            if self._dor is None:
                self._dor = DORProxy(node['rest_address'].split(':'))

            # get the identity of the node
            identity = self._db.get_identity(node['iid'])

            # add the choice
            self._node_choices.append({
                'label': f"{identity.name}/{identity.id} at {node['rest_address']}/{node['p2p_address']}",
                'iid': node['iid']
            })

    def _create_job_input(self, proc_descriptor: dict) -> Optional[list]:
        job_input = []
        for item in proc_descriptor['input']:
            selection = prompt_for_selection([
                {'label': f"by-value [{item['data_type']}/{item['data_format']}]", 'type': 'value'},
                {'label': f"by-reference [{item['data_type']}/{item['data_format']}]", 'type': 'reference'}
            ], f"How to set input parameters '{item['name']}'?")

            if selection['type'] == 'value':
                value = prompt_for_string(f"Enter the value for input '{item['name']}' as JSON object:")
                value = json.loads(value)
                job_input.append({
                    'name': item['name'],
                    'type': 'value',
                    'value': value
                })

            else:
                # get the data object choices for this input item
                object_choices = []
                result = self._dor.search(data_type=item['data_type'], data_format=item['data_format'])
                for found in result:
                    tags = [f"{tag['key']}={tag['value']}" for tag in found['tags']]
                    object_choices.append({
                        'label': f"{found['obj_id']} [{found['data_type']}/{found['data_format']}] {tags}",
                        'obj_id': found['obj_id']
                    })

                # do we have any matching objects?
                if len(object_choices) == 0:
                    print(f"No data objects found that match data type ({item['data_type']}) and "
                          f"format ({item['data_format']}) of input '{item['name']}'. Aborting.")
                    return None

                # select an object
                selection = prompt_for_selection(object_choices,
                                                 f"Select the data object to be used for input '{item['name']}':")
                job_input.append({
                    'name': item['name'],
                    'type': 'reference',
                    'obj_id': selection['obj_id']
                })

        return job_input

    def _create_job_output(self, proc_descriptor: dict) -> Optional[list]:
        # select the owner for the output data objects
        selected = prompt_for_selection(self._identity_choices,
                                        "Select the owner for the output data objects:",
                                        allow_multiple=False)
        owner = selected['identity']

        # select the target node for the output data objects
        selected = prompt_for_selection(self._node_choices,
                                        "Select the destination node for the output data objects:",
                                        allow_multiple=False)
        target = selected['iid']

        # create the job output
        job_output = []
        for item in proc_descriptor['output']:
            job_output.append({
                'name': item['name'],
                'owner_iid': owner.id,
                'restricted_access': False,
                'content_encrypted': False,
                'target_node_iid': target
            })

        return job_output

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address:",
                          default="127.0.0.1:5001")

        self._prepare(args['address'])

        # get the deployed processors
        deployed = self._rti.get_deployed()
        if len(deployed) == 0:
            print(f"No processors deployed at {args['address']}. Aborting.")
            return None

        # do we have a job descriptor?
        if args['job'] is not None:
            # does the file exist?
            if not os.path.isfile(args['job']):
                print(f"No job descriptor at '{args['job']}'. Aborting.")
                return None

            # read the file and validate
            job_descriptor = read_json_from_file(args['job'])
            if not validate_json(job_descriptor, task_descriptor_schema):
                print(f"Invalid job descriptor. Aborting.")
                return None

            # is the processor deployed?
            if job_descriptor['processor_id'] not in deployed:
                print(f"Processor {job_descriptor['processor_id']} is not deployed at {args['address']}. Aborting.")
                return None

        # if we don't have a job descriptor then we obtain all the information interactively
        else:
            # create choices for processor selection
            proc_choices = []
            for proc_id in deployed:
                descriptor = self._rti.get_descriptor(proc_id)
                proc_choices.append({
                    'label': f"{descriptor['name']}/{proc_id}",
                    'proc-id': proc_id
                })

            # select the processor
            proc_id = prompt_for_selection(items=proc_choices, message="Select the processor for the job:")['proc-id']

            # get the descriptor for this processor
            proc_descriptor = self._rti.get_descriptor(proc_id)
            print(f"Processor descriptor: {json.dumps(proc_descriptor, indent=4)}")

            # create the job input
            job_input = self._create_job_input(proc_descriptor)
            if job_input is None:
                return None

            # create the job output
            job_output = self._create_job_output(proc_descriptor)
            if job_output is None:
                return None

            # create the job descriptor template, then begin to fill it
            job_descriptor = {
                'processor_id': proc_id,
                'input': job_input,
                'output': job_output,
                'user_iid': None
            }

        # select the user on whose behalf the jbo
        selected = prompt_for_selection(self._identity_choices,
                                        "Select the user on whose behalf the job is executed:",
                                        allow_multiple=False)
        user = selected['identity']

        # submit the job
        job_id = self._rti.submit_job(job_descriptor['processor_id'],
                                      job_descriptor['input'],
                                      job_descriptor['output'],
                                      user)
        print(f"Job submitted: job-id={job_id}")


class RTIJobStatus(CLICommand):
    def __init__(self):
        super().__init__('status', 'retrieve the status of a job', arguments=[
            Argument('--job-id', dest='job-id', action='store',
                     help=f"the id of the job")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address:", default="127.0.0.1:5001")

        rti = RTIProxy(args['address'].split(':'))

        prompt_if_missing(args, 'job-id', prompt_for_string, message='Enter the job id:')

        print(args)
        descriptor, status = rti.get_job_info(args['job-id'])
        if descriptor is None:
            print(f"Job {args['job-id']} not found.")

        else:
            print(f"Job descriptor: {json.dumps(descriptor, indent=4)}")
            print(f"Status: {json.dumps(status, indent=4)}")
