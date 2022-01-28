import json
import os
from typing import Optional

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_if_missing, prompt_for_string, prompt_for_selection, \
    get_nodes_by_service, prompt_for_confirmation, load_keystore
from saas.dor.blueprint import DORProxy
from saas.helpers import read_json_from_file, validate_json
from saas.keystore.assets.credentials import CredentialsAsset, GithubCredentials
from saas.logging import Logging
from saas.nodedb.blueprint import NodeDBProxy
from saas.rest.exceptions import UnsuccessfulRequestError
from saas.rti.blueprint import RTIProxy
from saas.schemas import TaskDescriptor

logger = Logging.get('cli.rti')


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
        # prompt for the address (if missing)
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the node's REST address",
                          default='127.0.0.1:5001')

        keystore = load_keystore(args, ensure_publication=False)

        # discover nodes by service
        nodes = get_nodes_by_service(args['address'].split(':'))
        if len(nodes['dor']) == 0:
            raise CLIRuntimeError("Could not find any nodes with a DOR service in the network. Try again later.")

        # lookup all the GPP data objects
        choices = []
        custodian = {}
        repo_urls = {}
        for node in nodes['dor'].values():
            dor = DORProxy(node['rest_address'].split(':'))
            result = dor.search(data_type='Git-Processor-Pointer')
            for item in result:
                if item['data_type'] == 'Git-Processor-Pointer':
                    tags = {tag['key']: tag['value'] for tag in item['tags']}
                    choices.append({
                        'label': f"{tags['name']} from {tags['repository']} at {tags['path']}",
                        'proc-id': item['obj_id'],
                    })
                    custodian[item['obj_id']] = node
                    repo_urls[item['obj_id']] = tags['repository']

        # do we have any processors to choose from?
        if len(choices) == 0:
            raise CLIRuntimeError("No processors found for deployment. Aborting.")

        # do we have a processor id?
        if args['proc-id'] is None:
            selection = prompt_for_selection(choices, "Select the processor you would like to deploy:",
                                             allow_multiple=False)
            args['proc-id'] = selection['proc-id']

        # do we have a custodian for this processor id?
        if args['proc-id'] not in custodian:
            raise CLIRuntimeError(f"Custodian of processor {args['proc-id']} not found. Aborting.")

        # do we have a type?
        prompt_if_missing(args, 'type', prompt_for_selection, items=[
            {'label': 'Native Deployment', 'type': 'native'},
            {'label': 'Docker Deployment', 'type': 'docker'}
        ], message="Select the deployment type:")

        # should we use an SSH profile?
        ssh_credentials = None
        if args['ssh-profile'] is None:
            if prompt_for_confirmation("Use an SSH profile for deployment?", default=False):
                # get the SSH credentials
                asset: CredentialsAsset = keystore.get_asset('ssh-credentials')
                choices = []
                if asset is not None:
                    print(asset.index())
                    for key in asset.index():
                        choices.append({
                            'label': key,
                            'ssh-profile': key,
                        })

                # do we have any profiles to choose from?
                if len(choices) == 0:
                    raise CLIRuntimeError("No SSH profiles found. Aborting.")

                selection = prompt_for_selection(choices, "Select the SSH profile to be used for deployment:",
                                                 allow_multiple=False)
                args['ssh-profile'] = selection['ssh-profile']
                ssh_credentials = asset.get(args['ssh-profile'])

        prompt_if_missing(args, 'type', prompt_for_selection, items=[
            {'label': 'Native Deployment', 'type': 'native'},
            {'label': 'Docker Deployment', 'type': 'docker'}
        ], message="Select the deployment type:")

        # check if we have Github credentials for this URL
        url = repo_urls[args['proc-id']]
        asset: CredentialsAsset = keystore.get_asset('github-credentials')
        github_credentials: Optional[GithubCredentials] = asset.get(url)
        if github_credentials is not None:
            if not prompt_for_confirmation(f"Found Github credentials '{github_credentials.login}' for {url}. "
                                           f"Use for deployment?", default=True):
                github_credentials = None

        # deploy the processor
        print(f"Deploying processor {args['proc-id']}...", end='')
        rti = RTIProxy(args['address'].split(':'))
        rti.deploy(args['proc-id'], deployment=args['type'], gpp_custodian=custodian[args['proc-id']]['iid'],
                   ssh_credentials=ssh_credentials, github_credentials=github_credentials)
        print(f"Done")


class RTIProcUndeploy(CLICommand):
    def __init__(self):
        super().__init__('undeploy', 'undeploys a processor', arguments=[
            Argument('proc-id', metavar='proc-id', type=str, nargs='*',
                     help="the ids of the processors to be undeployed")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address:",
                          default="127.0.0.1:5001")

        # get the deployed processors
        rti = RTIProxy(args['address'].split(':'))
        deployed = rti.get_deployed()
        deployed = {item['proc_id']: item for item in deployed}
        if len(deployed) == 0:
            raise CLIRuntimeError(f"No processors deployed at {args['address']}. Aborting.")

        # do we have a processor id?
        if len(args['proc-id']) == 0:
            # create choices
            choices = []
            for proc_id in deployed:
                descriptor = rti.get_descriptor(proc_id)
                choices.append({
                    'label': f"{descriptor['name']}/{proc_id}",
                    'proc-id': proc_id
                })

            selection = prompt_for_selection(items=choices,
                                             message="Select the processor(s) you would like to undeploy:",
                                             allow_multiple=True)
            args['proc-id'] = [item['proc-id'] for item in selection]

        # do we have a selection?
        if len(args['proc-id']) == 0:
            raise CLIRuntimeError(f"No processors selected. Aborting.")

        # are the processors deployed?
        for proc_id in args['proc-id']:
            if proc_id not in deployed:
                print(f"Processor {proc_id} is not deployed at {args['address']}. Skipping.")

            # undeploy the processor
            print(f"Undeploy processor {proc_id}...", end='')
            rti.undeploy(proc_id)
            print(f"Done")


class RTIProcList(CLICommand):
    def __init__(self) -> None:
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
            for item in deployed:
                descriptor = rti.get_descriptor(item['proc_id'])
                print(f"{item['proc_id']}: {json.dumps(descriptor, indent=4)}")


class RTIJobSubmit(CLICommand):
    def __init__(self) -> None:
        super().__init__('submit', 'submit a new job', arguments=[
            Argument('--job', dest='job', action='store',
                     help=f"path to the job descriptor")
        ])

    def _prepare(self, address: str) -> None:
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

    def _create_job_input(self, proc_descriptor: dict) -> list:
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
                    raise CLIRuntimeError(f"No data objects found that match data type ({item['data_type']}) and "
                                          f"format ({item['data_format']}) of input '{item['name']}'. Aborting.")

                # select an object
                selection = prompt_for_selection(object_choices,
                                                 f"Select the data object to be used for input '{item['name']}':")
                job_input.append({
                    'name': item['name'],
                    'type': 'reference',
                    'obj_id': selection['obj_id']
                })

        return job_input

    def _create_job_output(self, proc_descriptor: dict) -> list:
        # select the owner for the output data objects
        selected = prompt_for_selection(self._identity_choices, "Select the owner for the output data objects:",
                                        allow_multiple=False)
        owner = selected['identity']

        # select the target node for the output data objects
        selected = prompt_for_selection(self._node_choices, "Select the destination node for the output data objects:",
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
        deployed = {item['proc_id']: item for item in deployed}
        if len(deployed) == 0:
            raise CLIRuntimeError(f"No processors deployed at {args['address']}. Aborting.")

        # do we have a job descriptor?
        if args['job'] is not None:
            # does the file exist?
            if not os.path.isfile(args['job']):
                raise CLIRuntimeError(f"No job descriptor at '{args['job']}'. Aborting.")

            # read the file and validate
            job_descriptor = read_json_from_file(args['job'])
            if not validate_json(job_descriptor, TaskDescriptor.schema()):
                raise CLIRuntimeError(f"Invalid job descriptor. Aborting.")

            # is the processor deployed?
            if job_descriptor['processor_id'] not in deployed:
                raise CLIRuntimeError(f"Processor {job_descriptor['processor_id']} is not deployed at {args['address']}. Aborting.")

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

            # create the job input and output
            job_input = self._create_job_input(proc_descriptor)
            job_output = self._create_job_output(proc_descriptor)

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
            Argument('job-id', metavar='job-id', type=str, nargs='?',
                     help=f"the id of the job")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address:", default="127.0.0.1:5001")

        rti = RTIProxy(args['address'].split(':'))

        prompt_if_missing(args, 'job-id', prompt_for_string, message='Enter the job id:')

        try:
            descriptor, status = rti.get_job_info(args['job-id'])
            print(f"Job descriptor: {json.dumps(descriptor, indent=4)}")
            print(f"Status: {json.dumps(status, indent=4)}")

        except UnsuccessfulRequestError:
            print(f"Job {args['job-id']} not found.")
