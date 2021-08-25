import json
import logging

from cli.helpers import CLICommand, Argument, prompt_if_missing, prompt_for_string, prompt_for_selection
from saas.dor.blueprint import DORProxy
from saas.keystore.identity import Identity
from saas.nodedb.blueprint import NodeDBProxy
from saas.rti.blueprint import RTIProxy

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

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
        prompt_if_missing(args, 'address', prompt_for_string, message="Enter the target node's REST address (e.g., 127.0.0.1:5001):")

        # do we have a processor id?
        if args['proc-id'] is None:
            # lookup all the data objects that are GPPs
            dor = DORProxy(args['address'].split(':'))
            choices = []
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

            selection = prompt_for_selection(choices, "Select the processor you would like to deploy:", allow_multiple=False)
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
        prompt_if_missing(args, 'proc-id', prompt_for_selection, items=choices, message="Select the processor you would like to undeploy:")

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
            Argument('--proc-id', dest='proc-id', action='store', required=False,
                     help=f"the id of the processor")

            # Argument('--job', dest='job', action='store',
            #          help=f"path to the job descriptor")
        ])

    def execute(self, args: dict) -> None:
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
        prompt_if_missing(args, 'proc-id', prompt_for_selection, items=choices, message="Select the processor for the job:")

        # is the processor deployed
        if args['proc-id'] not in deployed:
            print(f"Processor {args['proc-id']} is not deployed at {args['address']}. Aborting.")
            return None

        descriptor = rti.get_descriptor(args['proc-id'])
        print(f"Processor descriptor: {json.dumps(descriptor, indent=4)}")

        job = {
            'processor_id': args['proc-id'],
            'input': [],
            'output': [],
            'user_iid': None
        }
        for item in descriptor['input']:
            selection = prompt_for_selection([
                {'label': f"by-value [{item['data_type']}/{item['data_format']}]", 'type': 'value'},
                {'label': f"by-reference [{item['data_type']}/{item['data_format']}]", 'type': 'reference'}
            ], f"How to set input parameters '{item['name']}'?")

            if selection['type'] == 'value':
                value = prompt_for_string(f"Enter the value for input '{item['name']}' as JSON object:")
                value = json.loads(value)
                job['input'].append({
                    'name': item['name'],
                    'type': 'value',
                    'value': value
                })

            else:
                dor = DORProxy(args['address'].split(':'))
                choices = []
                result = dor.search(patterns=[item['data_type'], item['data_format']])
                for obj_id, tags in result.items():
                    choices.append({
                        'label': f"{obj_id} {tags}",
                        'obj_id': obj_id
                    })

                if len(choices) == 0:
                    print(f"No data objects found that match data type ({item['data_type']}) and format ({item['data_format']}) of input '{item['name']}'. Aborting.")
                    return None

                selection = prompt_for_selection(choices, f"Select the data object to be used for input '{item['name']}':")
                job['input'].append({
                    'name': item['name'],
                    'type': 'reference',
                    'obj_id': selection['obj_id']
                })

        # select the owner for the output data objects
        db = NodeDBProxy(args['address'].split(':'))
        identity_choices = []
        for serialised in db.get_identities().values():
            identity = Identity.deserialise(serialised)
            identity_choices.append({
                'label': f"{identity.name}/{identity.email}/{identity.id}",
                'identity': identity
            })

        selected = prompt_for_selection(identity_choices, "Select the owner for the output data objects:", allow_multiple=False)
        owner = selected['identity']

        # select the target node for the output data objects
        target_choices = []
        for node in db.get_network():
            target_choices.append({
                'label': f"{node['iid']} at {node['rest_address']}/{node['p2p_address']}",
                'iid': node['iid']
            })

        selected = prompt_for_selection(target_choices, "Select the destination node for the output data objects:", allow_multiple=False)
        target = selected['iid']

        selected = prompt_for_selection(identity_choices, "Select the user on whose behalf the job is executed:", allow_multiple=False)
        user = selected['identity']

        for item in descriptor['output']:
            job['output'].append({
                'name': item['name'],
                'owner_iid': owner.id,
                'restricted_access': False,
                'content_encrypted': False,
                'target_node_iid': target
            })

        # submit the job
        job_id = rti.submit_job(args['proc-id'], job['input'], job['output'], user)
        print(f"Job submitted: job-id={job_id}")


class RTIJobStatus(CLICommand):
    def __init__(self):
        super().__init__('status', 'retrieve the status of a job', arguments=[
            Argument('--job-id', dest='job-id', action='store',
                     help=f"the id of the job")
        ])

    def execute(self, args: dict) -> None:
        rti = RTIProxy(args['address'].split(':'))

        prompt_if_missing(args, 'job-id', prompt_for_string, message='Enter the job id:')

        print(args)
        descriptor, status = rti.get_job_info(args['job-id'])
        if descriptor is None:
            print(f"Job {args['job-id']} not found.")

        else:
            print(f"Job descriptor: {json.dumps(descriptor, indent=4)}")
            print(f"Status: {json.dumps(status, indent=4)}")

