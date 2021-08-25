import logging
import os
import subprocess

import jsonschema

from cli.helpers import CLICommand, Argument, prompt_if_missing, prompt_for_string, prompt_for_keystore_selection, \
    prompt_for_password, unlock_keystore, prompt_for_confirmation, \
    prompt_for_selection, prompt_for_data_object_selection, prompt_for_tags
from saas.cryptography.helpers import encrypt_file
from saas.dor.blueprint import DORProxy
from saas.helpers import read_json_from_file
from saas.keystore.assets.contentkeys import ContentKeysAsset
from saas.keystore.identity import Identity
from saas.nodedb.blueprint import NodeDBProxy
from saas.rti.blueprint import RTIProxy
from saas.schemas import processor_descriptor_schema

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('cli.rti')


class RTIDeploy(CLICommand):
    def __init__(self):
        super().__init__('deploy', 'deploys a processor', arguments=[
            Argument('--proc-id', dest='proc-id', action='store', required=False,
                     help=f"the id of the processor to be deployed")
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

                print(tags)
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

        # deploy the processor
        rti = RTIProxy(args['address'].split(':'))
        print(f"Deploying processor {args['proc-id']}...", end='')
        result = rti.deploy(args['proc-id'])
        print(result)


class RTIUndeploy(CLICommand):
    def __init__(self):
        super().__init__('undeploy', 'undeploys a processor', arguments=[
            Argument('--proc-id', dest='proc-id', action='store', required=False,
                     help=f"the id of the processor to be undeployed")
        ])

    def execute(self, args: dict) -> None:
        pass


class RTIDescriptor(CLICommand):
    def __init__(self):
        super().__init__('descriptor', 'retrieves the descriptor of a deployed processor', arguments=[
            Argument('--proc-id', dest='proc-id', action='store', required=False,
                     help=f"the id of the processor")
        ])

    def execute(self, args: dict) -> None:
        pass


class RTIJobSubmit(CLICommand):
    def __init__(self):
        super().__init__('tag', 'add/update tags of a data object', arguments=[
            Argument('--proc-id', dest='proc-id', action='store', required=False,
                     help=f"the id of the processor"),

            Argument('--job', dest='job', action='store',
                     help=f"path to the job descriptor")
        ])

    def execute(self, args: dict) -> None:
        pass


class RTIJobStatus(CLICommand):
    def __init__(self):
        super().__init__('untag', 'removes tags from a data object', arguments=[
            Argument('--job-id', dest='job-id', action='store',
                     help=f"the id of the job")
        ])

    def execute(self, args: dict) -> None:
        pass

