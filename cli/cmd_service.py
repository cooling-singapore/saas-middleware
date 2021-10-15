import logging
import os

from cli.helpers import CLICommand, Argument, prompt_for_string, prompt_for_confirmation, prompt_if_missing, \
    default_if_missing, initialise_storage_folder, prompt_for_selection, load_keystore
from saas.node import Node

logger = logging.getLogger('cli.service')


class Service(CLICommand):
    # define the default values
    default_datastore = os.path.join(os.environ['HOME'], '.datastore')
    default_rest_address = '127.0.0.1:5001'
    default_p2p_address = '127.0.0.1:4001'
    default_boot_node_address = '127.0.0.1:4001'
    default_service = 'full'

    def __init__(self):
        super().__init__('service', 'start a node as service provider', arguments=[
            Argument('--use-defaults', dest="use-defaults", action='store_const', const=True,
                     help=f"use defaults in case arguments are not specified (or prompt otherwise)"),
            Argument('--datastore', dest='datastore', action='store',
                     help=f"path to the datastore (default: '{self.default_datastore}')"),
            Argument('--rest-address', dest='rest-address', action='store',
                     help=f"address used by the REST service interface (default: '{self.default_rest_address}')."),
            Argument('--p2p-address', dest='p2p-address', action='store',
                     help=f"address used by the P2P service interface (default: '{self.default_p2p_address}')."),
            Argument('--boot-node', dest='boot-node', action='store',
                     help=f"address of an existing node for joining a network "
                          f"(default: '{self.default_boot_node_address}')."),
            Argument('--type', dest='type', action='store', choices=['full', 'storage', 'execution'],
                     help=f"indicate the type of service provided by the node: 'storage' and 'execution' "
                          f"will only load the DOR or RTI modules, respectively; a 'full' node will provide "
                          f"both (default: '{self.default_service}').")
        ])

    def execute(self, args: dict) -> None:
        if args['use-defaults']:
            default_if_missing(args, 'datastore', self.default_datastore)
            default_if_missing(args, 'rest-address', self.default_rest_address)
            default_if_missing(args, 'p2p-address', self.default_p2p_address)
            default_if_missing(args, 'boot-node', self.default_boot_node_address)
            default_if_missing(args, 'type', self.default_service)

        else:
            prompt_if_missing(args, 'datastore', prompt_for_string,
                              message="Enter path to datastore:",
                              default=self.default_datastore)
            prompt_if_missing(args, 'rest-address', prompt_for_string,
                              message="Enter address for REST service:",
                              default=self.default_rest_address)
            prompt_if_missing(args, 'p2p-address', prompt_for_string,
                              message="Enter address for P2P service:",
                              default=self.default_p2p_address)
            prompt_if_missing(args, 'boot-node', prompt_for_string,
                              message="Enter address for boot node:",
                              default=self.default_boot_node_address)
            prompt_if_missing(args, 'type', prompt_for_selection, items=[
                {'type': 'full', 'label': 'Full node (i.e., DOR + RTI services)'},
                {'type': 'storage', 'label': 'Storage node (i.e., DOR service only)'},
                {'type': 'execution', 'label': 'Execution node (i.e., RTI service only)'}
            ], message="Select the type of service:")

        keystore = load_keystore(args, ensure_publication=False)

        # initialise storage directory (if necessary)
        initialise_storage_folder(args['datastore'], 'datastore')

        # extract host/ports
        rest_service_address = args['rest-address'].split(':')
        p2p_service_address = args['p2p-address'].split(':')
        boot_node_address = args['boot-node'].split(':')
        rest_service_address = (rest_service_address[0], int(rest_service_address[1]))
        p2p_service_address = (p2p_service_address[0], int(p2p_service_address[1]))
        boot_node_address = (boot_node_address[0], int(boot_node_address[1]))

        # create a node instance
        node = Node.create(keystore, args['datastore'],
                           p2p_address=p2p_service_address,
                           rest_address=rest_service_address,
                           boot_node_address=boot_node_address,
                           enable_dor=args['type'] == 'full' or args['type'] == 'storage',
                           enable_rti=args['type'] == 'full' or args['type'] == 'execution')

        print(f"Created '{args['type']}' node instance at {args['rest-address']}/{args['p2p-address']}")

        # wait for confirmation to terminate the server
        terminate = False
        while not terminate:
            terminate = prompt_for_confirmation("Terminate the server?", default=False)

        print(f"Shutting down the node...")
        node.shutdown()
