import os
import sys

from InquirerPy.base import Choice

from saas.cli.helpers import CLICommand, Argument, prompt_for_string, prompt_for_confirmation, prompt_if_missing, \
    default_if_missing, initialise_storage_folder, prompt_for_selection, load_keystore, extract_address
from saas.core.logging import Logging
from saas.node import Node

logger = Logging.get('cli.service')


class Service(CLICommand):
    # define the default values
    default_datastore = os.path.join(os.environ['HOME'], '.datastore')
    default_rest_address = '127.0.0.1:5001'
    default_p2p_address = '127.0.0.1:4001'
    default_boot_node_address = '127.0.0.1:4001'
    default_service = 'full'
    default_retain_job_history = False
    default_strict_deployment = True
    default_bind_all_address = False


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
                          f"both (default: '{self.default_service}')."),
            Argument('--retain-job-history', dest="retain-job-history", action='store_const', const=True,
                     help=f"[for execution/full nodes only] instructs the RTI to retain the job history (default "
                          f"behaviour is to delete information of completed jobs). This flag should only be used for "
                          f"debug/testing purposes."),
            Argument('--disable-strict-deployment', dest="strict-deployment", action='store_const', const=False,
                     help=f"[for execution/full nodes only] instructs the RTI to disable strict processor deployment "
                          f"(default: enabled, i.e., only the node owner identity can deploy/undeploy processors.)"),
            Argument('--bind-all-address', dest="bind-all-address", action='store_const', const=True,
                     help=f"allows REST and P2P service to bind and accept connections pointing to any address of the machine"
                          f"i.e. 0.0.0.0 (useful for docker)")
        ])

    def execute(self, args: dict) -> None:
        if args['use-defaults']:
            default_if_missing(args, 'datastore', self.default_datastore)
            default_if_missing(args, 'rest-address', self.default_rest_address)
            default_if_missing(args, 'p2p-address', self.default_p2p_address)
            default_if_missing(args, 'boot-node', self.default_boot_node_address)
            default_if_missing(args, 'type', self.default_service)
            default_if_missing(args, 'retain-job-history', self.default_retain_job_history)
            default_if_missing(args, 'strict-deployment', self.default_strict_deployment)
            default_if_missing(args, 'bind-all-address', self.default_bind_all_address)

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

            if args['type'] is None:
                args['type'] = prompt_for_selection([
                    Choice('full', 'Full node (i.e., DOR + RTI services)'),
                    Choice('storage', 'Storage node (i.e., DOR service only)'),
                    Choice('execution', 'Execution node (i.e., RTI service only)')
                ], "Select the type of service:")

            if args['type'] == 'full' or args['type'] == 'execution':
                prompt_if_missing(args, 'retain-job-history', prompt_for_confirmation,
                                  message='Retain RTI job history?', default=False)
                prompt_if_missing(args, 'bind-all-address', prompt_for_confirmation,
                                  message='Bind service to all network addresses?', default=False)

                prompt_if_missing(args, 'strict-deployment', prompt_for_confirmation,
                                  message='Strict processor deployment?', default=True)

        keystore = load_keystore(args, ensure_publication=False)

        # initialise storage directory (if necessary)
        initialise_storage_folder(args['datastore'], 'datastore')

        # extract host/ports
        rest_service_address = extract_address(args['rest-address'])
        p2p_service_address = extract_address(args['p2p-address'])
        boot_node_address = extract_address(args['boot-node'])

        # create a node instance
        node = Node.create(keystore, args['datastore'],
                           p2p_address=p2p_service_address,
                           rest_address=rest_service_address,
                           boot_node_address=boot_node_address,
                           enable_dor=args['type'] == 'full' or args['type'] == 'storage',
                           enable_rti=args['type'] == 'full' or args['type'] == 'execution',
                           retain_job_history=args['retain-job-history'],
                           strict_deployment=args['strict-deployment'],
                           bind_all_address=args['bind-all-address'])

        # print info message
        if args['type'] == 'full' or args['type'] == 'execution':
            print(f"Created '{args['type']}' node instance at {args['rest-address']}/{args['p2p-address']} "
                  f"(keep RTI job history: {'Yes' if args['retain-job-history'] else 'No'})")
        else:
            print(f"Created '{args['type']}' node instance at {args['rest-address']}/{args['p2p-address']}")

        try:
            # wait for confirmation to terminate the server
            terminate = False
            while not terminate:
                # only show prompt if shell is interactive
                if sys.stdin.isatty():
                    terminate = prompt_for_confirmation("Terminate the server?", default=False)
        except KeyboardInterrupt:
            print("Received stop signal")
        finally:
            print("Shutting down the node...")
            node.shutdown()

