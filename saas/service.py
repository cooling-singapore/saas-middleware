import os
import sys
import time
import traceback

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLIParser, Argument, CLICommand, default_if_missing, initialise_storage_folder, \
    extract_address
from saas.core.exceptions import SaaSRuntimeException
from saas.core.keystore import Keystore
from saas.node import Node


class RunNode(CLICommand):
    # define the default values
    default_datastore = os.path.join(os.environ['HOME'], '.datastore')
    default_rest_address = '127.0.0.1:5001'
    default_p2p_address = '127.0.0.1:4001'
    default_boot_node_address = '127.0.0.1:4001'
    default_service = 'full'
    default_retain_job_history = False

    def __init__(self):
        super().__init__('run', 'run a node as service provider', arguments=[
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
                     help=f"[for execution/full nodes only] instructs the RTI to retain the job history (default: "
                          f"disabled, i.e., delete information of completed jobs). This flag should only be used for "
                          f"debug/testing purposes.")
        ])

    def execute(self, args: dict) -> None:
        default_if_missing(args, 'datastore', self.default_datastore)
        default_if_missing(args, 'rest-address', self.default_rest_address)
        default_if_missing(args, 'p2p-address', self.default_p2p_address)
        default_if_missing(args, 'boot-node', self.default_boot_node_address)
        default_if_missing(args, 'type', self.default_service)
        default_if_missing(args, 'retain-job-history', self.default_retain_job_history)

        # do we have keystore credentials?
        if not args['keystore-id'] or not args['password']:
            raise CLIRuntimeError(f"No keystore credentials provided (use --keystore-id and --password arguments). "
                                  f"Aborting.")

        # try to unlock the keystore
        try:
            keystore = Keystore.load(os.path.join(args['keystore'], f"{args['keystore-id']}.json"), args['password'])

        except SaaSRuntimeException as e:
            raise CLIRuntimeError(f"Could not open keystore {args['keystore-id']} because '{e.reason}'. Aborting.")

        # initialise storage directory (if necessary)
        initialise_storage_folder(args['datastore'], 'datastore')

        # extract host/ports
        rest_service_address = extract_address(args['rest-address'])
        p2p_service_address = extract_address(args['p2p-address'])
        boot_node_address = extract_address(args['boot-node'])

        # create a node instance
        try:
            node = Node.create(keystore, args['datastore'],
                               p2p_address=p2p_service_address,
                               rest_address=rest_service_address,
                               boot_node_address=boot_node_address,
                               enable_dor=args['type'] == 'full' or args['type'] == 'storage',
                               enable_rti=args['type'] == 'full' or args['type'] == 'execution',
                               retain_job_history=args['retain-job-history'])

        except SaaSRuntimeException as e:
            raise CLIRuntimeError(f"Could not start node because '{e.reason}'. Aborting.")

        # print info message
        if args['type'] == 'full' or args['type'] == 'execution':
            print(f"Created '{args['type']}' node instance at {args['rest-address']}/{args['p2p-address']} "
                  f"(keep RTI job history: {'Yes' if args['retain-job-history'] else 'No'})")
        else:
            print(f"Created '{args['type']}' node instance at {args['rest-address']}/{args['p2p-address']}")

        # wait forever
        try:
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            print("Interrupted by user. Shutting down.")
            node.shutdown()


def main():
    try:
        default_keystore = os.path.join(os.environ['HOME'], '.keystore')
        default_temp_dir = os.path.join(os.environ['HOME'], '.temp')
        default_log_level = 'INFO'

        cli = CLIParser('SaaS Middleware Service', arguments=[
            Argument('--keystore', dest='keystore', action='store', default=default_keystore,
                     help=f"path to the keystore (default: '{default_keystore}')"),
            Argument('--keystore-id', dest='keystore-id', action='store',
                     help=f"id of the keystore to be used"),
            Argument('--password', dest='password', action='store',
                     help=f"password for the keystore"),
            Argument('--temp-dir', dest='temp-dir', action='store', default=default_temp_dir,
                     help=f"path to directory used for intermediate files (default: '{default_temp_dir}')"),
            Argument('--log-level', dest='log-level', action='store',
                     choices=['INFO', 'DEBUG'], default=default_log_level,
                     help=f"set the log level (default: '{default_log_level}')"),
            Argument('--log-path', dest='log-path', action='store',
                     help=f"enables logging to file using the given path (default: disabled)"),
            Argument('--log-console', dest="log-console", action='store_const', const=False,
                     help=f"enables logging to the console (default: disabled)"),

        ], commands=[
            RunNode()
        ])

        cli.execute(sys.argv[1:])
        sys.exit(0)

    except CLIRuntimeError as e:
        print(e.reason)
        sys.exit(-1)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(f"Unrefined exception:\n{trace}")
        sys.exit(-2)


if __name__ == "__main__":
    main()
