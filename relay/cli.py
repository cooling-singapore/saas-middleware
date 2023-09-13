import time
import traceback

from relay.server import RelayRuntimeError, RelayServer
from saas.core.logging import Logging
from saas.sdk.app.auth import UserAuth, UserDB
from saas.sdk.app.exceptions import AppRuntimeError

from saas.sdk.cli.commands import UserInit, UserCreate, UserRemove, UserEnable, UserDisable, UserList, UserUpdateName, UserUpdatePassword
from saas.sdk.cli.exceptions import CLIRuntimeError
from saas.sdk.cli.helpers import CLIParser, CLICommand, CLICommandGroup, Argument, prompt_if_missing, \
    prompt_for_string, extract_address, prompt_for_confirmation

import os
import sys

logger = Logging.get('cli.service')


class Service(CLICommand):
    default_userstore = os.path.join(os.environ['HOME'], '.userstore')
    default_server_address = '127.0.0.1:5022'
    default_node_address = '127.0.0.1:5002'

    def __init__(self):
        super().__init__('service', 'start a Relay server instance', arguments=[
            Argument('--userstore', dest='userstore', action='store', default=self.default_userstore,
                     help=f"path to the userstore (default: '{self.default_userstore}')"),
            Argument('--secret_key', dest='secret_key', action='store', required=False,
                     help="the secret key used to secure passwords"),
            Argument('--server_address', dest='server_address', action='store',
                     help=f"address used by the server REST service interface (default: '{self.default_server_address}')."),
            Argument('--node_address', dest='node_address', action='store',
                     help=f"address used by the node REST  service interface (default: '{self.default_node_address}')."),
        ])

    def execute(self, args: dict) -> None:
        # check the userstore directory
        if not os.path.isdir(args['userstore']):
            raise RelayRuntimeError(f"Userstore directory not found: {args['userstore']}")

        # check the datastore directory
        if not os.path.isdir(args['datastore']):
            print(f"Creating datastore folder at '{args['datastore']}'")
            os.mkdir(args['datastore'])
        else:
            print(f"Using existing datastore folder at '{args['datastore']}'")

        # get the secret key and check it
        prompt_if_missing(args, 'secret_key', prompt_for_string, message="Enter the secret key:", hide=True)
        if len(args['secret_key']) != 32:
            raise RelayRuntimeError("Secret key must have a size of 32 characters")

        # get the server address
        prompt_if_missing(args, 'server_address', prompt_for_string,
                          message="Enter address for the server REST service:",
                          default=self.default_server_address)

        # get the node address
        prompt_if_missing(args, 'node_address', prompt_for_string,
                          message="Enter address of the SaaS node REST service:",
                          default=self.default_node_address)

        # initialise user database and publish all identities
        UserDB.initialise(args['userstore'])
        UserDB.publish_all_user_identities(extract_address(args['node_address']))

        # initialise user authentication
        UserAuth.initialise(args['secret_key'])

        # create server instance
        server = RelayServer(extract_address(args['server_address']),
                             extract_address(args['node_address']),
                             args['datastore'])
        server.startup()

        try:
            # wait for confirmation to terminate the server
            print("Waiting to be terminated...")
            terminate = False
            while not terminate:
                # only show prompt if shell is interactive
                if sys.stdin.isatty():
                    terminate = prompt_for_confirmation("Terminate the server?", default=False)

                else:
                    # wait for a bit...
                    time.sleep(0.5)

        except KeyboardInterrupt:
            print("Received stop signal")
        finally:
            print("Shutting down the node...")
            server.shutdown()


def main():
    try:
        default_datastore = os.path.join(os.environ['HOME'], '.datastore-relay')
        default_keystore = os.path.join(os.environ['HOME'], '.keystore')
        default_temp_dir = os.path.join(os.environ['HOME'], '.temp')
        default_log_level = 'INFO'

        cli = CLIParser('SaaS Relay command line interface (CLI)', arguments=[
            Argument('--datastore', dest='datastore', action='store', default=default_datastore,
                     help=f"path to the datastore (default: '{default_datastore}')"),
            Argument('--keystore', dest='keystore', action='store', default=default_keystore,
                     help=f"path to the keystore (default: '{default_keystore}')"),
            Argument('--temp-dir', dest='temp-dir', action='store', default=default_temp_dir,
                     help=f"path to directory used for intermediate files (default: '{default_temp_dir}')"),
            Argument('--keystore-id', dest='keystore-id', action='store',
                     help="id of the keystore to be used if there are more than one available "
                          "(default: id of the only keystore if only one is available )"),
            Argument('--password', dest='password', action='store',
                     help="password for the keystore"),
            Argument('--log-level', dest='log-level', action='store',
                     choices=['INFO', 'DEBUG'], default=default_log_level,
                     help=f"set the log level (default: '{default_log_level}')"),
            Argument('--log-path', dest='log-path', action='store',
                     help="enables logging to file using the given path"),
            Argument('--log-console', dest="log-console", action='store_const', const=False,
                     help="enables logging to the console"),

        ], commands=[
            CLICommandGroup('user', 'manage users', commands=[
                UserInit(),
                UserList(),
                UserCreate(),
                UserRemove(),
                UserEnable(),
                UserDisable(),
                UserUpdateName(),
                UserUpdatePassword()
            ]),
            Service()
        ])

        cli.execute(sys.argv[1:])
        sys.exit(0)

    except RelayRuntimeError as e:
        print(e.reason)
        sys.exit(-1)

    except CLIRuntimeError as e:
        print(e.reason)
        sys.exit(-1)

    except AppRuntimeError as e:
        print(e.reason)
        sys.exit(-1)

    except KeyboardInterrupt:
        print("Interrupted by user.")
        sys.exit(-2)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(f"Unrefined exception:\n{trace}")
        sys.exit(-3)


if __name__ == "__main__":
    main()
