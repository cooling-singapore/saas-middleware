import os
import sys
import traceback

from saas.cli.cmd_compose import Compose
from saas.cli.cmd_dor import DORAdd, DORAddGPP, DORRemove, DORSearch, DORTag, DORUntag, DORAccessGrant, \
    DORAccessRevoke, DORAccessShow, DORDownload, DORMeta
from saas.cli.cmd_identity import IdentityCreate, IdentityRemove, IdentityShow, IdentityUpdate, IdentityList, \
    IdentityDiscover, IdentityPublish, CredentialsRemove, CredentialsList, CredentialsAddSSHCredentials, \
    CredentialsAddGithubCredentials, CredentialsTestSSHCredentials, CredentialsTestGithubCredentials
from saas.cli.cmd_network import NetworkList
from saas.cli.cmd_rti import RTIProcDeploy, RTIProcUndeploy, RTIJobSubmit, RTIJobStatus, RTIProcList, RTIProcStatus, \
    RTIProcShow, RTIJobList, RTIJobLogs, RTIJobCancel
from saas.cli.cmd_service import Service
from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLIParser, Argument, CLICommandGroup


def main():
    try:
        default_keystore = os.path.join(os.environ['HOME'], '.keystore')
        default_temp_dir = os.path.join(os.environ['HOME'], '.temp')
        default_log_level = 'INFO'

        cli = CLIParser('SaaS Middleware command line interface (CLI)', arguments=[
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
            Argument('--log-to-aws', dest='log-to-aws', action='store_const', const=True,
                     help="enables logging to AWS CloudWatch"),
            Argument('--log-path', dest='log-path', action='store',
                     help="enables logging to file using the given path"),
            Argument('--log-console', dest="log-console", action='store_const', const=False,
                     help="enables logging to the console"),

        ], commands=[
            CLICommandGroup('identity', 'manage and explore identities', commands=[
                IdentityCreate(),
                IdentityRemove(),
                IdentityShow(),
                IdentityUpdate(),
                IdentityList(),
                IdentityDiscover(),
                IdentityPublish(),
                CLICommandGroup('credentials', 'manage credentials for a keystore', commands=[
                    CLICommandGroup('add', 'add credentials to a keystore', commands=[
                        CredentialsAddSSHCredentials(),
                        CredentialsAddGithubCredentials()
                    ]),
                    CLICommandGroup('test', 'test credentials', commands=[
                        CredentialsTestSSHCredentials(),
                        CredentialsTestGithubCredentials()
                    ]),
                    CredentialsRemove(),
                    CredentialsList()
                ]),
            ]),
            Service(),
            CLICommandGroup('dor', 'interact with a Data Object Repository (DOR)', arguments=[
                Argument('--address', dest='address', action='store',
                         help="the REST address (host:port) of the node (e.g., '127.0.0.1:5001')")
            ], commands=[
                DORSearch(),
                DORAdd(),
                DORAddGPP(),
                DORMeta(),
                DORDownload(),
                DORRemove(),
                DORTag(),
                DORUntag(),
                CLICommandGroup('access', 'manage access to data objects', commands=[
                    DORAccessGrant(),
                    DORAccessRevoke(),
                    DORAccessShow()
                ])
            ]),
            CLICommandGroup('rti', 'interact with a Runtime Infrastructure (RTI)', arguments=[
                Argument('--address', dest='address', action='store',
                         help="the REST address (host:port) of the node (e.g., '127.0.0.1:5001')")
            ], commands=[
                CLICommandGroup('proc', 'manage processors', commands=[
                    RTIProcDeploy(),
                    RTIProcUndeploy(),
                    RTIProcList(),
                    RTIProcShow(),
                    RTIProcStatus()
                ]),
                CLICommandGroup('job', 'manage job', commands=[
                    RTIJobList(),
                    RTIJobSubmit(),
                    RTIJobStatus(),
                    RTIJobCancel(),
                    RTIJobLogs()
                ])
            ]),
            CLICommandGroup('network', 'explore the network of nodes', arguments=[
                Argument('--address', dest='address', action='store',
                         help="the REST address (host:port) of the node (e.g., '127.0.0.1:5001')")
            ], commands=[
                NetworkList()
            ]),
            Compose()
        ])

        cli.execute(sys.argv[1:])
        sys.exit(0)

    except CLIRuntimeError as e:
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
