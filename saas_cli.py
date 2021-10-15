#! /usr/bin/env python3

import os
import sys

from cli.cmd_dor import DORAdd, DORAddGPP, DORRemove, DORSearch, DORTag, DORUntag, DORAccessGrant, \
    DORAccessRevoke, DORAccessShow
from cli.cmd_identity import IdentityCreate, IdentityRemove, IdentityShow, IdentityUpdate, IdentityList, \
    IdentityDiscover, IdentityPublish, CredentialsAdd, CredentialsRemove, CredentialsList
from cli.cmd_network import NetworkShow
from cli.cmd_rti import RTIProcDeploy, RTIProcUndeploy, RTIJobSubmit, RTIJobStatus, RTIProcList
from cli.cmd_service import Service
from cli.helpers import CLIParser, Argument, CLICommandGroup
from saas.exceptions import SaaSException

if __name__ == "__main__":
    try:
        default_keystore = os.path.join(os.environ['HOME'], '.keystore')
        default_temp_dir = os.path.join(os.environ['HOME'], '.temp')
        default_logging = 'file'

        cli = CLIParser('SaaS Middleware command line interface (CLI)', arguments=[
            Argument('--keystore', dest='keystore', action='store', default=default_keystore,
                     help=f"path to the keystore (default: '{default_keystore}')"),
            Argument('--temp-dir', dest='temp-dir', action='store', default=default_temp_dir,
                     help=f"path to directory used for intermediate files (default: '{default_temp_dir}')"),
            Argument('--keystore-id', dest='keystore-id', action='store',
                     help=f"id of the keystore to be used if there are more than one available "
                          f"(default: id of the only keystore if only one is available )"),
            Argument('--password', dest='password', action='store',
                     help=f"password for the keystore"),
            Argument('--logging', dest='logging', action='store',
                     choices=['console', 'file', 'both'], default=default_logging,
                     help=f"indicate where log output should be written to (default: '{default_logging}')")

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
                    CredentialsAdd(),
                    CredentialsRemove(),
                    CredentialsList()
                ]),
            ]),
            Service(),
            CLICommandGroup('dor', 'interact with a Data Object Repository (DOR)', arguments=[
                Argument('--address', dest='address', action='store',
                         help=f"the REST address (host:port) of the node (e.g., '127.0.0.1:5001')")
            ], commands=[
                DORSearch(),
                DORAdd(),
                DORAddGPP(),
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
                         help=f"the REST address (host:port) of the node (e.g., '127.0.0.1:5001')")
            ], commands=[
                RTIProcDeploy(),
                RTIProcUndeploy(),
                RTIProcList(),
                RTIJobSubmit(),
                RTIJobStatus()
            ]),
            CLICommandGroup('network', 'explore the network of nodes', arguments=[
                Argument('--address', dest='address', action='store',
                         help=f"the REST address (host:port) of the node (e.g., '127.0.0.1:5001')")
            ], commands=[
                NetworkShow()
            ])
        ])

        cli.execute(sys.argv[1:])
        sys.exit(0)

    except SaaSException as e:
        print(e.reason)
        # trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        # print(trace)
        sys.exit(-1)
