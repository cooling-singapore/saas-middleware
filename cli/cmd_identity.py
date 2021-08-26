import logging
import os
import requests

from cli.helpers import CLICommand, Argument, prompt_for_string, \
    get_available_keystores, prompt_for_confirmation, prompt_for_address, \
    prompt_for_password, prompt_if_missing, unlock_keystore, \
    prompt_for_keystore_selection, prompt_for_selection
from saas.helpers import read_json_from_file, validate_json
from saas.keystore.assets.credentials import CredentialsAsset, SSHCredentials, SMTPCredentials, GithubCredentials
from saas.keystore.identity import Identity
from saas.keystore.keystore import Keystore
from saas.keystore.schemas import keystore_schema
from saas.nodedb.blueprint import NodeDBProxy


logger = logging.getLogger('cli.identity')


class IdentityCreate(CLICommand):
    def __init__(self):
        super().__init__('create', 'creates a new identity', arguments=[
            Argument('--name', dest='name', action='store', help=f"name of the identity"),
            Argument('--email', dest='email', action='store', help=f"email of the identity")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'name', prompt_for_string, message="Enter name:")
        prompt_if_missing(args, 'email', prompt_for_string, message="Enter email:")
        prompt_if_missing(args, 'password', prompt_for_password)

        keystore = Keystore.create(args['keystore'], args['name'], args['email'], args['password'])
        identity = keystore.identity

        print(f"New keystore created!")
        print(f"- Identity: {identity.name}/{identity.email}/{identity.id}")
        print(f"- Signing Key: {keystore.signing_key().info()}")
        print(f"- Encryption Key: {keystore.encryption_key().info()}")


class IdentityRemove(CLICommand):
    def __init__(self):
        super().__init__('remove', 'removes an existing identity', arguments=[
            Argument('--confirm', dest="confirm", action='store_const', const=True,
                     help=f"do not require user confirmation to delete keystore"),
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection, path=args['keystore'], message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            # confirm removal (if applicable)
            confirm = prompt_if_missing(args, 'confirm', prompt_for_confirmation, message=f"Remove keystore {args['keystore-id']}?", default=False)
            if confirm:
                # delete the keystore
                keystore_path = os.path.join(args['keystore'], f"{args['keystore-id']}.json")
                os.remove(keystore_path)
                print(f"Keystore {args['keystore-id']} deleted.")

            else:
                print(f"Aborting.")
        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class IdentityShow(CLICommand):
    def __init__(self):
        super().__init__('show', 'shows details about a keystore', arguments=[])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection, path=args['keystore'], message="Select the keystore:")

        # read the keystore file
        keystore_path = os.path.join(args['keystore'], f"{args['keystore-id']}.json")
        content = read_json_from_file(keystore_path)
        if not validate_json(content, keystore_schema):
            print(f"Keystore {args['keystore-id']} content not compliant with json schema.")
            return None

        # show the public information
        print(f"Keystore details:")
        print(f"- Id: {content['iid']}")
        print(f"- Name: {content['profile']['name']}")
        print(f"- Email: {content['profile']['email']}")
        print(f"- Nonce: {content['nonce']}")
        # print(f"- Signature: {content['signature']}")
        print(f"- Assets:")
        for asset in content['assets']:
            if asset['type'] in ['KeyPairAsset', 'MasterKeyPairAsset']:
                print(f"    - {asset['key']}: {asset['content']['info']}")
            else:
                print(f"    - {asset['key']}")


class IdentityList(CLICommand):
    def __init__(self):
        super().__init__('list', 'lists all identities found in the keystore directory')

    def execute(self, args: dict) -> None:
        available = get_available_keystores(args['keystore'])
        if len(available) > 0:
            print(f"Found {len(available)} keystores in '{args['keystore']}':")
            for item in available:
                print(f"- {item['label']}")
        else:
            print(f"No keystores found in '{args['keystore']}':")


class IdentityPublish(CLICommand):
    def __init__(self):
        super().__init__('publish', 'publishes an identity update to a node', arguments=[
            Argument('--address', dest='address', action='store', required=False,
                     help=f"the address (host:port) of the node")
        ])

    def execute(self, args):
        prompt_if_missing(args, 'address', prompt_for_address, message="Enter address of node for publication:")
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection, path=args['keystore'], message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        # load the keystore
        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            try:
                proxy = NodeDBProxy(args['address'].split(":"))
                proxy.update_identity(keystore.identity)
                print(f"Published identity of keystore {args['keystore-id']}")

            except requests.exceptions.ConnectionError:
                print(f"Could not connect to node at '{args['address']}'. Aborting.")

            except requests.exceptions.InvalidURL:
                print(f"Invalid node address: '{args['address']}'. Aborting.")
        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class IdentityDiscover(CLICommand):
    def __init__(self):
        super().__init__('discover', 'retrieves a list of all identities known to a node', arguments=[
            Argument('--address', dest='address', action='store', required=False,
                     help=f"the address (host:port) of the node")
        ])

    def execute(self, args):
        prompt_if_missing(args, 'address', prompt_for_address, message="Enter address of node for discovery:")

        try:
            proxy = NodeDBProxy(args['address'].split(":"))
            identities = proxy.get_identities()
            if len(identities) == 0:
                print(f"No identities discovered.")
            else:
                print(f"Discovered {len(identities)} identities:")
                for serialised in identities.values():
                    identity = Identity.deserialise(serialised)
                    print(f"- {identity.name}/{identity.email}/{identity.id}")

        except requests.exceptions.ConnectionError:
            print(f"Could not connect to node at '{args['address']}'. Aborting.")

        except requests.exceptions.InvalidURL:
            print(f"Invalid node address: '{args['address']}'. Aborting.")


class IdentityUpdate(CLICommand):
    def __init__(self):
        super().__init__('update', 'updates the profile of the identity', arguments=[
            Argument('--name', dest='name', action='store', help=f"name of the identity"),
            Argument('--email', dest='email', action='store', help=f"email of the identity")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection, path=args['keystore'], message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        # load the keystore
        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            # show the public information
            print(f"Keystore details:")
            print(f"- Name: {keystore.identity.name}")
            print(f"- Email: {keystore.identity.email}")

            name = prompt_for_string("Enter name:", default=keystore.identity.name)
            email = prompt_for_string("Enter email address:", default=keystore.identity.email)
            if keystore.identity.name != name or keystore.identity.email != email:
                print(f"Updating profile.")
                keystore.update_profile(name=name, email=email)

            else:
                print(f"Nothing to update.")

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class CredentialsAdd(CLICommand):
    def __init__(self):
        super().__init__('add', 'adds credentials to the keystore', arguments=[])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection, path=args['keystore'], message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        # load the keystore
        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            # define the items and select one
            items = [
                {
                    'label': 'SSH Credentials',
                    'asset-key': 'ssh-credentials',
                    'c-type': SSHCredentials,
                    'cred-key': 'SSH profile name',
                    'template': {
                        'host': None,
                        'login': None,
                        'key_path': None
                    },
                    'hide-when-prompt': []
                },
                {
                    'label': 'Github Credentials',
                    'asset-key': 'github-credentials',
                    'c-type': GithubCredentials,
                    'cred-key': 'repository URL',
                    'template': {
                        'login': None,
                        'personal_access_token': None
                    },
                    'hide-when-prompt': ['personal_access_token']
                },
                {
                    'label': 'SMTP Credentials',
                    'asset-key': 'smtp-credentials',
                    'c-type': SMTPCredentials,
                    'cred-key': 'email address',
                    'template': {
                        'server': None,
                        'login': None,
                        'password': None
                    },
                    'hide-when-prompt': ['password']
                }
            ]
            item = prompt_for_selection(items, 'Select the type of credential to add:')

            # do we already have credentials of that type? if no, create it
            asset = keystore.get_asset(item['asset-key'])
            if asset is None:
                asset = CredentialsAsset.create(item['asset-key'], item['c-type'])

            # create a credential
            cred_key = prompt_for_string(f"Enter the key/name for which this credential is for (hint: {item['cred-key']}):")
            for key in item['template'].keys():
                item['template'][key] = prompt_for_string(f"Enter value for '{key}':", hide=key in item['hide-when-prompt'])

            # update the asset
            asset.update(cred_key, item['c-type'].from_record(item['template']))

            # update the keystore
            keystore.update_asset(asset)

            print(f"Credential successfully created.")

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class CredentialsRemove(CLICommand):
    def __init__(self):
        super().__init__('remove', 'removes credentials from a keystore', arguments=[])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection, path=args['keystore'], message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        # load the keystore
        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            # collect all the removable credentials
            removable = []
            credential_types = ['ssh-credentials', 'github-credentials', 'smtp-credentials']
            for c_type in credential_types:
                asset = keystore.get_asset(c_type)
                if asset is not None:
                    index = asset.index()
                    for key in index:
                        removable.append({
                            'asset': asset,
                            'c_type': c_type,
                            'key': key,
                            'label': f"[{c_type}] {key}"
                        })

            # prompt for selection
            if len(removable) == 0:
                print(f"No credentials found.")
                return None

            else:
                items = prompt_for_selection(removable, 'Select the credentials to be removed:', allow_multiple=True)
                if len(items) == 0:
                    print(f"Nothing to remove.")
                    return None

                else:
                    if prompt_for_confirmation("Remove the selected credentials?", default=False):
                        modified_assets = []
                        for item in items:
                            print(f"Removing {item['label']}...", end='')
                            item['asset'].remove(item['key'])
                            if item['asset'] not in modified_assets:
                                modified_assets.append(item['asset'])
                            print("Done")

                        for asset in modified_assets:
                            keystore.update_asset(asset)

                    else:
                        print(f"Aborting.")
                        return None

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class CredentialsList(CLICommand):
    def __init__(self):
        super().__init__('list', 'lists credentials of the keystore', arguments=[])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection, path=args['keystore'], message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        # load the keystore
        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            credential_types = ['ssh-credentials', 'github-credentials', 'smtp-credentials']

            # collect all credentials
            credentials = []
            for c_type in credential_types:
                # print the credentials for this type
                asset = keystore.get_asset(c_type)
                if asset is not None:
                    index = asset.index()
                    for key in index:
                        credentials.append(f"[{c_type}] {key}")

            # print the credentials
            if len(credentials) == 0:
                print(f"No credentials found in keystore.")

            else:
                print(f"Found {len(credentials)} credentials in keystore:")
                for c in credentials:
                    print(f"- {c}")

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")



