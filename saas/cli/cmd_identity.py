import os

from saascore.api.sdk.proxies import NodeDBProxy
from saascore.log import Logging
from tabulate import tabulate

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_for_string, get_available_keystores, prompt_for_confirmation, \
    prompt_for_password, prompt_if_missing, prompt_for_keystore_selection, prompt_for_selection, load_keystore
from saascore.helpers import read_json_from_file, validate_json
from saascore.keystore.assets.credentials import CredentialsAsset, SSHCredentials, GithubCredentials
from saascore.keystore.keystore import Keystore
from saascore.keystore.schemas import SerializedKeystore as KeystoreSchema

logger = Logging.get('cli.identity')


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
        print(f"- Signing Key: {keystore.signing_key.info()}")
        print(f"- Encryption Key: {keystore.encryption_key.info()}")


class IdentityRemove(CLICommand):
    def __init__(self):
        super().__init__('remove', 'removes an existing identity', arguments=[
            Argument('--confirm', dest="confirm", action='store_const', const=True,
                     help=f"do not require user confirmation to delete keystore"),
        ])

    def execute(self, args: dict) -> None:
        load_keystore(args, ensure_publication=False)

        # confirm removal (if applicable)
        if prompt_if_missing(args, 'confirm', prompt_for_confirmation,
                             message=f"Remove keystore {args['keystore-id']}?", default=False):

            # delete the keystore
            keystore_path = os.path.join(args['keystore'], f"{args['keystore-id']}.json")
            os.remove(keystore_path)
            print(f"Keystore {args['keystore-id']} deleted.")

        else:
            print(f"Aborting.")


class IdentityShow(CLICommand):
    def __init__(self):
        super().__init__('show', 'shows details about a keystore', arguments=[])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                          path=args['keystore'],
                          message="Select the keystore:")

        # read the keystore file
        keystore_path = os.path.join(args['keystore'], f"{args['keystore-id']}.json")
        content = read_json_from_file(keystore_path)
        if not validate_json(content, KeystoreSchema.schema()):
            raise CLIRuntimeError(f"Keystore {args['keystore-id']} content not compliant with json schema.")

        # show the public information
        print(f"Keystore details:")
        print(f"- Id: {content['iid']}")
        print(f"- Name: {content['profile']['name']}")
        print(f"- Email: {content['profile']['email']}")
        print(f"- Nonce: {content['nonce']}")
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

            # headers
            lines = [
                ['NAME', 'EMAIL', 'KEYSTORE/IDENTITY ID'],
                ['----', '-----', '--------------------']
            ]

            # list
            lines += [
                [item['name'], item['email'], item['keystore-id']] for item in available
            ]

            print(tabulate(lines, tablefmt="plain"))
        else:
            print(f"No keystores found in '{args['keystore']}'.")


class IdentityPublish(CLICommand):
    def __init__(self):
        super().__init__('publish', 'publishes an identity update to a node', arguments=[
            Argument('--address', dest='address', action='store', required=False,
                     help=f"the address (host:port) of the node")
        ])

    def execute(self, args: dict) -> None:
        keystore = load_keystore(args, ensure_publication=False)

        # prompt for the address (if missing)
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')

        proxy = NodeDBProxy(args['address'].split(":"))
        proxy.update_identity(keystore.identity)
        print(f"Published identity of keystore {args['keystore-id']}")


class IdentityDiscover(CLICommand):
    def __init__(self):
        super().__init__('discover', 'retrieves a list of all identities known to a node', arguments=[
            Argument('--address', dest='address', action='store', required=False,
                     help=f"the address (host:port) of the node")
        ])

    def execute(self, args):
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter address of node for discovery:",
                          default="127.0.0.1:5001")

        proxy = NodeDBProxy(args['address'].split(":"))
        identities = proxy.get_identities()
        if len(identities) == 0:
            print(f"No identities discovered.")
        else:
            print(f"Discovered {len(identities)} identities:")

            # headers
            lines = [
                ['NAME', 'EMAIL', 'IDENTITY ID'],
                ['----', '-----', '-----------']
            ]

            # list
            lines += [
                [item.name, item.email, item.id] for item in identities.values()
            ]

            print(tabulate(lines, tablefmt="plain"))


class IdentityUpdate(CLICommand):
    def __init__(self):
        super().__init__('update', 'updates the profile of the identity', arguments=[
            Argument('--name', dest='name', action='store', help=f"name of the identity"),
            Argument('--email', dest='email', action='store', help=f"email of the identity")
        ])

    def execute(self, args: dict) -> None:
        keystore = load_keystore(args, ensure_publication=False)

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


class CredentialsAdd(CLICommand):
    def __init__(self):
        super().__init__('add', 'adds credentials to the keystore', arguments=[])

    def execute(self, args: dict) -> None:
        keystore = load_keystore(args, ensure_publication=False)

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
                    'key': None,
                    'key_is_password': None
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
            }
        ]
        item = prompt_for_selection(items, 'Select the type of credential to add:')

        # do we already have credentials of that type? if no, create it
        asset = keystore.get_asset(item['asset-key'])
        if asset is None:
            asset = CredentialsAsset.create(item['asset-key'], item['c-type'])

        # create a credential
        cred_key = prompt_for_string(f"Enter the key/name for which this credential is for "
                                     f"(hint: {item['cred-key']}):")
        for key in item['template'].keys():
            item['template'][key] = prompt_for_string(f"Enter value for '{key}':",
                                                      hide=key in item['hide-when-prompt'])

        # update the asset
        asset.update(cred_key, item['c-type'].from_record(item['template']))

        # update the keystore
        keystore.update_asset(asset)
        print(f"Credential successfully created.")


class CredentialsRemove(CLICommand):
    def __init__(self):
        super().__init__('remove', 'removes credentials from a keystore', arguments=[])

    def execute(self, args: dict) -> None:
        keystore = load_keystore(args, ensure_publication=False)

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
            raise CLIRuntimeError("No credentials found. Aborting.")

        # any items selected for removal?
        items = prompt_for_selection(removable, 'Select the credentials to be removed:', allow_multiple=True)
        if len(items) == 0:
            raise CLIRuntimeError("Nothing to remove. Aborting.")

        # confirm and remove
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


class CredentialsList(CLICommand):
    def __init__(self):
        super().__init__('list', 'lists credentials of the keystore', arguments=[])

    def execute(self, args: dict) -> None:
        keystore = load_keystore(args, ensure_publication=False)

        # collect all credentials
        credential_types = ['ssh-credentials', 'github-credentials', 'smtp-credentials']
        credentials = []
        for c_type in credential_types:
            # print the credentials for this type
            asset: CredentialsAsset = keystore.get_asset(c_type)
            if asset is not None:
                index = asset.index()
                for key in index:
                    credentials.append({
                        'type': c_type,
                        'key': key
                    })

        # print the credentials
        if len(credentials) == 0:
            raise CLIRuntimeError("No credentials found in keystore.")

        print(f"Found {len(credentials)} credentials in keystore:")

        # headers
        lines = [
            ['TYPE', 'CREDENTIAL KEY'],
            ['----', '--------------']
        ]

        # list
        lines += [
            [item['type'], item['key']] for item in credentials
        ]

        print(tabulate(lines, tablefmt="plain"))
