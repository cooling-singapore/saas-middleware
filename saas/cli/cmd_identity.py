import os

from InquirerPy.base import Choice
from tabulate import tabulate

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_for_string, get_available_keystores, \
    prompt_for_confirmation, prompt_for_password, prompt_if_missing, prompt_for_keystore_selection, \
    prompt_for_selection, load_keystore, extract_address
from saas.core.schemas import GithubCredentials, SSHCredentials, KeystoreContent
from saas.core.keystore import Keystore
from saas.core.logging import Logging
from saas.nodedb.proxy import NodeDBProxy

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
        content = KeystoreContent.parse_file(keystore_path)

        # show the public information
        print(f"Keystore details:")
        print(f"- Id: {content.iid}")
        print(f"- Name: {content.profile.name}")
        print(f"- Email: {content.profile.email}")
        print(f"- Nonce: {content.nonce}")
        print(f"- Assets:")
        for key, content in content.assets.items():
            if content['type'] in ['KeyPairAsset', 'MasterKeyPairAsset']:
                print(f"    - {key}: {content['info']}")
            else:
                print(f"    - {key}")


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
                [item.profile.name, item.profile.email, item.iid] for item in available
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

        proxy = NodeDBProxy(extract_address(args['address']))
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

        proxy = NodeDBProxy(extract_address(args['address']))
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


class CredentialsAddSSHCredentials(CLICommand):
    def __init__(self):
        super().__init__('ssh', 'adds SSH credentials to the keystore', arguments=[
            Argument('--name', dest='name', action='store', help=f"name used to identify this SSH credential"),
            Argument('--host', dest='host', action='store', help=f"host used to connect the remote machine"),
            Argument('--login', dest='login', action='store', help=f"login used for connecting to remote machine"),
            Argument('--key-is-password', dest="key_is_password", action='store_const', const=True,
                     help=f"indicates that the key of this credential is a password"),
            Argument('--key', dest='key', action='store', help=f"key for this credentials items (or password in"
                                                               f"case --key-is-password is set)")
        ])

    def execute(self, args: dict) -> None:
        keystore = load_keystore(args, ensure_publication=False)

        prompt_if_missing(args, 'name', prompt_for_string, message="Enter name:")
        prompt_if_missing(args, 'host', prompt_for_string, message="Enter host:")
        prompt_if_missing(args, 'login', prompt_for_string, message="Enter login:")

        if args['key_is_password'] is None:
            args['key_is_password'] = prompt_for_selection([
                Choice(True, 'Password'),
                Choice(False, 'Key')
            ], f"Type of SSH credentials:")

        if args['key'] is None:
            if args['key_is_password']:
                args['key'] = prompt_for_password()

            else:
                args['key'] = prompt_for_string("Enter SSH key:")

        # update the keystore
        keystore.ssh_credentials.update(args['name'], SSHCredentials(host=args['host'], login=args['login'],
                                                                     key_is_password=args['key_is_password'],
                                                                     key=args['key']))
        keystore.sync()
        print(f"Credential successfully created.")


class CredentialsAddGithubCredentials(CLICommand):
    def __init__(self):
        super().__init__('github', 'adds Github credentials to the keystore', arguments=[
            Argument('--url', dest='url', action='store', help=f"URL of the repository (also used as identifier "
                                                               f"for this Github credential)"),
            Argument('--login', dest='login', action='store', help=f"login used to connect the remote machine"),
            Argument('--personal-access-token', dest='personal_access_token', action='store',
                     help=f"personal access token for the login"),
        ])

    def execute(self, args: dict) -> None:
        keystore = load_keystore(args, ensure_publication=False)

        prompt_if_missing(args, 'url', prompt_for_string, message="Enter repository URL:")
        prompt_if_missing(args, 'login', prompt_for_string, message="Enter login:")
        prompt_if_missing(args, 'personal_access_token', prompt_for_string, message="Enter personal access token:")

        # update the keystore
        keystore.github_credentials.update(
            args['url'], GithubCredentials(login=args['login'], personal_access_token=args['personal_access_token']))
        keystore.sync()
        print(f"Credential successfully created.")


class CredentialsRemove(CLICommand):
    def __init__(self):
        super().__init__('remove', 'removes credentials from a keystore', arguments=[])

    def execute(self, args: dict) -> None:
        keystore = load_keystore(args, ensure_publication=False)

        # collect all the removable credentials
        removable = []
        for name in keystore.ssh_credentials.list():
            label = f"[SSH] {name}"
            removable.append(Choice(value={
                'asset': 'ssh',
                'label': label,
                'key': name
            }, name=label))

        for name in keystore.github_credentials.list():
            label = f"[Github] {name}"
            removable.append(Choice(value={
                'asset': 'github',
                'label': label,
                'key': name
            }, name=label))

        # prompt for selection
        if len(removable) == 0:
            raise CLIRuntimeError("No credentials found. Aborting.")

        # any items selected for removal?
        items = prompt_for_selection(removable, 'Select the credentials to be removed:', allow_multiple=True)
        if len(items) == 0:
            raise CLIRuntimeError("Nothing to remove. Aborting.")

        # confirm and remove
        if prompt_for_confirmation("Remove the selected credentials?", default=False):
            for item in items:
                print(f"Removing {item['label']}...", end='')
                if item['asset'] == 'ssh':
                    keystore.ssh_credentials.remove(item['key'])
                    print("Done")
                elif item['asset'] == 'github':
                    keystore.github_credentials.remove(item['key'])
                    print("Done")
            keystore.sync()

        else:
            print(f"Aborting.")


class CredentialsList(CLICommand):
    def __init__(self):
        super().__init__('list', 'lists credentials of the keystore', arguments=[])

    def execute(self, args: dict) -> None:
        keystore = load_keystore(args, ensure_publication=False)

        # headers
        lines = [
            ['TYPE', 'CREDENTIAL NAME', 'DETAILS'],
            ['----', '---------------', '-------']
        ]

        for name in keystore.ssh_credentials.list():
            c = keystore.ssh_credentials.get(name)
            lines.append(['SSH', name, f"{c.login}@{c.host}"])

        for name in keystore.github_credentials.list():
            c = keystore.github_credentials.get(name)
            lines.append(['Github', name, c.login])

        if len(lines) == 2:
            raise CLIRuntimeError("No credentials found.")

        print(f"Found {len(lines)-2} credentials:")
        print(tabulate(lines, tablefmt="plain"))
