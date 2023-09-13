import os

from InquirerPy.base import Choice
from saas.core.helpers import generate_random_string
from saas.sdk.app.auth import UserDB, User
from saas.sdk.base import connect
from tabulate import tabulate

from saas.sdk.cli.exceptions import CLIRuntimeError
from saas.sdk.cli.helpers import CLICommand, Argument, prompt_if_missing, prompt_for_string, load_keystore, \
    extract_address, prompt_for_selection

default_userstore = os.path.join(os.environ['HOME'], '.userstore')


class UserInit(CLICommand):
    def __init__(self) -> None:
        super().__init__('init', 'initialise the user database', arguments=[
            Argument('--userstore', dest='userstore', action='store', default=default_userstore,
                     help=f"path to the userstore (default: '{default_userstore}')")
        ])

    def execute(self, args: dict) -> None:
        # get the user directory
        if os.path.isdir(args['userstore']):
            raise CLIRuntimeError(f"Directory already exists: {args['userstore']}")

        # initialise user db/keystore directory
        UserDB.initialise(args['userstore'])
        print(f"User directory initialised: {args['userstore']}")


class UserList(CLICommand):
    def __init__(self) -> None:
        super().__init__('list', 'prints a list of all users in the database', arguments=[
            Argument('--userstore', dest='userstore', action='store', default=default_userstore,
                     help=f"path to the userstore (default: '{default_userstore}')")
        ])

    def execute(self, args: dict) -> None:
        # get the user directory and initialise user database
        if not os.path.isdir(args['userstore']):
            raise CLIRuntimeError(f"Directory does not exist: {args['userstore']}")
        UserDB.initialise(args['userstore'])

        # get the list of base data packages
        result = UserDB.all_users()
        if len(result) == 0:
            print(f"No users found in database at {args['userstore']}:")

        else:
            print(f"Found {len(result)} users in database at {args['userstore']}:")

            # headers
            lines = [
                ['LOGIN', 'NAME', 'DISABLED', 'KEYSTORE ID'],
                ['-----', '----', '--------', '-----------']
            ]

            for user in result:
                lines.append([
                    user.login, user.name, 'Yes' if user.disabled else 'No', user.keystore.identity.id
                ])

            print(tabulate(lines, tablefmt="plain"))
            print()


class UserCreate(CLICommand):
    default_node_address = '127.0.0.1:5001'

    def __init__(self) -> None:
        super().__init__('create', 'create a new user profile', arguments=[
            Argument('--userstore', dest='userstore', action='store', default=default_userstore,
                     help=f"path to the userstore (default: '{default_userstore}')"),
            Argument('--node_address', dest='node_address', action='store',
                     help=f"address used for publishing the identity (default: '{self.default_node_address}')."),
            Argument('--login', dest='login', action='store', required=False,
                     help="the login for this account"),
            Argument('--name', dest='name', action='store', required=False,
                     help="the name of the user"),
            Argument('--user_password', dest='user_password', action='store', required=False,
                     help="the password of the user")
        ])

    def execute(self, args: dict) -> None:
        # get the user directory and initialise user database
        if not os.path.isdir(args['userstore']):
            raise CLIRuntimeError(f"Directory does not exist: {args['userstore']}")
        UserDB.initialise(args['userstore'])

        # get the node address
        prompt_if_missing(args, 'node_address', prompt_for_string,
                          message="Enter address of the SaaS node REST service:",
                          default=self.default_node_address)

        prompt_if_missing(args, 'login', prompt_for_string, message="Enter the login:")
        prompt_if_missing(args, 'name', prompt_for_string, message="Enter the name:")

        # check the password
        prompt_if_missing(args, 'user_password', prompt_for_string, allow_empty=True, hide=True,
                          message="Enter the password [leave empty to generate]:")
        if len(args['user_password']) == 0:
            args['user_password'] = generate_random_string(8)
            print(f"Using generated password: {args['user_password']}")

        # create the user
        user: User = UserDB.add_user(args['login'], args['name'], args['user_password'])
        print(f"User account created: {user.login}")

        # publish the identity of the user
        identity = user.keystore.identity
        print(f"Publish identity {identity.id} of user {user.login} to node at {args['node_address']}")
        # server_keystore = load_keystore(args, ensure_publication=True, address_arg='node_address')
        context = connect(extract_address(args['node_address']), user.keystore)
        context.publish_identity(user.keystore.identity)


class UserRemove(CLICommand):
    def __init__(self) -> None:
        super().__init__('remove', 'remove a user profile', arguments=[
            Argument('--userstore', dest='userstore', action='store', default=default_userstore,
                     help=f"path to the userstore (default: '{default_userstore}')"),
            Argument('--login', dest='login', action='store', required=False,
                     help="the login for this account")
        ])

    def execute(self, args: dict) -> None:
        # get the user directory and initialise user database
        if not os.path.isdir(args['userstore']):
            raise CLIRuntimeError(f"Directory does not exist: {args['userstore']}")
        UserDB.initialise(args['userstore'])

        # determine the username (if we don't have one already)
        if not args['login']:
            # determine the choices of user to be removed
            choices = [
                Choice(user.login,
                       f"{user.login} ({user.name}, Enabled: {'NO' if user.disabled else 'yes'})"
                       ) for user in UserDB.all_users()]
            if not choices:
                raise CLIRuntimeError(f"No users found in {args['userstore']}")

            args['login'] = prompt_for_selection(choices, "Select the user to be removed:", allow_multiple=False)

        # check if the user exists
        UserDB.initialise(args['userstore'])
        user: User = UserDB.get_user(args['login'])
        if not user:
            raise CLIRuntimeError(f"No user with username '{args['login']}'")

        user: User = UserDB.delete_user(args['login'])
        print(f"User account removed: login={user.login}")


class UserEnable(CLICommand):
    def __init__(self) -> None:
        super().__init__('enable', 'enable a user profile', arguments=[
            Argument('--userstore', dest='userstore', action='store', default=default_userstore,
                     help=f"path to the userstore (default: '{default_userstore}')"),
            Argument('--login', dest='login', action='store', required=False,
                     help="the login of the account")
        ])

    def execute(self, args: dict) -> None:
        # get the user directory and initialise user database
        if not os.path.isdir(args['userstore']):
            raise CLIRuntimeError(f"Directory does not exist: {args['userstore']}")
        UserDB.initialise(args['userstore'])

        # determine the username (if we don't have one already)
        if not args['login']:
            # determine the choices of user to be removed
            choices = [Choice(user.login, user.login) for user in UserDB.all_users()]
            if not choices:
                raise CLIRuntimeError(f"No users found in {args['userstore']}")

            args['login'] = prompt_for_selection(choices, "Select the user to be removed:", allow_multiple=False)

        # enable the user
        user = UserDB.enable_user(args['login'])
        print(f"User account enabled: {user.login} ({user.name})")


class UserDisable(CLICommand):
    def __init__(self) -> None:
        super().__init__('disable', 'disable a user profile', arguments=[
            Argument('--userstore', dest='userstore', action='store', default=default_userstore,
                     help=f"path to the userstore (default: '{default_userstore}')"),
            Argument('--login', dest='login', action='store', required=False,
                     help="the login of the account")
        ])

    def execute(self, args: dict) -> None:
        # get the user directory and initialise user database
        if not os.path.isdir(args['userstore']):
            raise CLIRuntimeError(f"Directory does not exist: {args['userstore']}")
        UserDB.initialise(args['userstore'])

        # determine the username (if we don't have one already)
        if not args['login']:
            # determine the choices of user to be removed
            choices = [Choice(user.login, user.login) for user in UserDB.all_users()]
            if not choices:
                raise CLIRuntimeError(f"No users found in {args['userstore']}")

            args['login'] = prompt_for_selection(choices, "Select the user to be removed:", allow_multiple=False)

        # enable the user
        user = UserDB.disable_user(args['login'])
        print(f"User account disabled: {user.login} ({user.name})")


class UserUpdateName(CLICommand):
    def __init__(self) -> None:
        super().__init__('update', 'update user display name', arguments=[
            Argument('--userstore', dest='userstore', action='store', default=default_userstore,
                     help=f"path to the userstore (default: '{default_userstore}')"),
            Argument('--login', dest='login', action='store', required=False,
                     help="the login of the account"),
            Argument('--new_display_name', dest='user_display_name', action='store', required=True,
                     help="the new display name of the account")
        ])

    def execute(self, args: dict) -> None:
        # get the user directory and initialise user database
        if not os.path.isdir(args['userstore']):
            raise CLIRuntimeError(f"Directory does not exist: {args['userstore']}")
        UserDB.initialise(args['userstore'])

        # determine the username (if we don't have one already)
        if not args['login']:
            # determine the choices of user to be updated
            choices = [Choice(user.login, user.login) for user in UserDB.all_users()]
            if not choices:
                raise CLIRuntimeError(f"No users found in {args['userstore']}")

            args['login'] = prompt_for_selection(choices, "Select the user to be updated:", allow_multiple=False)

        # update the user
        user = UserDB.update_user(args['login'], True, user_display_name=args['user_display_name'])
        print(f"User updated: {user.login} ({user.name})")


class UserUpdatePassword(CLICommand):
    def __init__(self) -> None:
        super().__init__('update', 'update user password', arguments=[
            Argument('--userstore', dest='userstore', action='store', default=default_userstore,
                     help=f"path to the userstore (default: '{default_userstore}')"),
            Argument('--login', dest='login', action='store', required=False,
                     help="the login of the account"),
            Argument('--new_password', dest='new_password', action='store', required=False,
                     help="the new password of the account")
        ])

    def execute(self, args: dict) -> None:
        # get the user directory and initialise user database
        if not os.path.isdir(args['userstore']):
            raise CLIRuntimeError(f"Directory does not exist: {args['userstore']}")
        UserDB.initialise(args['userstore'])

        # determine the username (if we don't have one already)
        if not args['login']:
            # determine the choices of user to be updated
            choices = [Choice(user.login, user.login) for user in UserDB.all_users()]
            if not choices:
                raise CLIRuntimeError(f"No users found in {args['userstore']}")

            args['login'] = prompt_for_selection(choices, "Select the user to be updated:", allow_multiple=False)

        # check the password
        prompt_if_missing(args, 'new_password', prompt_for_string, allow_empty=True, hide=True,
                          message="Enter the new password [leave empty to generate]:")
        if len(args['new_password']) == 0:
            args['new_password'] = generate_random_string(8)
            print(f"Using generated new password: {args['new_password']}")

        # update the user
        user = UserDB.update_user(args['login'], True, password=("", args['new_password']))
        print(f"User updated: {user.login} ({user.name})")




