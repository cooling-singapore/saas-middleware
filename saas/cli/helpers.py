from __future__ import annotations

import argparse
import logging
import os
import sys
from abc import abstractmethod, ABC
from argparse import ArgumentParser
from typing import Optional, Union

import requests
from PyInquirer import prompt
from saascore.api.sdk.exceptions import UnsuccessfulRequestError
from saascore.api.sdk.proxies import NodeDBProxy, DORProxy
from saascore.log import Logging

from saas.cli.exceptions import CLIRuntimeError
from saascore.helpers import read_json_from_file, validate_json
from saascore.keystore.identity import Identity
from saascore.keystore.keystore import Keystore
from saascore.keystore.schemas import SerializedKeystore as KeystoreSchema

logger = Logging.get('cli.helpers')


def initialise_storage_folder(path: str, usage: str) -> None:
    # check if the path is pointing at a file
    if os.path.isfile(path):
        raise CLIRuntimeError(f"Storage path '{path}' is a file. This path cannot be used as storage ({usage}) directory.")

    # check if it already exists as directory
    if not os.path.isdir(path):
        logger.info(f"creating storage ({usage}) directory '{path}'")
        os.mkdir(path)
        print(f"Storage directory ({usage}) created at '{path}'.")


def get_available_keystores(path: str) -> list[dict[str, str]]:
    available = []
    for f in os.listdir(path):
        # valid example: 9rak8e1tmc0xt4v3onwq7cpsydpselrjxqp2cys823alhu8evzkjhusqic740h39.json

        temp = os.path.basename(f).split(".")
        if len(temp) != 2:
            continue

        if temp[1].lower() != 'json':
            continue

        if len(temp[0]) != 64:
            continue

        # read content and validate
        keystore_path = os.path.join(path, f)
        content = read_json_from_file(keystore_path)
        if validate_json(content, KeystoreSchema.schema()):
            available.append({
                'keystore-id': temp[0],
                'keystore-path': keystore_path,
                'label': f"{content['profile']['name']}/{content['profile']['email']}/{temp[0]}",
                'name': content['profile']['name'],
                'email': content['profile']['email']
            })

    return available


def prompt_for_keystore_selection(path: str, message: str) -> Optional[dict]:
    # get all available keystores
    available = get_available_keystores(path)
    if len(available) == 0:
        raise CLIRuntimeError(f"No keystores found at '{path}'")

    return prompt_for_selection(available, message)


def prompt_for_identity_selection(address: str, message: str, id_name: str) -> Optional[dict]:
    try:
        # get all identities known to the node
        proxy = NodeDBProxy(address.split(":"))
        available = []
        for identity in proxy.get_identities().values():
            available.append({
                'label': f"{identity.name}/{identity.email}/{identity.id}",
                'identity': identity,
                id_name: identity.id
            })
            available.append(identity)

        # prompt for selection
        if len(available) == 0:
            raise CLIRuntimeError(f"No identities found at '{address}'")

        return prompt_for_selection(available, message)

    except requests.exceptions.ConnectionError:
        raise CLIRuntimeError(f"Could not connect to node at '{address}'.")

    except requests.exceptions.InvalidURL:
        raise CLIRuntimeError(f"Invalid node address: '{address}'.")


def load_keystore(args: dict, ensure_publication: bool, address_arg: str = 'address') -> Keystore:
    # prompt for the keystore and id (if missing)
    prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                      path=args['keystore'],
                      message="Select the keystore:")

    prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

    # try to unlock the keystore
    try:
        keystore = Keystore.load(args['keystore'], args['keystore-id'], args['password'])

    except Exception:
        raise CLIRuntimeError(f"Could not open keystore {args['keystore-id']}. "
                              f"Incorrect password? Keystore corrupted? Aborting.")

    if ensure_publication:
        # prompt for the address (if missing)
        prompt_if_missing(args, address_arg, prompt_for_string,
                          message="Enter the node's REST address",
                          default='127.0.0.1:5001')

        # try to ensure check if the identity is known and prompt to publish (if otherwise)
        try:
            # check if node knows about identity
            db = NodeDBProxy(args[address_arg].split(":"))
            if db.get_identity(keystore.identity.id) is None:
                if prompt_for_confirmation(
                        message=f"Identity {keystore.identity.id} is not known to the node at {args[address_arg]}. "
                                f"Publish identity?",
                        default=True
                ):
                    db.update_identity(keystore.identity)
                    print(f"Identity {keystore.identity.id} published to node at {args[address_arg]}.")
                else:
                    raise CLIRuntimeError(f"Cannot proceed without node ")

        except UnsuccessfulRequestError as e:
            raise CLIRuntimeError(f"Could not ensure identity is known to node at {args[address_arg]}. Aborting. "
                                  f"(Hint: {e.reason})")

    return keystore


def prompt_for_string(message: str, default: str = None, hide: bool = False, allow_empty: bool = False) -> str:
    questions = [
        {
            'type': 'password' if hide else 'input',
            'message': message,
            'name': 'answer',
        }
    ]

    # set the default (if any)
    if default:
        questions[0]['default'] = default

    while True:
        # get the answer
        answers = prompt(questions)
        if len(answers['answer']) == 0 and not allow_empty:
            continue

        return answers['answer']


def prompt_for_password(confirm: bool = True, allow_empty: bool = False) -> str:
    if confirm:
        questions = [
            {
                'type': 'password',
                'message': 'Enter password:',
                'name': 'password1'
            },
            {
                'type': 'password',
                'message': 'Re-enter password:',
                'name': 'password2'
            }
        ]

        while True:
            answers = prompt(questions)
            if len(answers['password1']) == 0 and not allow_empty:
                print(f"Password must not be empty! Please try again.")
                continue

            elif answers['password1'] != answers['password2']:
                print(f"Passwords don't match! Please try again.")
                continue

            else:
                return answers['password1']

    else:
        questions = [
            {
                'type': 'password',
                'message': 'Enter password:',
                'name': 'password'
            }
        ]

        while True:
            answers = prompt(questions)
            if len(answers['password']) == 0 and not allow_empty:
                print(f"Password must not be empty! Please try again.")
                continue

            else:
                return answers['password']


def prompt_for_selection(items: list[dict], message: str, allow_multiple=False) -> Union[dict, list[dict]]:
    # build the reverse lookup table and the choices
    reverse = {}
    choices = []
    for item in items:
        reverse[item['label']] = item
        choices.append({'name': item['label']} if allow_multiple else item['label'])

    # determine questions
    if allow_multiple:
        questions = [
            {
                'type': 'checkbox',
                'message': message,
                'name': 'selection',
                'choices': choices
            }
        ]

    else:
        questions = [
            {
                'type': 'list',
                'message': message,
                'name': 'selection',
                'choices': choices
            }
        ]

    answers = prompt(questions)

    if allow_multiple:
        result = []
        for item in answers['selection']:
            result.append(reverse[item])
        return result

    else:
        return reverse[answers['selection']]


def prompt_for_confirmation(message: str, default: bool) -> bool:
    questions = [
        {
            'type': 'confirm',
            'message': message,
            'name': 'confirmation',
            'default': default
        }
    ]

    answers = prompt(questions)
    return answers['confirmation']


def prompt_for_tags(message: str) -> list[str]:
    questions = [
        {
            'type': 'input',
            'message': message,
            'name': 'tag'
        }
    ]

    result = []
    while True:
        answers = prompt(questions)
        if answers['tag'] == '':
            break

        elif answers['tag'].count('=') > 1:
            print(f"Invalid tag. Use key=value form. Must not contain more than 1 '=' character. Try again...")

        else:
            result.append(answers['tag'])

    return result


def prompt_for_data_object_selection(address: str, owner: Identity, message: str,
                                     allow_multiple=False) -> Union[Optional[str], list[str]]:
    # find all data objects owned by the identity
    dor = DORProxy(address.split(':'))
    result = dor.search(owner_iid=owner.id)

    # do we have any data objects?
    if len(result) == 0:
        return [] if allow_multiple else None

    # determine choices
    choices = []
    for item in result:
        obj_id = item['obj_id']
        data_type = item['data_type']
        data_format = item['data_format']
        tags = [f"{tag['key']}={tag['value']}" for tag in item['tags']]
        choices.append({
            'label': f"{obj_id} [{data_type}/{data_format}] {tags}",
            'obj-id': obj_id
        })

    # prompt for selection
    return [item['obj-id'] for item in prompt_for_selection(choices, message, allow_multiple=True)] \
        if allow_multiple else prompt_for_selection(choices, message, allow_multiple=False)['obj-id']


def prompt_if_missing(args: dict, arg_key: str, function, **fargs) -> Union[str, bool]:
    if args[arg_key] is None:
        result = function(**fargs)
        if isinstance(result, dict):
            args[arg_key] = result[arg_key]

        else:
            args[arg_key] = result

    return args[arg_key]


def default_if_missing(args: dict, arg_key: str, default: Union[str, bool]) -> str:
    if args[arg_key] is None:
        args[arg_key] = default

    return args[arg_key]


def get_nodes_by_service(address: [str, int]) -> dict[str, dict]:
    result = {
        'dor': {},
        'rti': {}
    }

    db = NodeDBProxy(address)
    for node in db.get_network():
        if node['dor_service']:
            result['dor'][node['iid']] = node

        if node['rti_service']:
            result['rti'][node['iid']] = node

    return result


class Argument:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs


class CLIExecutable(ABC):
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def help(self) -> str:
        pass

    @abstractmethod
    def initialise(self, parser: ArgumentParser) -> None:
        pass

    @abstractmethod
    def execute(self, args: dict) -> None:
        pass


class CLICommand(CLIExecutable, ABC):
    def __init__(self, name: str, description: str, arguments: list[Argument] = None) -> None:
        self._name = name
        self._description = description
        self._arguments = arguments if arguments else []

    def name(self) -> str:
        return self._name

    def help(self) -> str:
        return self._description

    def initialise(self, parser: ArgumentParser) -> None:
        for a in self._arguments:
            parser.add_argument(*a.args, **a.kwargs)


class CLICommandGroup(CLIExecutable, ABC):
    def __init__(self, name: str, description: str,
                 arguments: list[Argument] = None, commands: list[CLIExecutable] = None) -> None:
        self._name = name
        self._tag = f"cmd_{name}"
        self._description = description
        self._arguments = arguments if arguments else []
        self._commands = commands if commands else []
        self._c_map: dict[str, CLIExecutable] = {}

    def name(self) -> str:
        return self._name

    def help(self) -> str:
        return self._description

    def initialise(self, parser: ArgumentParser) -> None:
        for a in self._arguments:
            parser.add_argument(*a.args, **a.kwargs)

        subparsers = parser.add_subparsers(title='Available commands', metavar=self._tag, dest=self._tag, required=True)
        for c in self._commands:
            c_parser = subparsers.add_parser(c.name(), help=c.help())
            c.initialise(c_parser)
            self._c_map[c.name()] = c

    def execute(self, args: dict) -> None:
        c_name = args[self._tag]
        command = self._c_map[c_name]
        command.execute(args)


class CLIArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_help()
        sys.exit(1)


class CLIParser(CLICommandGroup):
    def __init__(self, description, arguments: list[Argument] = None, commands: list[CLIExecutable] = None) -> None:
        super().__init__('main', description, arguments, commands)

    def execute(self, args: list) -> None:
        parser = CLIArgumentParser(description=self._description)

        try:
            self.initialise(parser)

            args = vars(parser.parse_args(args))

            initialise_storage_folder(args['temp-dir'], 'temp-dir')

            initialise_storage_folder(args['keystore'], 'keystore')

            if args['log-level'] == 'DEBUG':
                level = logging.DEBUG
            elif args['log-level'] == 'INFO':
                level = logging.INFO
            else:
                level = logging.INFO

            console_enabled = args['log-console'] is not None
            log_path = args['log-path']
            print(f"Logging parameters: level={level} log_path={log_path} console_enabled={console_enabled}")
            Logging.initialise(level=level, log_path=log_path, console_log_enabled=console_enabled)
            super().execute(args)

        except argparse.ArgumentError:
            parser.print_help()