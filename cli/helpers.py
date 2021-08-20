from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
from abc import abstractmethod, ABC
from argparse import ArgumentParser
from PyInquirer import prompt

from saas.helpers import read_json_from_file, validate_json
from saas.keystore.keystore import Keystore
from saas.keystore.schemas import keystore_schema

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('cli.helpers')


def initialise_storage_folder(path: str, usage: str) -> None:
    # check if the path is pointing at a file
    if os.path.isfile(path):
        raise Exception(f"Storage path '{path}' is a file. This path cannot be used as storage ({usage}) directory.")

    # check if it already exists as directory
    if not os.path.isdir(path):
        logger.info(f"creating storage ({usage}) directory '{path}'")
        os.mkdir(path)
        print(f"Storage directory ({usage}) created at '{path}'.")


def get_available_keystores(path: str) -> (dict, list):
    available = {}
    index = []
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
        if validate_json(content, keystore_schema):
            available[temp[0]] = {
                'keystore-id': temp[0],
                'path': keystore_path,
                'label': f"{content['profile']['name']}/{content['profile']['email']}/{temp[0]}"
            }
            index.append(temp[0])

    return available, index


def prompt_for_password(args: dict, key: str, confirm=True) -> None:
    if args[key] is not None:
        return None

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
            if answers['password1'] == answers['password2']:
                args[key] = answers['password1']
                return None

            print(f"Passwords don't match! Please try again.")

    else:
        questions = [
            {
                'type': 'password',
                'message': 'Enter password:',
                'name': 'password'
            }
        ]

        answers = prompt(questions)
        args[key] = answers['password']


def prompt_for_string(args: dict, key: str, message: str) -> None:
    questions = [
        {
            'type': 'input',
            'message': message,
            'name': key
        }
    ]

    if args[key] is None:
        answers = prompt(questions)
        args[key] = answers[key]


def prompt_for_selection(items: dict[str, dict], index: list[str], message: str) -> dict:
    reverse = {}
    for item in items.values():
        reverse[item['label']] = item

    choices = []
    for key in index:
        item = items[key]
        choices.append(item['label'])

    questions = [
        {
            'type': 'list',
            'message': message,
            'name': 'selection',
            'choices': choices
        }
    ]

    answers = prompt(questions)
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


class Argument:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs


class CLIExecutable:
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

    def execute(self, args) -> None:
        c_name = args[self._tag]
        command = self._c_map[c_name]
        command.execute(args)


class CLIParser(CLICommandGroup):
    def __init__(self, description, arguments: list[Argument] = None, commands: list[CLIExecutable] = None) -> None:
        super().__init__('main', description, arguments, commands)

    def execute(self, args) -> None:
        parser = argparse.ArgumentParser(description=self._description)

        try:
            self.initialise(parser)

            args = vars(parser.parse_args(args))

            super().execute(args)

        except argparse.ArgumentError:
            parser.print_help()
            return None
