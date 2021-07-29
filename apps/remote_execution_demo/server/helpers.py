import os
import pathlib
import logging

from saas.keystore.keystore import Keystore
from saas.utilities.general_helpers import prompt

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('helpers')


def initialise_keystore_path(path):
    if os.path.isfile(path):
        raise Exception(f"Keystore path '{path}' is a file.")

    if not os.path.isdir(path):
        logger.info(f"creating keystore directory '{path}'")

        p = pathlib.Path(path)
        p.mkdir(parents=True, exist_ok=True)


def get_keystore(path, password=None):
    # check if the path is point at a directory
    if os.path.isdir(path):
        logger.info(f"loading keystore from '{path}'")
    else:
        raise Exception(f"Keystore path '{path}' not a directory.")

    # determine the available keystores at the location
    available = []
    for f in os.listdir(path):
        # determine the iid
        temp = f.split(".")
        keystore_id = temp[0]

        # add if the master/keystores files exist
        if Keystore.is_valid(path, keystore_id) and keystore_id not in available:
            available.append(keystore_id)

    # do we have any?
    if len(available) == 0:
        print(f"No existing keystores found at location '{path}'. Creating a new keystore.")

        name = prompt(f"Enter name:")
        email = prompt(f"Enter email address:")
        if not password:
            password = prompt(f"Enter password:", hidden=True)

        keystore = Keystore.create(path, name, email, password)

        print(f"New keystore created!")
        print(f"- Identity: {keystore.identity.iid}")
        print(f"- Master: {keystore.master.iid}")
        print(f"- Keys: {len(keystore.content['object_keys'])}")
        return keystore

    else:
        # prompt if there is more than one keystore
        selected = 0
        if len(available) > 1:
            valid = []
            print(f"Multiple keystores found at location '{path}':")
            for i in range(len(available)):
                valid.append(str(i))
                print(f"[1] {available[i]}")

            selected = prompt("Select keystore: ", valid)

        keystore_id = available[selected]

        print(f"Using existing keystore {keystore_id}")
        if not password:
            password = prompt(f"Enter password:", hidden=True)

        # load existing keystore
        keystore = Keystore.load(path, keystore_id, password)

        print(f"Existing keystore loaded!")
        print(f"- Identity: {keystore.identity.iid}")
        print(f"- Master: {keystore.master.iid}")
        print(f"- Keys: {len(keystore.content['object_keys'])}")
        return keystore
