import os
import argparse
import sys
import traceback
import logging
import subprocess

from cryptography.fernet import Fernet

from saas.dor.blueprint import DORProxy
from saas.keystore.keystore import Keystore
from saas.node import Node
from saas.utilities.general_helpers import prompt, get_address_from_string

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('CLI_Keystore')


def encrypt_file(source, destination, key, chunk_size=1024*1024):
    cipher = Fernet(key)
    with open(destination, 'wb') as f_out:
        with open(source, 'rb') as f_in:
            chunk = f_in.read(chunk_size)
            while chunk:
                chunk = cipher.encrypt(chunk)
                chunk_length = len(chunk)
                length_bytes = chunk_length.to_bytes(4, byteorder='big')

                f_out.write(length_bytes)
                f_out.write(chunk)

                chunk = f_in.read(chunk_size)


def decrypt_file(source, destination, key):
    cipher = Fernet(key)
    with open(destination, 'wb') as f_out:
        with open(source, 'rb') as f_in:
            while True:
                length_bytes = f_in.read(4)
                if not length_bytes:
                    break

                chunk_size = int.from_bytes(length_bytes, 'big')
                chunk = f_in.read(chunk_size)
                chunk = cipher.decrypt(chunk)

                f_out.write(chunk)


def initialise_keystore_folder(path):
    if os.path.isfile(path):
        raise Exception(f"Keystore path '{path}' is a file.")

    if not os.path.isdir(path):
        logger.info(f"creating keystore directory '{path}'")
        subprocess.check_output(['mkdir', path])


def load_keystore(args):
    path = args['keystore']

    # check if the path is point at a directory
    if os.path.isdir(path):
        logger.info(f"loading keystore from '{path}'")
    else:
        raise Exception(f"Keystore path '{path}' not a directory.")

    # do we have a keystore id?
    if 'keystore-id' in args and args['keystore-id'] is not None:
        if not Keystore.is_valid(path, args['keystore-id']):
            return None

    else:
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
            return None

        # prompt if there is more than one keystore
        selected = 0
        if len(available) > 1:
            valid = []
            print(f"Multiple keystores found at location '{path}':")
            for i in range(len(available)):
                valid.append(str(i))
                print(f"[1] {available[i]}")

            selected = prompt("Select keystore: ", valid)

        args['keystore-id'] = available[selected]

    if 'password' not in args or args['password'] is None:
        args['password'] = prompt(f"Enter password:", hidden=True)

    # load existing keystore
    keystore = Keystore.load(path, args['keystore-id'], args['password'])

    print(f"Existing keystore loaded!")
    print(f"- Identity: {keystore.identity.iid}")
    print(f"- Master: {keystore.master.iid}")
    print(f"- Keys: {len(keystore.content['object_keys'])}")

    return keystore


def add_cmd_initialise(subparsers):
    init_parser = subparsers.add_parser('init', help='create an identity and initialises the keystore.')
    init_parser.add_argument('--name', dest='name', action='store',
                             help=f"name of the identity")
    init_parser.add_argument('--email', dest='email', action='store',
                             help=f"email of the identity")
    init_parser.add_argument('--password', dest='password', action='store',
                             help=f"password for the keystore")


def exec_cmd_initialise(args):
    initialise_keystore_folder(args['keystore'])

    if args['name'] is None:
        args['name'] = prompt(f"Enter name:")

    if args['email'] is None:
        args['email'] = prompt(f"Enter email address:")

    if args['password'] is None:
        args['password'] = prompt(f"Enter password:", hidden=True)

    keystore = Keystore.create(args['keystore'], args['name'], args['email'], args['password'])

    print(f"New keystore created!")
    print(f"- Identity: {keystore.identity.iid}")
    print(f"- Master: {keystore.master.iid}")
    print(f"- Keys: {len(keystore.content['object_keys'])}")

    return keystore.identity.iid


def add_cmd_service(subparsers):
    default_datastore = os.path.join(os.environ['HOME'], '.datastore')
    default_host = '127.0.0.1'
    default_rest_port = 5001
    default_p2p_port = 4001
    default_service = 'full'

    service_parser = subparsers.add_parser('service', help='start a node as service provider')
    service_parser.add_argument('--datastore', dest='datastore', action='store',
                                default=default_datastore,
                                help=f"path to the datastore (default: '{default_datastore}')")
    service_parser.add_argument('--host', dest='host', action='store',
                                default=default_host,
                                help=f"host to be used by the services (default: '{default_host}').")
    service_parser.add_argument('--rest-port', dest='rest-port', action='store',
                                default=default_rest_port,
                                help=f"port to be used by the service REST API endpoints (default: {default_rest_port}).")
    service_parser.add_argument('--p2p-port', dest='p2p-port', action='store',
                                default=default_p2p_port,
                                help=f"port to be used by the node P2P interface (default: {default_p2p_port}).")
    service_parser.add_argument('--boot-node', dest='boot-node', action='store',
                                default=f"{default_host}:{default_p2p_port}",
                                help=f"URL (address:p2p-port) of a existing node for joining a network "
                                     f"(default: '{default_host}:{default_p2p_port}').")
    service_parser.add_argument('--service', dest='service', action='store',
                                choices=['full', 'storage', 'execution'],
                                default=default_service,
                                help=f"indicate the service provided by the node: 'storage' and 'execution' will only "
                                     f"load the DOR or RTI modules, respectively; a 'full' node will provide both "
                                     f"(default: '{default_service}').")
    service_parser.add_argument('--keystore-id', dest='keystore-id', action='store',
                                help=f"id of the keystore to be used if there are more than one available "
                                     f"(default: id of the only keystore if only one is available )")
    service_parser.add_argument('--password', dest='password', action='store',
                                help=f"password for the keystore")


def exec_cmd_service(args):
    keystore = load_keystore(args)

    rest_service_address = (args['host'], args['rest-port'])
    p2p_service_address = (args['host'], args['p2p-port'])
    boot_node_address = get_address_from_string(args['boot-node'])
    enable_dor = args['service'] == 'full' or args['service'] == 'storage'
    enable_rti = args['service'] == 'full' or args['service'] == 'execution'

    # check datastore path and create new directory if needed.
    if os.path.isfile(args['datastore']):
        raise Exception(f"Datastore path '{args['datastore']}' is pointing at a file.")

    elif not os.path.isdir(args['datastore']):
        subprocess.check_output(['mkdir', '-p', args['datastore']])

    node = Node.create(keystore, args['datastore'], p2p_address=p2p_service_address,
                       rest_address=rest_service_address,
                       enable_dor=enable_dor, enable_rti=enable_rti)

    return node


def add_cmd_dor(subparsers):
    dor_parser = subparsers.add_parser('dor', help='add/remove and search for data objects')

    dor_parser.add_argument('--keystore-id', dest='keystore-id', action='store',
                            help=f"id of the keystore to be used if there are more than one available "
                                 f"(default: id of the only keystore if only one is available )")
    dor_parser.add_argument('--password', dest='password', action='store',
                            help=f"password for the keystore")
    dor_parser.add_argument('--dor-address', dest='dor-address', action='store',
                            help=f"the address (host:port) of the DOR")

    dor_subparsers = dor_parser.add_subparsers(title='Available DOR commands',
                                               metavar='command', dest='command2', required=True)

    add_parser = dor_subparsers.add_parser('add', help='add a data object to the DOR')

    add_parser.add_argument('--data-type', dest='data-type', action='store',
                            help=f"the data type of the data object")
    add_parser.add_argument('--data-format', dest='data-format', action='store',
                            help=f"the data format of the data object")
    add_parser.add_argument('files', metavar='file', type=str, nargs='+',
                            help="the content of the data object (if more than one file is specified, the files will "
                                 "be archived into a single file with --format set to 'archive(tar.gz)')")

    remove_parser = dor_subparsers.add_parser('remove', help='removes a data object from the DOR')

    remove_parser.add_argument('obj-ids', metavar='obj-id', type=str, nargs='+',
                               help="the ids of the data object that are to be deleted")


def exec_cmd_dor(args):
    keystore = load_keystore(args)

    if args['command2'] == 'add':
        # check if files exist
        files = args['files']
        for file in files:
            if not os.path.isfile(file):
                print(f"No file found at '{file}'. Abort.")
                return -1

        # prepare plain data object file (if we have multiple files, they need to be archived)
        obj_path0 = os.path.join(args['temp-dir'], 'obj.plain')
        subprocess.check_output(['rm', '-f', obj_path0])
        if len(files) > 1:
            cmd = ['tar', 'czf', obj_path0]
            for file in files:
                cmd.append(file)
            subprocess.check_output(cmd)
            args['data-format'] = 'archive(tar.gz)'

        else:
            subprocess.check_output(['ln', '-s', files[0], obj_path0])

        # create key for this data object and encrypt data object in chunks
        obj_key = Fernet.generate_key()
        obj_path1 = os.path.join(args['temp-dir'], 'obj.protected')
        encrypt_file(obj_path0, obj_path1, obj_key)

        proxy = DORProxy(args['dor-address'].split(":"), keystore.identity)
        obj_id, descriptor = proxy.add_data_object(obj_path1, keystore.identity, args['data-type'], args['data-format'],
                                       keystore.content['identity']['name'])

        # add object key to key chain
        keystore.add_object_key(obj_id, obj_key)

        # clean up
        subprocess.check_output(['rm', '-f', obj_path0, obj_path1])

        print(f"Data object added: id={obj_id} descriptor={descriptor}")

        return obj_id

    elif args['command2'] == 'remove':
        proxy = DORProxy(args['dor-address'].split(":"), keystore.identity)
        result = {}
        for obj_id in args['obj-ids']:
            result[obj_id] = proxy.delete_data_object(obj_id, keystore.identity)

        print(f"Data object(s) removal result: {result}")

        return result


def parse_args(args):
    default_keystore = os.path.join(os.environ['HOME'], '.keystore')
    default_temp_dir = os.path.join(default_keystore)

    parser = argparse.ArgumentParser(description='SaaS Middleware command line interface (CLI)')
    parser.add_argument('--keystore', dest='keystore', action='store',
                        default=default_keystore,
                        help=f"path to the keystore (default: '{default_keystore}')")
    parser.add_argument('--temp-dir', dest='temp-dir', action='store',
                        default=default_temp_dir,
                        help=f"path to directory used for intermediate files (default: '{default_temp_dir}')")

    subparsers = parser.add_subparsers(title='Available commands', metavar='command', dest='command', required=True)

    add_cmd_initialise(subparsers)
    add_cmd_service(subparsers)
    add_cmd_dor(subparsers)

    try:
        args = vars(parser.parse_args(args))
        print(args)

        # execute the command...
        if args['command'] == 'init':
            return exec_cmd_initialise(args)

        elif args['command'] == 'service':
            node = exec_cmd_service(args)

            prompt("Press return to shutdown!")

            node.shutdown()
            return None

        elif args['command'] == 'dor':
            return exec_cmd_dor(args)

    except argparse.ArgumentError:
        parser.print_help()
        return None


if __name__ == "__main__":
    try:
        parse_args(sys.argv[1:])
        sys.exit(0)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        logger.error(trace)
        sys.exit(-1)

