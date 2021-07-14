#! /usr/bin/env python3
import json
import os
import argparse
import string
import sys
import traceback
import logging
import subprocess

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.helpers import encrypt_file
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.dor.blueprint import DORProxy
from saas.keystore.keystore import Keystore, Identity
from saas.node import Node
from saas.helpers import prompt, get_address_from_string, load_json_from_file
from saas.nodedb.blueprint import NodeDBProxy
from saas.rti.blueprint import RTIProxy

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('CLI_Keystore')


def initialise_storage_folder(path, usage):
    # check if the path is pointing at a file
    if os.path.isfile(path):
        raise Exception(f"Storage path '{path}' is a file. This path cannot be used as storage ({usage}) directory.")

    # check if it already exists as directory
    if not os.path.isdir(path):
        logger.info(f"creating storage ({usage}) directory '{path}'")
        subprocess.check_output(['mkdir', path])
        print(f"Storage directory ({usage}) created at '{path}'.")


def get_available_keystores(path):
    # determine the available keystores at the location
    result = []
    for f in os.listdir(path):
        # determine the iid
        temp = f.split(".")
        keystore_id = temp[0]

        # add if the master/keystores files exist
        if Keystore.is_valid(path, keystore_id) and keystore_id not in result:
            result.append(keystore_id)

    return result


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
        # determine the available keystores at the location. do we have any?
        available = get_available_keystores(path)
        if len(available) == 0:
            return None

        # prompt if there is more than one keystore
        selected = 0
        if len(available) > 1:
            valid = []
            print(f"Multiple keystores found at location '{path}':")
            for i in range(len(available)):
                valid.append(str(i))
                print(f"[{i}] {available[i]}")

            selected = int(prompt("Select keystore: ", valid))

        args['keystore-id'] = available[selected]

    if 'password' not in args or args['password'] is None:
        args['password'] = prompt(f"Enter password:", hidden=True)

    # load existing keystore
    keystore = Keystore.load(path, args['keystore-id'], args['password'])

    if keystore is None:
        print("Loading keystore failed!")

    else:
        identity = keystore.identity()
        print(f"Keystore loaded!")
        print(f"- Identity: {identity.name()}/{identity.email()}/{identity.id()}")
        print(f"- Signing Key: {keystore.signing_key().info()}")
        print(f"- Encryption Key: {keystore.encryption_key().info()}")
        print(f"- Object Keys: {keystore.object_keys()}")

    return keystore


def add_cmd_identity(subparsers):
    identity_parser = subparsers.add_parser('identity', help='create, remove and list identities')

    subparsers = identity_parser.add_subparsers(title='Available commands',
                                                metavar='command', dest='command2', required=True)

    create_parser = subparsers.add_parser('create', help='creates a new identity')
    create_parser.add_argument('--name', dest='name', action='store',
                               help=f"name of the identity")
    create_parser.add_argument('--email', dest='email', action='store',
                               help=f"email of the identity")

    remove_parser = subparsers.add_parser('remove', help='removes an existing identity')
    remove_parser.add_argument('--confirm', dest="confirm", action='store_const', const=True,
                               help=f"do not require user confirmation to delete keystore")

    subparsers.add_parser('list', help='lists all identities found in the keystore directory')

    discover_parser = subparsers.add_parser('discover', help='retrieves a list of all identities known to a node')
    discover_parser.add_argument('--address', dest='address', action='store',
                                 help=f"the address (host:port) of the node")


def exec_cmd_identity(args):
    initialise_storage_folder(args['keystore'], 'keystore')

    if args['command2'] == 'create':
        if args['name'] is None:
            args['name'] = prompt(f"Enter name:")

        if args['email'] is None:
            args['email'] = prompt(f"Enter email address:")

        while args['password'] is None:
            pwd1 = prompt(f"Enter password:", hidden=True)
            pwd2 = prompt(f"Re-enter password:", hidden=True)
            if pwd1 == pwd2:
                args['password'] = pwd1
            else:
                print("Password do not match! Try again.")

        keystore = Keystore.create(args['keystore'], args['name'], args['email'], args['password'])
        identity = keystore.identity()

        print(f"New keystore created!")
        print(f"- Identity: {identity.name()}/{identity.email()}/{identity.id()}")
        print(f"- Signing Key: {keystore.signing_key().info()}")
        print(f"- Encryption Key: {keystore.encryption_key().info()}")
        print(f"- Object Keys: {keystore.object_keys()}")
        return identity.id()

    elif args['command2'] == 'remove':
        # get the keystore
        keystore = load_keystore(args)
        if keystore is not None:
            identity = keystore.identity()

            if args['confirm'] or prompt("Delete keystore?", valid_answers=['y', 'n']) == 'y':
                if Keystore.delete(args['keystore'], identity.id()):
                    print(f"Keystore deleted!")

                else:
                    print(f"Keystore could not be deleted!")

        return None

    elif args['command2'] == 'list':
        available = get_available_keystores(args['keystore'])
        if len(available) > 0:
            print(f"Found {len(available)} keystores in '{args['keystore']}':")
            for i in range(len(available)):
                print(f"[{i}] {available[i]}")
        else:
            print(f"No keystores found in '{args['keystore']}':")

        return None

    elif args['command2'] == 'discover':
        proxy = NodeDBProxy(args['address'].split(":"))
        identities = proxy.get_identities()
        if len(identities) > 0:
            print("Identities known by node:")
            for iid in identities:
                identity = Identity.deserialise(identities[iid])
                print(f"- {identity.id()}: {identity.name()}, {identity.email()}")
        else:
            print("No identities found.")

        return identities


def add_cmd_service(subparsers):
    # define the default values
    default_datastore = os.path.join(os.environ['HOME'], '.datastore')
    default_host = '127.0.0.1'
    default_rest_port = 5001
    default_p2p_port = 4001
    default_service = 'full'

    # create the parser(s)
    parser = subparsers.add_parser('service', help='start a node as service provider')
    parser.add_argument('--datastore', dest='datastore', action='store',
                        default=default_datastore,
                        help=f"path to the datastore (default: '{default_datastore}')")
    parser.add_argument('--host', dest='host', action='store',
                        default=default_host,
                        help=f"host to be used by the services (default: '{default_host}').")
    parser.add_argument('--rest-port', dest='rest-port', action='store',
                        default=default_rest_port,
                        help=f"port to be used by the service REST API endpoints (default: {default_rest_port}).")
    parser.add_argument('--p2p-port', dest='p2p-port', action='store',
                        default=default_p2p_port,
                        help=f"port to be used by the node P2P interface (default: {default_p2p_port}).")
    parser.add_argument('--boot-node', dest='boot-node', action='store',
                        default=f"{default_host}:{default_p2p_port}",
                        help=f"URL (address:p2p-port) of a existing node for joining a network "
                             f"(default: '{default_host}:{default_p2p_port}').")
    parser.add_argument('--type', dest='type', action='store',
                        choices=['full', 'storage', 'execution'],
                        default=default_service,
                        help=f"indicate the type of service provided by the node: 'storage' and 'execution' "
                             f"will only load the DOR or RTI modules, respectively; a 'full' node will provide "
                             f"both (default: '{default_service}').")


def exec_cmd_service(args, keystore):
    rest_service_address = (args['host'], args['rest-port'])
    p2p_service_address = (args['host'], args['p2p-port'])
    boot_node_address = get_address_from_string(args['boot-node'])
    enable_dor = args['type'] == 'full' or args['type'] == 'storage'
    enable_rti = args['type'] == 'full' or args['type'] == 'execution'

    # initialise storage directory (if necessary)
    initialise_storage_folder(args['datastore'], 'datastore')

    # create a node instance
    node = Node.create(keystore, args['datastore'],
                       p2p_address=p2p_service_address,
                       boot_node_address=boot_node_address,
                       rest_address=rest_service_address,
                       enable_dor=enable_dor,
                       enable_rti=enable_rti)

    print(f"Created '{args['type']}' node instance at {args['host']}:{args['rest-port']}/{args['p2p-port']}")
    return node


def add_cmd_dor(subparsers):
    # create the parser(s)
    parser = subparsers.add_parser('dor', help='interact with a node\'s Data Object Repository (DOR)')
    parser.add_argument('--address', dest='address', action='store',
                        help=f"the address (host:port) of the node")

    subparsers = parser.add_subparsers(title='Available commands',
                                       metavar='command', dest='command2', required=True)

    add_parser = subparsers.add_parser('add', help='adds a data object')

    add_parser.add_argument('--restrict-access', dest="restrict_access", action='store_const', const=True,
                            help=f"indicates that access to this data object requires permission by the data owner")
    add_parser.add_argument('--encrypt-content', dest="content_encrypted", action='store_const', const=True,
                            help=f"indicates that the content of the data object should be encrypted")
    add_parser.add_argument('--data-type', dest='data-type', action='store',
                            help=f"the data type of the data object")
    add_parser.add_argument('--data-format', dest='data-format', action='store',
                            help=f"the data format of the data object")
    add_parser.add_argument('files', metavar='files', type=str, nargs='+',
                            help="the content of the data object (if more than one file is specified, the files will "
                                 "be archived into a single file with --format set to 'archive(tar.gz)')")

    remove_parser = subparsers.add_parser('remove', help='removes a data object')

    remove_parser.add_argument('obj-ids', metavar='obj-ids', type=str, nargs='+',
                               help="the ids of the data object that are to be deleted")

    tag_parser = subparsers.add_parser('tag', help='adds tags to a data object')

    tag_parser.add_argument('--obj-id', dest='obj-id', action='store',
                            help=f"the id of the data object")

    tag_parser.add_argument('key-value-pairs', metavar='key-value-pairs', type=str, nargs='+',
                            help="the tags (given as \'key=value\' pairs) to be used for the data object")

    untag_parser = subparsers.add_parser('untag', help='removes tags (identified by their keys) from a data object')

    untag_parser.add_argument('--obj-id', dest='obj-id', action='store',
                              help=f"the id of the data object")

    untag_parser.add_argument('keys', metavar='keys', type=str, nargs='+',
                              help="the tags (identified by their keys) to be removed from the data object")

    search_parser = subparsers.add_parser('search', help='searches for data objects')

    search_parser.add_argument('--own', dest="own", action='store_const', const=True,
                               help=f"limits the search to data objects owned by the identity used (refer to "
                                    f"--keystore-id)")

    search_parser.add_argument('patterns', metavar='patterns', type=str, nargs='+',
                               help="limits the search to data objects whose tag (key or value) contains any "
                                    "of the patterns")

    grant_parser = subparsers.add_parser('grant', help='grants access to one or more data objects')

    grant_parser.add_argument('--iid', dest='iid', action='store',
                              help=f"the id of the identity who will be granted access to the data objects")

    grant_parser.add_argument('obj-ids', metavar='obj-id', type=str, nargs='+',
                              help="the ids of the data objects to which access will be granted")

    revoke_parser = subparsers.add_parser('revoke', help='revokes access to one or more data objects')

    revoke_parser.add_argument('--iid', dest='iid', action='store',
                               help=f"the id of the identity whose access will be revoked from the data objects")

    revoke_parser.add_argument('obj-ids', metavar='obj-id', type=str, nargs='+',
                               help="the ids of the data objects to which access will be revoked")


def exec_cmd_dor(args, keystore):
    proxy = DORProxy(args['address'].split(":"))
    db_proxy = NodeDBProxy(args['address'].split(":"))

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

        # set some access/content parameters
        restrict_access = args['restrict_access'] is True
        content_encrypted = args['content_encrypted'] is True
        content_key = None
        protected_content_key = None

        # should the data object be encrypted?
        obj_path1 = obj_path0
        if content_encrypted:
            # create key for this data object and encrypt data object in chunks
            obj_path1 = os.path.join(args['temp-dir'], 'obj.protected')
            content_key = encrypt_file(obj_path0, destination=obj_path1)

            # encrypt the content key
            protected_content_key = keystore.encryption_key().encrypt(content_key, base64_encoded=True).decode('utf-8')

        # connect to the DOR and add the data object
        obj_id, descriptor = proxy.add_data_object(obj_path1, keystore.identity(),
                                                   restrict_access, content_encrypted, protected_content_key,
                                                   args['data-type'], args['data-format'], keystore.identity().name())

        # if we used encryption, store the content key
        if content_encrypted:
            keystore.add_object_key(obj_id, content_key)

        # clean up
        subprocess.check_output(['rm', '-f', obj_path0, obj_path1])

        print(f"Data object added: id={obj_id} descriptor={descriptor}")
        return obj_id

    elif args['command2'] == 'remove':
        result = {}
        for obj_id in args['obj-ids']:
            result[obj_id] = proxy.delete_data_object(obj_id, keystore.signing_key())

        print(f"Data object(s) removal result: {result}")
        return result

    elif args['command2'] == 'tag':
        tags = {}
        for pair in args['key-value-pairs']:
            temp = pair.split("=")
            tags[temp[0]] = temp[1]

        tags = proxy.update_tags(args['obj-id'], keystore.signing_key(), tags)
        print(f"All tags of data object {args['obj-id']}:")
        for key, value in tags.items():
            print(f"- {key} : {value}")

        return tags

    elif args['command2'] == 'untag':
        tags = proxy.remove_tags(args['obj-id'], keystore.signing_key(), args['keys'])
        print(f"All tags of data object {args['obj-id']}:")
        for key, value in tags.items():
            print(f"- {key} : {value}")

        return tags

    elif args['command2'] == 'search':
        if args['own']:
            result = proxy.search(args['patterns'], owner_iid=keystore.identity().id())
        else:
            result = proxy.search(args['patterns'])

        print(f"All data objects that match the criteria:")
        for obj_id in result:
            print(f"- {obj_id}:")
            tags = proxy.get_tags(obj_id)
            for key, value in tags.items():
                print(f"\t{key} : {value}")

        return result

    elif args['command2'] == 'grant':
        # is the identity known to the node?
        record = db_proxy.get_identity(args['iid'])
        if record is None:
            print(f"Identity '{args['iid']}' is not known to the node. Cannot proceed.")
            return None

        # grant access to the data objects
        identity = Identity.deserialise(record)
        result = []
        for obj_id in args['obj-ids']:
            r = proxy.grant_access(obj_id, keystore.signing_key(), identity)
            if r[obj_id] == identity.id():
                result.append(obj_id)

        # print results
        print(f"Access granted to '{identity.id()}':")
        for obj_id in result:
            print(f"- {obj_id}")

        return result

    elif args['command2'] == 'revoke':
        # is the identity known to the node?
        record = db_proxy.get_identity(args['iid'])
        if record is None:
            print(f"Identity '{args['iid']}' is not known to the node. Cannot proceed.")
            return None

        # grant access to the data objects
        identity = Identity.deserialise(record)
        result = []
        for obj_id in args['obj-ids']:
            r = proxy.revoke_access(obj_id, keystore.signing_key(), identity)
            if r[obj_id] == identity.id():
                result.append(obj_id)

        # print results
        print(f"Access revoked from '{identity.id()}':")
        for obj_id in result:
            print(f"- {obj_id}")

        return result


def add_cmd_rti(subparsers):
    # create the parser(s)
    parser = subparsers.add_parser('rti', help='interact with a node\'s Runtime Infrastructure (RTI)')
    parser.add_argument('--address', dest='address', action='store',
                        help=f"the address (host:port) of the node")

    subparsers = parser.add_subparsers(title='Available commands',
                                       metavar='command', dest='command2', required=True)

    deploy_parser = subparsers.add_parser('deploy', help='deploys a processor to the node')

    deploy_parser.add_argument('--proc-id', dest='proc-id', action='store',
                               help=f"the id of the processor to be deployed to the node")

    undeploy_parser = subparsers.add_parser('undeploy', help='undeploys a processor from the node')

    undeploy_parser.add_argument('--proc-id', dest='proc-id', action='store',
                                 help=f"the id of the processor to be undeployed from the node")

    descriptor_parser = subparsers.add_parser('descriptor', help='retrieves the descriptor of a deployed processor')

    descriptor_parser.add_argument('--proc-id', dest='proc-id', action='store',
                                   help=f"the id of the processor")

    submit_parser = subparsers.add_parser('submit', help='submits a job')

    submit_parser.add_argument('--proc-id', dest='proc-id', action='store',
                               help=f"the id of the processor")

    submit_parser.add_argument('--job', dest='job', action='store',
                               help=f"path to the job descriptor")

    submit_parser.add_argument('item', metavar='item', type=str, nargs='+',
                               help="specification of input items (by-reference format: 'input-name:object-id' or "
                                    "by-value format: 'input-name:path-to-file') and output items (format: "
                                    "'output-name:owner-iid:restrict-access:encrypt-content', where restrict-access "
                                    "and encrypt-content are boolean ('true' or 'false')")

    status_parser = subparsers.add_parser('status', help='retrieves the status of a job')

    status_parser.add_argument('--job-id', dest='job-id', action='store',
                               help=f"the id of the job")


def exec_cmd_rti(args, keystore):
    proxy = RTIProxy(args['address'].split(":"))
    db_proxy = NodeDBProxy(args['address'].split(":"))

    if args['command2'] == 'deploy':
        descriptor = proxy.deploy(args['proc-id'])
        if descriptor is not None:
            print(f"Processor (id={args['proc-id']}) successfully deployed: \n{descriptor}")

        else:
            print(f"Could not deploy processor. Make sure processor (id={args['proc-id']}) is available in domain.")

        return descriptor

    elif args['command2'] == 'undeploy':
        proc_id = proxy.deploy(args['proc-id'])
        if proc_id is not None:
            print(f"Processor (id={args['proc-id']}) successfully undeployed.")

        else:
            print(f"Could not undeploy processor. Was the processor deployed in the first place?")

        return proc_id

    elif args['command2'] == 'descriptor':
        descriptor = proxy.get_descriptor(args['proc-id'])
        if descriptor is not None:
            print(f"Descriptor of processor (id={args['proc-id']}):\n{descriptor}")

        else:
            print(f"Processor (id={args['proc-id']}) not deployed.")

        return descriptor

    elif args['command2'] == 'submit':
        # get the processor descriptor
        descriptor = proxy.get_descriptor(args['proc-id'])
        if descriptor is None:
            print(f"Could not retrieve descriptor of processor (id='{args['proc-id']}'). Not deployed? Aborting.")
            return None

        # get the RTI node info:
        node_info = db_proxy.get_node()

        # determine pending items for the input interface
        pending_input = []
        for item in descriptor['input']:
            pending_input.append(item['name'])

        # determine pending items for the output interface
        pending_output = []
        for item in descriptor['output']:
            pending_output.append(item['name'])

        # process the items
        allowed = set(string.ascii_lowercase + string.digits)
        job_input = []
        job_output = []
        for item in args['item']:
            temp = item.split(":")

            # input item
            if len(temp) == 2:
                # is it a path?
                if os.path.isfile(temp[1]):
                    value = load_json_from_file(temp[1])
                    if value is not None:
                        job_input.append({
                            'name': temp[0],
                            'type': 'value',
                            'value': value
                        })
                        print(f"Adding by-value input item: {item}")
                        if temp[0] in pending_input:
                            pending_input.remove(temp[0])

                    else:
                        print(f"Cannot load contents of '{temp[1]}'. Not a valid json file? Aborting.")
                        return None

                # is it an object id?
                elif len(temp[1]) == 64 and set(temp[1]) <= allowed:
                    # create signature for access token
                    access_token = f"{node_info['iid']}:{temp[1]}"
                    signature = keystore.signing_key().sign(access_token.encode('utf-8'))

                    # add the job input item
                    job_input.append({
                        'name': temp[0],
                        'type': 'reference',
                        'obj_id': temp[1],
                        'user_signature': signature
                    })
                    print(f"Adding by-reference input item: {item}")
                    if temp[0] in pending_input:
                        pending_input.remove(temp[0])

                else:
                    print(f"Invalid input item (either not a object id or file does not exist): {item}. Aborting.")
                    return None

            # output item
            elif len(temp) == 4:
                # check owner iid
                if len(temp[1]) != 64 or set(temp[1]) > allowed:
                    print(f"Invalid owner iid: {item}. Aborting.")
                    return None

                # check restrict access
                if not (temp[2] == 'true' or temp[2] == 'false'):
                    print(f"Invalid value for 'restrict-access': {item}. Aborting.")
                    return None

                # check encrypt content
                if not (temp[3] == 'true' or temp[3] == 'false'):
                    print(f"Invalid value for 'encrypt-content': {item}. Aborting.")
                    return None

                job_output.append({
                    'name': temp[0],
                    'owner_iid': temp[1],
                    'restricted_access': temp[2] == 'true',
                    'content_encrypted': temp[2] == 'true'
                })
                print(f"Adding output item: {item}")
                if temp[0] in pending_output:
                    pending_output.remove(temp[0])

            else:
                print(f"Invalid item (neither input nor output): {item}. Aborting.")
                return None

        # check if the input and output matches the process interface
        if len(pending_input) > 0 or len(pending_output) > 0:
            print(f"Missing items for input {pending_input} or output {pending_output}. Aborting.")
            return None

        job_id = proxy.submit_job(args['proc-id'], job_input, job_output, keystore.identity())
        return job_id

    elif args['command2'] == 'status':
        _, status = proxy.get_job_info(args['job-id'])
        if status is not None:
            print(f"Status for job '{args['job-id']}:\n{status}'")
            return status

        else:
            print(f"No status found for job '{args['job-id']}'.")
            return None


def add_cmd_request(subparsers):
    # create the parser(s)
    parser = subparsers.add_parser('handle', help='handles an encrypted request')

    parser.add_argument('--confirm', dest="confirm", action='store_const', const=True,
                        help=f"do not require user confirmation to process with request")

    parser.add_argument('request', metavar='request', type=str, nargs=1, help="the encrypted request")


def exec_cmd_request(args, keystore):
    request = args['request'][0]

    # we should be able to decrypt it
    request = keystore.encryption_key().decrypt(request.encode('utf-8'), base64_encoded=True).decode('utf-8')
    request = json.loads(request)
    if 'type' in request and request['type'] == 'request_content_key':
        print(f"Request for content key:\n"
              f"- Object Id: {request['obj_id']}\n"
              f"- Requesting User: {request['user_name']} <{request['user_email']}>\n"
              f"- RTI Address: {request['node_address']}")

        # get the content key
        content_key = keystore.get_object_key(request['obj_id'])
        if content_key is None:
            print(f"No content key found for obj_id={request['obj_id']}. Aborting.")
            return False

        # get the ephemeral key and encrypt the content key with the ephemeral key
        key = RSAKeyPair.from_public_key_string(request['ephemeral_public_key'])
        content_key = key.encrypt(content_key, base64_encoded=True).decode('utf-8')

        # ask for confirmation
        if args['confirm'] or prompt("Please review the above request and confirm whether to proceed", ['y', 'n']) == 'y':
            # submit the content key
            proxy = RTIProxy(request['node_address'])
            proxy.put_permission(request['req_id'], content_key)
            return True

        else:
            print(f"Aborting.")
            return False

    else:
        print(f"Malformed request or unsupported request type: {request}")
        return False


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

    parser.add_argument('--keystore-id', dest='keystore-id', action='store',
                        help=f"id of the keystore to be used if there are more than one available "
                             f"(default: id of the only keystore if only one is available )")
    parser.add_argument('--password', dest='password', action='store',
                        help=f"password for the keystore")

    subparsers = parser.add_subparsers(title='Available commands', metavar='command', dest='command', required=True)

    add_cmd_identity(subparsers)
    add_cmd_service(subparsers)
    add_cmd_dor(subparsers)
    add_cmd_rti(subparsers)
    add_cmd_request(subparsers)

    try:
        args = vars(parser.parse_args(args))
        print(args)

        # execute the command...
        if args['command'] == 'identity':
            return exec_cmd_identity(args)

        # load a keystore
        keystore = load_keystore(args)
        if keystore is not None:
            # execute the command...
            if args['command'] == 'service':
                node = exec_cmd_service(args, keystore)

                prompt("Press return to shutdown!")

                node.shutdown()
                return None

            elif args['command'] == 'dor':
                return exec_cmd_dor(args, keystore)

            elif args['command'] == 'rti':
                return exec_cmd_rti(args, keystore)

            elif args['command'] == 'handle':
                return exec_cmd_request(args, keystore)

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

