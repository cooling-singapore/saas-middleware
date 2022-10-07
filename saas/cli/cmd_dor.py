import json
import os
import shutil
import subprocess

from InquirerPy.base import Choice
from pydantic import ValidationError
from tabulate import tabulate

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_if_missing, prompt_for_string, \
    prompt_for_keystore_selection, prompt_for_confirmation, prompt_for_selection, prompt_for_tags, load_keystore, \
    get_nodes_by_service, extract_address, prompt_for_identity_selection, prompt_for_data_objects, \
    deserialise_tag_value
from saas.core.helpers import encrypt_file
from saas.dor.proxy import DORProxy
from saas.core.identity import Identity
from saas.core.logging import Logging
from saas.nodedb.proxy import NodeDBProxy
from saas.dor.schemas import ProcessorDescriptor, DataObject
from saas.core.schemas import GithubCredentials
from saas.rest.exceptions import UnsuccessfulRequestError

logger = Logging.get('cli.dor')


def _require_dor(args: dict) -> DORProxy:
    prompt_if_missing(args, 'address', prompt_for_string,
                      message="Enter the node's REST address",
                      default='127.0.0.1:5001')

    db = NodeDBProxy(extract_address(args['address']))
    if db.get_node().dor_service is False:
        raise CLIRuntimeError(f"Node at {args['address'][0]}:{args['address'][1]} does "
                              f"not provide a DOR service. Aborting.")

    return DORProxy(extract_address(args['address']))


class DORAdd(CLICommand):
    def __init__(self) -> None:
        super().__init__('add', 'adds a data object', arguments=[
            Argument('--restrict-access', dest="restrict_access", action='store_const', const=True,
                     help=f"indicates that access to this data object should be restricted"),
            Argument('--encrypt-content', dest="content_encrypted", action='store_const', const=True,
                     help=f"indicates that the content of the data object should be encrypted"),
            Argument('--assume-creator', dest="assume_creator", action='store_const', const=True,
                     help=f"assumes that the user uploading the data object is also the creator"),
            Argument('--data-type', dest='data-type', action='store',
                     help=f"the data type of the data object"),
            Argument('--data-format', dest='data-format', action='store',
                     help=f"the data format of the data object"),
            Argument('file', metavar='file', type=str, nargs=1,
                     help="file containing the content of the data object")
        ])

    def execute(self, args: dict) -> None:
        _require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # get data type and format
        prompt_if_missing(args, 'data-type', prompt_for_string, message="Enter the data type of the data object:")
        prompt_if_missing(args, 'data-format', prompt_for_string, message="Enter the data format of the data object:")

        # check if the file exists
        if not os.path.isfile(args['file'][0]):
            raise CLIRuntimeError(f"No file found at '{args['file']}'. Aborting.")

        # set some access/content parameters
        restrict_access = args['restrict_access'] is True
        content_encrypted = args['content_encrypted'] is True
        content_key = None

        # should the data object be encrypted?
        obj_path = args['file'][0]
        if content_encrypted:
            # create key for this data object and encrypt data object in chunks
            obj_path_temp = os.path.join(args['temp-dir'], 'obj.protected')
            content_key = encrypt_file(obj_path, destination_path=obj_path_temp).decode('utf-8')
            obj_path = obj_path_temp

        # determine creators
        creators = [keystore.identity]
        if not args['assume_creator']:
            creators = prompt_for_identity_selection(
                address=extract_address(args['address']),
                message='Select all identities that are co-creators of this data object:',
                allow_multiple=True
            )

        # connect to the DOR and add the data object
        dor = DORProxy(extract_address(args['address']))
        meta = dor.add_data_object(obj_path, keystore.identity, restrict_access, content_encrypted,
                                   args['data-type'], args['data-format'], creators)
        obj_id = meta.obj_id

        # do some simple tagging
        dor.update_tags(obj_id, keystore, [
            DataObject.Tag(key='name', value=os.path.basename(args['file'][0]))
        ])

        # if we used encryption, store the content key
        if content_encrypted:
            keystore.content_keys.update(obj_id, content_key)
            print(f"Content key for object {obj_id} added to keystore.")

            os.remove(obj_path)

        print(f"Data object added: {json.dumps(meta.dict(), indent=4)}")


class DORAddGPP(CLICommand):
    def __init__(self) -> None:
        super().__init__('add-gpp', 'adds a Git Processor Pointer (GPP) data object', arguments=[
            Argument('--url', dest='url', action='store',
                     help=f"the URL where to find the git repository that contains the processor"),

            Argument('--commit-id', dest='commit-id', action='store',
                     help=f"the commit id to be used (default: most recent commit of the repository)"),

            Argument('--path', dest='path', action='store',
                     help=f"the relative path inside the repository where to find the processor"),

            Argument('--config', dest='config', action='store',
                     help=f"the configuration to be used for installing and executing the processor"),

            Argument('--name', dest='name', action='store',
                     help=f"the name of the processor"),
        ])

    def execute(self, args: dict) -> None:
        _require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # get the URL of the repo (if missing)
        prompt_if_missing(args, 'url', prompt_for_string, message="Enter the URL of the Github repository:")

        # is any of the other arguments missing?
        if not args['commit-id'] or not args['path'] or not args['config'] or not args['name']:
            if prompt_for_confirmation(f"Analyse repository at {args['url']} to help with missing arguments?",
                                       default=True):
                # delete existing directory (if it exists)
                repo_name = args['url'].split('/')[-1]
                repo_path = os.path.join(args['temp-dir'], repo_name)
                if os.path.exists(repo_path):
                    print(f"Deleting already existing path '{repo_path}'...", end='')
                    shutil.rmtree(os.path.join(args['temp-dir'], repo_name))
                    print(f"Done")

                # get the URL
                url = args['url']
                credentials: GithubCredentials = keystore.github_credentials.get(url)
                if credentials is not None:
                    insert = f"{credentials.login}:{credentials.personal_access_token}@"
                    index = url.find('github.com')
                    url = url[:index] + insert + url[index:]

                # clone the repository
                print(f"Cloning repository '{repo_name}' to '{repo_path}'...", end='')
                result = subprocess.run(['git', 'clone', url], capture_output=True, cwd=args['temp-dir'])
                if result.returncode != 0:
                    raise CLIRuntimeError(f"Cannot clone repository {url}.")
                print(f"Done")

                # do we have a commit it?
                if not args['commit-id']:
                    # obtain current commit id
                    print("Determining default commit id...", end='')
                    result = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, cwd=repo_path)
                    if result.returncode != 0:
                        raise CLIRuntimeError(f"Cannot determine default commit id.")
                    default_commit_id = result.stdout.decode('utf-8').strip()
                    print(f"Done: {default_commit_id}")

                    # which commit id to use?
                    prompt_if_missing(args, 'commit-id', prompt_for_string, message="Enter commit id:",
                                      default=default_commit_id)

                # checkout commit-id
                print(f"Checkout commit id {args['commit-id']}...", end='')
                result = subprocess.run(['git', 'checkout', args['commit-id']], capture_output=True, cwd=repo_path)
                if result.returncode != 0:
                    raise CLIRuntimeError(f"Invalid commit id {args['commit-id']}. Aborting.")
                print("Done")

                # do we have a processor path?
                if not args['path']:
                    # analyse all subdirectories to find 'descriptor.json' files
                    print(f"Searching for processor descriptors...", end='')
                    pending = [repo_path]
                    found = []
                    while len(pending) > 0:
                        current = pending.pop(0)
                        descriptor_path = os.path.join(current, 'descriptor.json')
                        if os.path.isfile(descriptor_path):
                            found.append({
                                'file-path': descriptor_path,
                                'proc-path': current[len(repo_path) + len(os.sep):]
                            })

                        for item in os.listdir(current):
                            if item.startswith('.'):
                                continue

                            path = os.path.join(current, item)
                            if os.path.isdir(path):
                                pending.append(path)

                    if len(found) == 0:
                        raise CLIRuntimeError("No descriptors found. Aborting.")

                    print(f"Done: found {len(found)} descriptors.")

                    # verify processor descriptors
                    choices = []
                    for item in found:
                        print(f"Analysing descriptor file '{item['file-path']}'...", end='')
                        try:
                            descriptor = ProcessorDescriptor.parse_file(item['file-path'])
                            choices.append(Choice(item['proc-path'], f"{descriptor.name} in {item['proc-path']}"))
                            print("Done")

                        except ValidationError:
                            print("Done: invalid processor descriptor -> ignoring")

                    # any valid processors found?
                    if len(choices) == 0:
                        raise CLIRuntimeError("No valid processor descriptors. Aborting.")

                    # select the processor path
                    args['path'] = prompt_for_selection(choices, f"Select a processor:", allow_multiple=False)

                # does the descriptor file exist?
                descriptor_path = os.path.join(repo_path, args['path'], 'descriptor.json')
                if not os.path.isfile(descriptor_path):
                    raise CLIRuntimeError("No processor descriptor found. Aborting.")

                # try to load the processor descriptor
                print(f"Load processor descriptor at '{args['path']}'...", end='')
                try:
                    descriptor = ProcessorDescriptor.parse_file(descriptor_path)
                    print("Done")

                except ValidationError:
                    raise CLIRuntimeError("Invalid processor descriptor. Aborting.")

                # do we have a configuration?
                if not args['config']:
                    choices = [Choice(c, c) for c in descriptor.configurations]
                    args['config'] = prompt_for_selection(choices, f"Select the configuration profile:")

                # do we have a name?
                if not args['name']:
                    args['name'] = descriptor.name

                # clean up
                shutil.rmtree(os.path.join(args['temp-dir'], repo_name))

            else:
                prompt_if_missing(args, 'commit-id', prompt_for_string,
                                  message="Enter the commit id:")
                prompt_if_missing(args, 'name', prompt_for_string,
                                  message="Enter the name of the processor:")
                prompt_if_missing(args, 'path', prompt_for_string,
                                  message="Enter the relative path of the processor in the repository:")
                prompt_if_missing(args, 'config', prompt_for_string,
                                  message="Enter the name of the configuration profile to be used:")

        # get Github credentials (if any)
        url = args['url']
        github_credentials: GithubCredentials = keystore.github_credentials.get(url)
        if github_credentials is not None:
            print(f"Using Github credentials for {url}: {github_credentials.login}")

        # connect to the DOR and add the data object
        dor = DORProxy(extract_address(args['address']))
        meta = dor.add_gpp_data_object(
            args['url'], args['commit-id'], args['path'], args['config'], keystore.identity,
            github_credentials=github_credentials
        )

        print(f"GPP Data object added: {json.dumps(meta.dict(), indent=4)}")


class DORDownload(CLICommand):
    def __init__(self):
        super().__init__('download', 'retrieves the contents of a data object', arguments=[
            Argument('obj-ids', metavar='obj-ids', type=str, nargs='*',
                     help="the ids of the data object that are to be downloaded"),
            Argument('destination', metavar='destination', type=str, nargs=1,
                     help="directory where to store the data object content")

        ])

    def execute(self, args: dict) -> None:
        # do we have a valid destination directory?
        if not args['destination']:
            raise CLIRuntimeError(f"No download path provided")
        elif not os.path.isdir(args['destination'][0]):
            raise CLIRuntimeError(f"Destination path provided is not a directory")

        dor = _require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have an object id?
        if not args['obj-ids']:
            # determine object ids for downloading
            args['obj-ids'] = prompt_for_data_objects(extract_address(args['address']),
                                                      message="Select data object to be downloaded:",
                                                      filter_by_owner=keystore.identity, allow_multiple=True)

            # get the meta information for the objects
            downloadable = [dor.get_meta(obj_id) for obj_id in args['obj-ids']]

        else:
            # check if the object ids exist/owned by this entity or if the entity has access
            result: list[DataObject] = dor.search(owner_iid=keystore.identity.id)
            result: dict[str, DataObject] = {obj.obj_id: obj for obj in result}
            downloadable = []
            for obj_id in args['obj-ids']:
                if obj_id not in result:
                    print(f"Ignoring data object '{obj_id}': does not exist or is not owned by "
                          f"'{keystore.identity.name}/{keystore.identity.email}/{keystore.identity.id}'")

                elif result[obj_id].access_restricted and keystore.identity.id not in result[obj_id].access:
                    print(f"Ignoring data object '{obj_id}': '{keystore.identity.name}/{keystore.identity.email}/"
                          f"{keystore.identity.id}' does not have access.")

                else:
                    downloadable.append(result[obj_id])

        # do we have removable data objects?
        if len(downloadable) == 0:
            raise CLIRuntimeError("No data objects available for download. Aborting.")

        # download the data objects
        dor = DORProxy(extract_address(args['address']))
        for obj in downloadable:
            download_path = os.path.join(args['destination'][0], f"{obj.obj_id}.{obj.data_format}")
            print(f"Downloading {obj.obj_id} to {download_path}...", end='')
            try:
                dor.get_content(obj.obj_id, keystore, download_path)
                print("Done")

            except UnsuccessfulRequestError as e:
                print(f"{e.reason} details: {e.details}")


class DORRemove(CLICommand):
    def __init__(self) -> None:
        super().__init__('remove', 'removes a data object', arguments=[
            Argument('obj-ids', metavar='obj-ids', type=str, nargs='*',
                     help="the ids of the data object that are to be deleted")
        ])

    def execute(self, args: dict) -> None:
        _require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have object ids?
        if len(args['obj-ids']) == 0:
            args['obj-ids'] = prompt_for_data_objects(extract_address(args['address']),
                                                      message="Select data objects to be removed:",
                                                      filter_by_owner=keystore.identity, allow_multiple=True)

        else:
            # check if the object ids exist/owned by this entity
            dor = DORProxy(extract_address(args['address']))
            result = dor.search(owner_iid=keystore.identity.id)
            result = {obj.obj_id: obj for obj in result}
            removable = []
            for obj_id in args['obj-ids']:
                if obj_id not in result:
                    print(f"Ignoring data object '{obj_id}': does not exist or is not owned by "
                          f"'{keystore.identity.name}/{keystore.identity.email}/{keystore.identity.id}'")
                else:
                    removable.append(obj_id)
            args['obj-ids'] = removable

        # do we have removable data objects?
        if len(args['obj-ids']) == 0:
            raise CLIRuntimeError("No removable data objects. Aborting.")

        # remove data objects
        dor = DORProxy(extract_address(args['address']))
        for obj_id in args['obj-ids']:
            print(f"Deleting {obj_id}...", end='')
            dor.delete_data_object(obj_id, keystore)
            print("Done")


class DORTag(CLICommand):
    def __init__(self) -> None:
        super().__init__('tag', 'add/update tags of a data object', arguments=[
            Argument('--obj-id', dest='obj-id', action='store',
                     help=f"the id of the data object"),

            Argument('tags', metavar='tags', type=str, nargs='*',
                     help="the tags (given as \'key=value\' pairs) to be used for the data object")
        ])

    def execute(self, args: dict) -> None:
        dor = _require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have an object id?
        if args['obj-id'] is None:
            args['obj-id'] = prompt_for_data_objects(extract_address(args['address']),
                                                     message="Select data objects for tagging:",
                                                     filter_by_owner=keystore.identity,
                                                     allow_multiple=True)
        else:
            args['obj-id'] = [args['obj-id']]

        # check if the object ids exist/owned by this entity
        result = dor.search(owner_iid=keystore.identity.id)
        result = [item.obj_id for item in result]
        found = []
        for obj_id in args['obj-id']:
            if obj_id not in result:
                print(f"Data object '{obj_id}' does not exist or is not owned by "
                      f"'{keystore.identity.name}/{keystore.identity.email}/{keystore.identity.id}'. Skipping.")
            else:
                found.append(obj_id)

        # do we have any data objects?
        if len(found) == 0:
            raise CLIRuntimeError("No data objects found. Aborting.")

        # do we have valid tags?
        if args['tags']:
            # check if the tags are valid
            valid_tags = []
            for tag in args['tags']:
                if tag.count('=') > 1:
                    print(f"Invalid tag '{tag}'. Ignoring.")
                elif tag.count('=') == 0:
                    valid_tags.append(DataObject.Tag(key=tag))
                else:
                    tag = tag.split("=")
                    valid_tags.append(deserialise_tag_value(DataObject.Tag(key=tag[0], value=tag[1])))

        else:
            valid_tags = prompt_for_tags("Enter a tag (key=value) or press return if done:")

        # do we have valid tags?
        if len(valid_tags) == 0:
            raise CLIRuntimeError("No valid tags found. Aborting.")

        # update the tags
        for obj_id in found:
            print(f"Updating tags for data object {obj_id}...", end='')
            dor.update_tags(obj_id, keystore, valid_tags)
            print("Done")


class DORUntag(CLICommand):
    def __init__(self) -> None:
        super().__init__('untag', 'removes tags from a data object', arguments=[
            Argument('--obj-id', dest='obj-id', action='store',
                     help=f"the id of the data object"),

            Argument('keys', metavar='keys', type=str, nargs='*',
                     help="the tags (identified by their key) to be removed from the data object")
        ])

    def execute(self, args: dict) -> None:
        dor = _require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have an object id?
        if args['obj-id'] is None:
            args['obj-id'] = prompt_for_data_objects(extract_address(args['address']),
                                                     message="Select data object for untagging:",
                                                     filter_by_owner=keystore.identity,
                                                     allow_multiple=False)

        else:
            # check if the object ids exist/owned by this entity
            result = dor.search(owner_iid=keystore.identity.id)
            result = {item.obj_id: item for item in result}
            if not args['obj-id'] in result:
                raise CLIRuntimeError(f"Data object '{args['obj-id']}' does not exist or is not owned by "
                                      f"'{keystore.identity.name}/{keystore.identity.email}/{keystore.identity.id}'. "
                                      f"Aborting.")

        # do we have tags?
        meta = dor.get_meta(args['obj-id'])
        if not args['keys']:
            choices = []
            for key, value in meta. tags.items():
                if value:
                    choices.append(
                        Choice(key, f"{key}: {value if isinstance(value, (str, bool, int, float)) else '...'}")
                    )
                else:
                    choices.append(Choice(key, key))

            args['keys'] = prompt_for_selection(choices, "Select tags to be removed:", allow_multiple=True)

        # check if the tags are valid
        valid_keys = []
        for key in args['keys']:
            if key not in meta.tags:
                print(f"Invalid key '{key}'. Ignoring.")
            else:
                valid_keys.append(key)

        # do we have valid tags?
        if len(valid_keys) == 0:
            raise CLIRuntimeError("No valid keys found. Aborting.")

        # update the tags
        print(f"Removing tags for data object {args['obj-id']}...", end='')
        dor.remove_tags(args['obj-id'], keystore, valid_keys)
        print("Done")


class DORSearch(CLICommand):
    def __init__(self) -> None:
        super().__init__('search', 'searches for data objects', arguments=[
            Argument('--own', dest="own", action='store_const', const=True,
                     help=f"limits the search to data objects owned by the identity used (refer to --keystore-id)"),

            Argument('--data-type', dest='data-type', action='store',
                     help=f"only search for data objects with this data type"),

            Argument('--data-format', dest='data-format', action='store',
                     help=f"only search for data objects with this data format"),

            Argument('pattern', metavar='pattern', type=str, nargs="*",
                     help="limits the search to data objects whose tag (key or value) contains the pattern(s)")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')

        # determine the owner iid to limit the search (if applicable)
        owner_iid = None
        if args['own'] is not None:
            prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection, path=args['keystore'],
                              message="Select the owner:")
            owner_iid = args['keystore-id']

        # get a list of nodes in the network
        dor_nodes, _ = get_nodes_by_service(extract_address(args['address']))
        for node in dor_nodes:
            # create proxies
            node_dor = DORProxy(node.rest_address)
            node_db = NodeDBProxy(node.rest_address)

            # perform the search
            result = node_dor.search(patterns=args['pattern'], data_type=args['data-type'],
                                     data_format=args['data-format'], owner_iid=owner_iid)

            # print search results
            if result:
                print(f"Found {len(result)} data objects at {node.identity.id}/"
                      f"{node.rest_address[0]}:{node.rest_address[1]} that match the criteria:")

                # headers
                lines = [
                    ['OBJECT ID', 'OWNER', 'DATA TYPE', 'DATA FORMAT', 'TAGS'],
                    ['---------', '-----', '---------', '-----------', '----']
                ]

                for item in result:
                    owner: Identity = node_db.get_identity(item.owner_iid)
                    tags = [
                        f"{key}: {value if isinstance(value, (str, bool, int, float)) else '...'}" if value else key
                        for key, value in item.tags.items()
                    ]

                    lines.append([
                        f"{item.obj_id[:4]}...{item.obj_id[-4:]}",
                        f"{owner.name}/{owner.id[:4]}...{owner.id[-4:]}",
                        item.data_type,
                        item.data_format,
                        tags
                    ])

                print(tabulate(lines, tablefmt="plain"))
                print()

            else:
                print(
                    f"No data objects found at {node.identity.id}/{node.rest_address[0]}:{node.rest_address[1]} "
                    f"that match the criteria.")


class DORAccessShow(CLICommand):
    def __init__(self) -> None:
        super().__init__('show', 'shows the identities who have been granted access to a data object', arguments=[
            Argument('--obj-id', dest='obj-id', action='store', required=False,
                     help=f"the id of the data object"),
        ])

    def execute(self, args: dict) -> None:
        dor = _require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # get all data objects by this user
        result = dor.search(owner_iid=keystore.identity.id)
        if not result:
            raise CLIRuntimeError(f"No data objects found. Aborting.")

        # do we have object id?
        if not args['obj-id']:
            choices = []
            for item in result:
                tags = []
                for key, value in item.tags.items():
                    if value:
                        tags.append(f"{key}={value if isinstance(value, (str, bool, int, float)) else '...'}")
                    else:
                        tags.append(key)
                choices.append(Choice(item.obj_id, f"{item.obj_id} [{item.data_type}:{item.data_format}] {tags}"))

            args['obj-id'] = prompt_for_selection(choices, "Select data object:", allow_multiple=False)

        # check if the object id exists
        result = {item.obj_id: item for item in result}
        if args['obj-id'] not in result:
            raise CLIRuntimeError(f"Data object '{args['obj-id']}' does not exist or is not owned by '"
                                  f"{keystore.identity.name}/"
                                  f"{keystore.identity.email}/"
                                  f"{keystore.identity.id}"
                                  f"'. Aborting.")

        # get the meta information
        meta = result[args['obj-id']]

        if not meta.access_restricted:
            print(f"Data object is not access restricted: everyone has access.")

        else:
            print(f"The following identities have been granted access:")
            db = NodeDBProxy(extract_address(args['address']))
            identities = [db.get_identity(iid) for iid in meta.access]
            # headers
            lines = [
                ['NAME', 'EMAIL', 'IDENTITY ID'],
                ['----', '-----', '-----------']
            ]

            # list
            lines += [
                [item.name, item.email, item.id] for item in identities
            ]

            print(tabulate(lines, tablefmt="plain"))


class DORAccessGrant(CLICommand):
    def __init__(self) -> None:
        super().__init__('grant', 'grants access to one or more data objects', arguments=[
            Argument('--iid', dest='iid', action='store',
                     help=f"the id of the identity who will be granted access"),

            Argument('obj-ids', metavar='obj-ids', type=str, nargs='*',
                     help="the ids of the data objects to which access will be granted")
        ])

    def execute(self, args: dict) -> None:
        dor = _require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have object ids?
        if len(args['obj-ids']) == 0:
            args['obj-ids'] = prompt_for_data_objects(extract_address(args['address']),
                                                      message="Select data objects:",
                                                      filter_by_owner=keystore.identity,
                                                      allow_multiple=True)

        else:
            # check if the object ids exist/owned by this entity
            removable = []
            for obj_id in args['obj-ids']:
                meta = dor.get_meta(obj_id)
                if not meta or meta.owner_iid != keystore.identity.id:
                    raise CLIRuntimeError(f"Ignoring data object '{obj_id}': does not exist or is not owned by '"
                                          f"{keystore.identity.name}/"
                                          f"{keystore.identity.email}/"
                                          f"{keystore.identity.id}"
                                          f"'")
                else:
                    removable.append(obj_id)
            args['obj-ids'] = removable

        # do we have data objects?
        if len(args['obj-ids']) == 0:
            raise CLIRuntimeError("No data objects. Aborting.")

        # get the identities known to the node
        db = NodeDBProxy(extract_address(args['address']))
        identities = db.get_identities()

        # do we have an identity?
        if not args['iid']:
            args['iid'] = prompt_for_selection([
                Choice(iid, f"{identity.name}/{identity.email}/{identity.id}") for iid, identity in identities.items()
            ], message="Select the identity who should be granted access:", allow_multiple=False)

        # is the identity known to the node?
        if args['iid'] not in identities:
            raise CLIRuntimeError(f"Target node does not know identity {args['iid']}. Aborting.")

        # grant access
        for obj_id in args['obj-ids']:
            print(f"Granting access to data object {obj_id} for identity {args['iid']}...", end='')
            meta = dor.grant_access(obj_id, keystore, identities[args['iid']])
            if args['iid'] not in meta.access:
                print(f"Failed")
            else:
                print(f"Done")


class DORAccessRevoke(CLICommand):
    def __init__(self) -> None:
        super().__init__('revoke', 'revokes access to a data object', arguments=[
            Argument('--obj-id', dest='obj-id', action='store',
                     help="the id of the data objects to which access will be revoked"),

            Argument('iids', metavar='iids', type=str, nargs='*',
                     help=f"the ids of the identities whose access will be revoked")
        ])

    def execute(self, args: dict) -> None:
        dor = _require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have object ids?
        if args['obj-id'] is None:
            args['obj-id'] = prompt_for_data_objects(extract_address(args['address']),
                                                     message="Select data object:",
                                                     filter_by_owner=keystore.identity,
                                                     allow_multiple=False)

            if args['obj-id'] is None:
                raise CLIRuntimeError(f"No data objects found. Aborting.")

        else:
            # check if the object id exists/owned by this entity
            meta = dor.get_meta(args['obj-id'])
            if not meta or meta.owner_iid != keystore.identity.id:
                raise CLIRuntimeError(f"Ignoring data object '{args['obj-id']}': does not exist or is not owned by '"
                                      f"{keystore.identity.name}/"
                                      f"{keystore.identity.email}/"
                                      f"{keystore.identity.id}"
                                      f"'")

        # do we have removable identities?
        db = NodeDBProxy(extract_address(args['address']))
        removable = args['iids'] if args['iids'] else dor.get_meta(args['obj-id']).access

        # collect the identity information of all those that have access
        choices = []
        identities = {}
        for iid in removable:
            identity = db.get_identity(iid)
            if identity:
                identities[identity.id] = identity
                choices.append(Choice(identity.id, f"{identity.name}/{identity.email}/{identity.id}"))
            else:
                print(f"No identity with id={iid}. Ignoring.")

        # do we have any choices?
        if not choices:
            raise CLIRuntimeError(f"No identities whose access could be revoked.")

        # select the identities to be removed
        args['iids'] = prompt_for_selection(
            choices, message="Select the identities whose access should be removed:", allow_multiple=True)

        # revoke access
        for iid in args['iids']:
            print(f"Revoking access to data object {args['obj-id']} for identity {iid}...", end='')
            meta = dor.revoke_access(args['obj-id'], keystore, identities[iid])
            if iid in meta.access:
                print(f"Failed")
            else:
                print(f"Done")
