import json
import os
import shutil
import subprocess

import jsonschema
from tabulate import tabulate

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_if_missing, prompt_for_string, prompt_for_keystore_selection, \
    prompt_for_confirmation, prompt_for_selection, prompt_for_data_object_selection, prompt_for_tags, load_keystore, \
    get_nodes_by_service
from saas.cryptography.helpers import encrypt_file
from saas.dor.blueprint import DORProxy
from saas.helpers import read_json_from_file, validate_json
from saas.keystore.assets.contentkeys import ContentKeysAsset
from saas.keystore.assets.credentials import CredentialsAsset, GithubCredentials
from saas.keystore.schemas import SerializedKeystore as KeystoreSchema
from saas.logging import Logging
from saas.nodedb.blueprint import NodeDBProxy
from saas.schemas import ProcessorDescriptor

logger = Logging.get('cli.dor')


def require_dor(args: dict) -> DORProxy:
    prompt_if_missing(args, 'address', prompt_for_string,
                      message="Enter the node's REST address",
                      default='127.0.0.1:5001')

    db = NodeDBProxy(args['address'].split(":"))
    info = db.get_node()
    if info['dor_service'] is False:
        raise CLIRuntimeError(f"Node at {args['address']} does not have a DOR service. Aborting.")

    return DORProxy(args['address'].split(':'))


class DORAdd(CLICommand):
    def __init__(self) -> None:
        super().__init__('add', 'adds a data object', arguments=[
            Argument('--restrict-access', dest="restrict_access", action='store_const', const=True,
                     help=f"indicates that access to this data object should be restricted"),
            Argument('--encrypt-content', dest="content_encrypted", action='store_const', const=True,
                     help=f"indicates that the content of the data object should be encrypted"),
            Argument('--data-type', dest='data-type', action='store',
                     help=f"the data type of the data object"),
            Argument('--data-format', dest='data-format', action='store',
                     help=f"the data format of the data object"),
            Argument('file', metavar='file', type=str, nargs=1,
                     help="file containing the content of the data object")
        ])

    def execute(self, args: dict) -> None:
        require_dor(args)
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

        # connect to the DOR and add the data object
        dor = DORProxy(args['address'].split(':'))
        meta = dor.add_data_object(obj_path, keystore.identity, restrict_access, content_encrypted,
                                   args['data-type'], args['data-format'], keystore.identity.name)
        obj_id = meta['obj_id']

        # do some simple tagging
        dor.update_tags(obj_id, keystore, {
            'name': os.path.basename(args['file'][0])
        })

        # if we used encryption, store the content key
        if content_encrypted:
            asset: ContentKeysAsset = keystore.get_asset('content-keys')
            asset.update(obj_id, content_key)
            print(f"Content key for object {obj_id} added to keystore.")

            os.remove(obj_path)

        print(f"Data object added: {json.dumps(meta, indent=4)}")


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
        require_dor(args)
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
                asset: CredentialsAsset = keystore.get_asset('github-credentials')
                credentials: GithubCredentials = asset.get(url) if asset else None
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
                    # analyse all sub directories to find 'descriptor.json' files
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
                    descriptors = []
                    for item in found:
                        print(f"Analysing descriptor file '{item['file-path']}'...", end='')
                        try:
                            descriptor = read_json_from_file(item['file-path'], schema=ProcessorDescriptor.schema())
                            descriptors.append({
                                'descriptor': descriptor,
                                'proc-path': item['proc-path'],
                                'label': f"{descriptor['name']} in {item['proc-path']}"
                            })
                            print("Done")

                        except jsonschema.exceptions.ValidationError:
                            print("Done: invalid processor descriptor -> ignoring")

                    # any valid processors found?
                    if len(descriptors) == 0:
                        raise CLIRuntimeError("No valid processor descriptors. Aborting.")

                    # select the processor
                    selection = prompt_for_selection(descriptors, f"Select a processor:")
                    args['path'] = selection['proc-path']

                # does the descriptor file exist? load it
                descriptor_path = os.path.join(repo_path, args['path'], 'descriptor.json')
                print(f"Load processor descriptor at '{args['path']}'...", end='')
                if not os.path.isfile(descriptor_path):
                    raise CLIRuntimeError("No processor descriptor found. Aborting.")

                try:
                    descriptor = read_json_from_file(descriptor_path, schema=ProcessorDescriptor.schema())
                    print("Done")

                except jsonschema.exceptions.ValidationError:
                    raise CLIRuntimeError("Invalid processor descriptor. Aborting.")

                # do we have a configuration?
                if not args['config']:
                    profiles = [{'label': c, 'config': c} for c in descriptor['configurations']]
                    selection = prompt_for_selection(profiles, f"Select the configuration profile:")
                    args['config'] = selection['config']

                # do we have a name?
                if not args['name']:
                    args['name'] = descriptor['name']

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
        asset: CredentialsAsset = keystore.get_asset('github-credentials')
        github_credentials: GithubCredentials = asset.get(url) if asset else None
        if github_credentials is not None:
            print(f"Using Github credentials for {url}: {github_credentials.login}")

        # connect to the DOR and add the data object
        dor = DORProxy(args['address'].split(':'))
        meta = dor.add_gpp_data_object(
            args['url'], args['commit-id'], args['path'], args['config'],
            keystore.identity, keystore.identity.name,
            github_credentials=github_credentials
        )
        obj_id = meta['obj_id']

        # set some tags
        dor.update_tags(obj_id, keystore, {
            'name': args['name'],
            'repository': args['url'],
            'commit-id': args['commit-id'],
            'path': args['path'],
            'config': args['config']
        })

        print(f"GPP Data object added: {json.dumps(meta, indent=4)}")


class DORRemove(CLICommand):
    def __init__(self) -> None:
        super().__init__('remove', 'removes a data object', arguments=[
            Argument('obj-ids', metavar='obj-ids', type=str, nargs='*',
                     help="the ids of the data object that are to be deleted")
        ])

    def execute(self, args: dict) -> None:
        require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have object ids?
        if len(args['obj-ids']) == 0:
            args['obj-ids'] = prompt_for_data_object_selection(args['address'], keystore.identity,
                                                               "Select data objects to be removed:",
                                                               allow_multiple=True)

        else:
            # check if the object ids exist/owned by this entity
            dor = DORProxy(args['address'].split(':'))
            result = dor.search(owner_iid=keystore.identity.id)
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
        dor = DORProxy(args['address'].split(':'))
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
        dor = require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have an object id?
        if args['obj-id'] is None:
            args['obj-id'] = prompt_for_data_object_selection(args['address'], keystore.identity,
                                                              "Select data objects for tagging:",
                                                              allow_multiple=True)
        else:
            args['obj-id'] = [args['obj-id']]

        # check if the object ids exist/owned by this entity
        result = dor.search(owner_iid=keystore.identity.id)
        result = [item['obj_id'] for item in result]
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

        # do we have tags?
        if len(args['tags']) == 0:
            args['tags'] = prompt_for_tags("Enter a tag (key=value) or press return if done:")

        # check if the tags are valid
        valid_tags = {}
        for tag in args['tags']:
            if tag.count('=') > 1:
                print(f"Invalid tag '{tag}'. Ignoring.")
            else:
                tag = tag.split("=")
                if len(tag) == 1:
                    tag.append('')
                valid_tags[tag[0]] = tag[1]

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
        dor = require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have an object id?
        if args['obj-id'] is None:
            args['obj-id'] = prompt_for_data_object_selection(args['address'], keystore.identity,
                                                              "Select data object for untagging:")

        else:
            # check if the object ids exist/owned by this entity
            result = dor.search(owner_iid=keystore.identity.id)
            if not args['obj-id'] in result:
                raise CLIRuntimeError(f"Data object '{args['obj-id']}' does not exist or is not owned by "
                                      f"'{keystore.identity.name}/{keystore.identity.email}/{keystore.identity.id}'. "
                                      f"Aborting.")

        # do we have tags?
        meta = dor.get_meta(args['obj-id'])
        if len(args['keys']) == 0:
            choices = []
            for tag in meta['tags']:
                choices.append({
                    'label': f"{tag['key']} : {tag['value']}",
                    'key': tag['key']
                })

            for item in prompt_for_selection(choices, "Select tags to be removed:", allow_multiple=True):
                args['keys'].append(item['key'])

        # check if the tags are valid
        valid_keys = []
        tags = [tag['key'] for tag in meta['tags']]
        for key in args['keys']:
            if key not in tags:
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

            # read the keystore content (we only need the public part)
            keystore_path = os.path.join(args['keystore'], f"{args['keystore-id']}.json")
            keystore_content = read_json_from_file(keystore_path)
            if not validate_json(keystore_content, KeystoreSchema.schema()):
                raise CLIRuntimeError(f"Invalid keystore. Aborting.")

            owner_iid = keystore_content['iid']

        # get a list of nodes in the network
        search_result = []
        nodes = get_nodes_by_service(args['address'].split(':'))
        for node in nodes['dor'].values():
            # create proxies
            node_dor = DORProxy(node['rest_address'].split(':'))
            node_db = NodeDBProxy(node['rest_address'].split(':'))

            # perform the search
            result = node_dor.search(patterns=args['pattern'], data_type=args['data-type'],
                                     data_format=args['data-format'], owner_iid=owner_iid)
            items = []
            for item in result:
                meta = node_dor.get_meta(item['obj_id'])
                owner_iid = meta['owner_iid']
                owner = node_db.get_identity(owner_iid)

                # add an item
                items.append({
                    'obj_id': item['obj_id'],
                    'data_type': item['data_type'],
                    'data_format': item['data_format'],
                    'owner': owner,
                    'tags': item['tags']
                })

            search_result.append({
                'node': node,
                'objects': items
            })

        # do we have any search results?
        if len(search_result) == 0:
            raise CLIRuntimeError(f"No data objects found that match the criteria.")

        # print search results
        print(f"Found the following data objects that match the criteria:")
        for item in search_result:
            count = len(item['objects'])
            if count == 0:
                continue

            for obj in item['objects']:
                print()
                print(f"{obj['obj_id']} [{obj['data_type']}/{obj['data_format']}]")
                print(f"  - HOST: {item['node']['iid']}/{item['node']['rest_address']}/{item['node']['p2p_address']}")
                print(f"  - OWNER: {obj['owner'].name}/{obj['owner'].email}/{obj['owner'].id}")
                print(f"  - TAGS:")
                for tag in obj['tags']:
                    print(f"      {tag['key']}: {tag['value']}")


class DORAccessShow(CLICommand):
    def __init__(self) -> None:
        super().__init__('show', 'shows the identities who have been granted access to a data object', arguments=[
            Argument('--obj-id', dest='obj-id', action='store', required=False,
                     help=f"the id of the data object"),
        ])

    def execute(self, args: dict) -> None:
        dor = require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have object ids?
        if not args['obj-id']:
            obj_id = prompt_for_data_object_selection(args['address'], keystore.identity, "Select data object:",
                                                      allow_multiple=False)
            if obj_id is None:
                raise CLIRuntimeError(f"No data objects found. Aborting.")

            args['obj-id'] = obj_id

        else:
            # check if the object ids exist/owned by this entity
            result = dor.search(owner_iid=keystore.identity.id)
            result = [item['obj_id'] for item in result]
            if args['obj-id'] not in result:
                raise CLIRuntimeError(f"Data object '{args['obj-id']}' does not exist or is not owned by '"
                                      f"{keystore.identity.name}/"
                                      f"{keystore.identity.email}/"
                                      f"{keystore.identity.id}"
                                      f"'. Aborting.")

        # get the ids of the identities that have access and resolve them
        meta = dor.get_meta(args['obj-id'])
        db = NodeDBProxy(args['address'].split(":"))
        identities = db.get_identities()
        identities = [identities[iid] for iid in meta['access']]

        if len(identities) == 0:
            raise CLIRuntimeError(f"No access granted to any identity. Aborting.")

        print(f"Access granted to {len(identities)} identities:")

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
        dor = require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have object ids?
        if len(args['obj-ids']) == 0:
            args['obj-ids'] = prompt_for_data_object_selection(args['address'], keystore.identity,
                                                               "Select data objects:", allow_multiple=True)

        else:
            # check if the object ids exist/owned by this entity
            result = dor.search(owner_iid=keystore.identity.id)
            removable = []
            for obj_id in args['obj-ids']:
                if obj_id not in result:
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
        db = NodeDBProxy(args['address'].split(":"))
        identities = db.get_identities()

        # do we have an identity?
        if not args['iid']:
            items = [{'label': f"{identity.name}/{identity.email}/{identity.id}", 'iid': iid}
                     for iid, identity in identities.items()]

            selected = prompt_for_selection(items,
                                            "Select the identity who should be granted access:",
                                            allow_multiple=False)
            args['iid'] = selected['iid']

        # is the identity known to the node?
        if args['iid'] not in identities:
            raise CLIRuntimeError(f"Target node does not know identity {args['iid']}. Aborting.")

        # grant access
        for obj_id in args['obj-ids']:
            print(f"Granting access to data object {obj_id} for identity {args['iid']}...", end='')
            meta = dor.grant_access(obj_id, keystore, identities[args['iid']])
            if args['iid'] not in meta['access']:
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
        dor = require_dor(args)
        keystore = load_keystore(args, ensure_publication=True)

        # do we have object ids?
        if args['obj-id'] is None:
            obj_id = prompt_for_data_object_selection(args['address'], keystore.identity, "Select data object:",
                                                      allow_multiple=False)
            if obj_id is None:
                raise CLIRuntimeError(f"No data objects found. Aborting.")

            args['obj-id'] = obj_id

        else:
            # check if the object ids exist/owned by this entity
            result = dor.search(owner_iid=keystore.identity.id)
            result = [item['obj_id'] for item in result]
            for obj_id in args['obj-id']:
                if obj_id not in result:
                    raise CLIRuntimeError(f"Data object {obj_id} does not exist or is not owned by '"
                                          f"{keystore.identity.name}/"
                                          f"{keystore.identity.email}/"
                                          f"{keystore.identity.id}"
                                          f"'")

        # get the identities known to the node
        db = NodeDBProxy(args['address'].split(":"))
        identities = db.get_identities()

        # do we have an identity?
        if not args['iids']:
            # get the identities that have currently access
            choices = []
            meta = dor.get_meta(args['obj-id'])
            access = meta['access']
            for iid in access:
                identity = identities[iid]
                choices.append({
                    'label': f"{identity.name}/{identity.email}/{identity.id}",
                    'iid': iid
                })

            for selected in prompt_for_selection(choices, "Select the identities whose access should be removed:",
                                                 allow_multiple=True):
                args['iids'].append(selected['iid'])

        # revoke access
        for iid in args['iids']:
            print(f"Revoking access to data object {args['obj-id']} for identity {iid}...", end='')
            meta = dor.revoke_access(args['obj-id'], keystore, identities[iid])
            if iid in meta['access']:
                print(f"Failed")
            else:
                print(f"Done")
