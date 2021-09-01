import logging
import os
import subprocess

import jsonschema
from tabulate import tabulate

from cli.helpers import CLICommand, Argument, prompt_if_missing, prompt_for_string, prompt_for_keystore_selection, \
    prompt_for_password, unlock_keystore, prompt_for_confirmation, \
    prompt_for_selection, prompt_for_data_object_selection, prompt_for_tags
from saas.cryptography.helpers import encrypt_file
from saas.dor.blueprint import DORProxy
from saas.helpers import read_json_from_file
from saas.keystore.assets.contentkeys import ContentKeysAsset
from saas.keystore.assets.credentials import CredentialsAsset, GithubCredentials
from saas.nodedb.blueprint import NodeDBProxy
from saas.schemas import processor_descriptor_schema

logger = logging.getLogger('cli.dor')


class DORAdd(CLICommand):
    def __init__(self):
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
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                          path=args['keystore'],
                          message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            prompt_if_missing(args, 'address', prompt_for_string,
                              message="Enter the target node's REST address",
                              default='127.0.0.1:5001')
            prompt_if_missing(args, 'data-type', prompt_for_string,
                              message="Enter the data type of the data object:")
            prompt_if_missing(args, 'data-format', prompt_for_string,
                              message="Enter the data format of the data object:")

            # check if the file exists
            if not os.path.isfile(args['file'][0]):
                print(f"No file found at '{args['file']}'. Abort.")
                return None

            # set some access/content parameters
            restrict_access = args['restrict_access'] is True
            content_encrypted = args['content_encrypted'] is True
            content_key = None

            # should the data object be encrypted?
            obj_path = args['file'][0]
            if content_encrypted:
                # create key for this data object and encrypt data object in chunks
                obj_path_temp = os.path.join(args['temp-dir'], 'obj.protected')
                content_key = encrypt_file(obj_path, destination=obj_path_temp).decode('utf-8')
                obj_path = obj_path_temp

            # connect to the DOR and add the data object
            dor = DORProxy(args['address'].split(':'))
            obj_id, descriptor = dor.add_data_object(obj_path, keystore.identity,
                                                     restrict_access, content_encrypted,
                                                     args['data-type'], args['data-format'],
                                                     keystore.identity.name)

            # do some simple tagging
            dor.update_tags(obj_id, keystore, {
                'name': os.path.basename(args['file'][0]),
                'data-type': args['data-type'],
                'data-format': args['data-format']
            })

            # if we used encryption, store the content key
            if content_encrypted:
                asset: ContentKeysAsset = keystore.get_asset('content-keys')
                asset.update(obj_id, content_key)

                subprocess.run(['rm', '-f', obj_path])

            print(f"Data object added: id={obj_id} descriptor={descriptor}")

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class DORAddProc(CLICommand):
    def __init__(self):
        super().__init__('add-proc', 'adds a Processor Git Pointer data object', arguments=[
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
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')
        prompt_if_missing(args, 'url', prompt_for_string, message="Enter the URL of the Github repository:")
        # default_if_missing(args, 'url', 'https://github.com/cooling-singapore/saas-processor-template')

        # is any of the other arguments missing?
        if not args['commit-id'] or not args['path'] or not args['config'] or not args['name']:
            if prompt_for_confirmation(f"Analyse repository at {args['url']} to help with missing arguments?",
                                       default=True):
                # delete existing directory (if it exists)
                repo_name = args['url'].split('/')[-1]
                repo_path = os.path.join(args['temp-dir'], repo_name)
                if os.path.exists(repo_path):
                    print(f"Deleting already existing path '{repo_path}'...", end='')
                    subprocess.run(['rm', '-rf', repo_name], cwd=args['temp-dir'])
                    print(f"Done")

                # clone the repository
                print(f"Cloning repository '{repo_name}' to '{repo_path}'...", end='')
                result = subprocess.run(['git', 'clone', args['url']], capture_output=True, cwd=args['temp-dir'])
                if result.returncode != 0:
                    print(f"Failed: {result}")
                    return None
                else:
                    print(f"Done")

                # do we have a commit it?
                if not args['commit-id']:
                    # obtain current commit id
                    print("Determining default commit id...", end='')
                    result = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, cwd=repo_path)
                    if result.returncode != 0:
                        print(f"Failed: {result}")
                        return None
                    else:
                        default_commmit_id = result.stdout.decode('utf-8').strip()
                        print(f"Done: {default_commmit_id}")

                    # which commit id to use?
                    prompt_if_missing(args, 'commit-id', prompt_for_string,
                                      message="Enter commit id:",
                                      default=default_commmit_id)

                # checkout commit-id
                print(f"Checkout commit id {args['commit-id']}...", end='')
                result = subprocess.run(['git', 'checkout', args['commit-id']], capture_output=True, cwd=repo_path)
                if result.returncode != 0:
                    print(f"Failed: invalid commit id '{args['commit-id']}' -> aborting.")
                    return None
                else:
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
                        print("Done: no descriptors found -> aborting.")
                        return None

                    else:
                        print(f"Done: found {len(found)} descriptors.")

                    # verify processor descriptors
                    descriptors = []
                    for item in found:
                        print(f"Analysing descriptor file '{item['file-path']}'...", end='')
                        try:
                            descriptor = read_json_from_file(item['file-path'], schema=processor_descriptor_schema)
                            # proc_path = item['proc-path'][len(repo_path) + len(os.sep):]
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
                        print("No valid processor descriptors -> aborting.")
                        return None

                    # select the processor
                    selection = prompt_for_selection(descriptors, f"Select a processor:")
                    args['path'] = selection['proc-path']

                # does the descriptor file exist? load it
                print(args)
                descriptor_path = os.path.join(repo_path, args['path'], 'descriptor.json')
                print(f"Load processor descriptor at '{args['path']}'...", end='')
                if not os.path.isfile(descriptor_path):
                    print("Failed: no processor descriptor found at location -> aborting")
                    return None
                else:
                    try:
                        descriptor = read_json_from_file(descriptor_path, schema=processor_descriptor_schema)
                        print("Done")

                    except jsonschema.exceptions.ValidationError:
                        print("Failed: invalid processor descriptor -> aborting.")
                        return None

                # do we have a configuration?
                if not args['config']:
                    profiles = [{'label': c, 'config': c} for c in descriptor['configurations']]
                    selection = prompt_for_selection(profiles, f"Select the configuration profile:")
                    args['config'] = selection['config']

                # do we have a name?
                if not args['name']:
                    args['name'] = descriptor['name']

                # clean up
                subprocess.run(['rm', '-rf', repo_name], cwd=args['temp-dir'])

            else:
                prompt_if_missing(args, 'commit-id', prompt_for_string,
                                  message="Enter the commit id:")
                prompt_if_missing(args, 'name', prompt_for_string,
                                  message="Enter the name of the processor:")
                prompt_if_missing(args, 'path', prompt_for_string,
                                  message="Enter the relative path of the processor in the repository:")
                prompt_if_missing(args, 'config', prompt_for_string,
                                  message="Enter the name of the configuration profile to be used:")

        # get keystore and upload data object
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                          path=args['keystore'],
                          message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)
        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            # do we have git credentials for this repository
            asset: CredentialsAsset = keystore.get_asset('github-credentials')
            credentials: GithubCredentials = asset.get(args['url']) if asset else None

            # connect to the DOR and add the data object
            dor = DORProxy(args['address'].split(':'))
            obj_id, descriptor = dor.add_gpp_data_object(
                args['url'], args['commit-id'], args['path'], args['config'],
                keystore.identity, keystore.identity.name, git_credentials=credentials
            )

            # set some tags
            dor.update_tags(obj_id, keystore, {
                'name': args['name'],
                'repository': args['url'],
                'commit-id': args['commit-id'],
                'path': args['path'],
                'config': args['config'],
                'data-type': 'Git-Processor-Pointer',
                'data-format': 'json'
            })

            print(f"GPP Data object added: id={obj_id} descriptor={descriptor}")

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class DORRemove(CLICommand):
    def __init__(self):
        super().__init__('remove', 'removes a data object', arguments=[
            Argument('obj-ids', metavar='obj-ids', type=str, nargs='*',
                     help="the ids of the data object that are to be deleted")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                          path=args['keystore'],
                          message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            # do we have object ids?
            if len(args['obj-ids']) == 0:
                args['obj-ids'] = prompt_for_data_object_selection(args['address'],
                                                                   keystore.identity,
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
                print("No removable data objects. Aborting.")
                return None

            # remove data objects
            dor = DORProxy(args['address'].split(':'))
            for obj_id in args['obj-ids']:
                print(f"Deleting {obj_id}...", end='')
                dor.delete_data_object(obj_id, keystore)
                print("Done")

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class DORTag(CLICommand):
    def __init__(self):
        super().__init__('tag', 'add/update tags of a data object', arguments=[
            Argument('--obj-id', dest='obj-id', action='store',
                     help=f"the id of the data object"),

            Argument('tags', metavar='tags', type=str, nargs='*',
                     help="the tags (given as \'key=value\' pairs) to be used for the data object")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                          path=args['keystore'],
                          message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            dor = DORProxy(args['address'].split(':'))

            # do we have an object id?
            if args['obj-id'] is None:
                args['obj-id'] = prompt_for_data_object_selection(args['address'],
                                                                  keystore.identity, "Select data object for tagging:")

            else:
                # check if the object ids exist/owned by this entity
                result = dor.search(owner_iid=keystore.identity.id)
                if not args['obj-id'] in result:
                    print(f"Data object '{args['obj-id']}' does not exist or is not owned by "
                          f"'{keystore.identity.name}/{keystore.identity.email}/{keystore.identity.id}'. Aborting.")
                    return None

            # do we have tags?
            if len(args['tags']) == 0:
                args['tags'] = prompt_for_tags("Enter a tag (key=value) or press return if done:")

            # check if the tags are valid
            valid_tags = {}
            for tag in args['tags']:
                if tag.count('=') > 1:
                    print(f"Invalid tag '{tag}' -> ignoring.")
                else:
                    tag = tag.split("=")
                    if len(tag) == 1:
                        tag.append('')
                    valid_tags[tag[0]] = tag[1]

            # do we have valid tags?
            if len(valid_tags) == 0:
                print("No valid tags found. Aborting.")
                return None

            # update the tags
            tags = dor.update_tags(args['obj-id'], keystore, valid_tags)
            print(f"Updated tags of data object {args['obj-id']}: tags={tags}")

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class DORUntag(CLICommand):
    def __init__(self):
        super().__init__('untag', 'removes tags from a data object', arguments=[
            Argument('--obj-id', dest='obj-id', action='store',
                     help=f"the id of the data object"),

            Argument('keys', metavar='keys', type=str, nargs='*',
                     help="the tags (identified by their key) to be removed from the data object")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                          path=args['keystore'],
                          message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            dor = DORProxy(args['address'].split(':'))

            # do we have an object id?
            if args['obj-id'] is None:
                args['obj-id'] = prompt_for_data_object_selection(args['address'],
                                                                  keystore.identity,
                                                                  "Select data object for untagging:")

            else:
                # check if the object ids exist/owned by this entity
                result = dor.search(owner_iid=keystore.identity.id)
                if not args['obj-id'] in result:
                    print(f"Data object '{args['obj-id']}' does not exist or is not owned by "
                          f"'{keystore.identity.name}/{keystore.identity.email}/{keystore.identity.id}'. Aborting.")
                    return None

            # do we have tags?
            tags = dor.get_tags(args['obj-id'])
            if len(args['keys']) == 0:
                choices = []
                for key, value in tags.items():
                    choices.append({
                        'label': f"{key} : {value}",
                        'key': key
                    })

                for item in prompt_for_selection(choices, "Select tags to be removed:", allow_multiple=True):
                    args['keys'].append(item['key'])

            # check if the tags are valid
            valid_keys = []
            for key in args['keys']:
                if key not in tags:
                    print(f"Invalid key '{key}' -> ignoring.")
                else:
                    valid_keys.append(key)

            # do we have valid tags?
            if len(valid_keys) == 0:
                print("No valid keys found. Aborting.")
                return None

            # update the tags
            tags = dor.remove_tags(args['obj-id'], keystore, valid_keys)
            print(f"Removed tags from data object {args['obj-id']}: remaining tags={tags}")

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class DORSearch(CLICommand):
    def __init__(self):
        super().__init__('search', 'searches for data objects', arguments=[
            Argument('--own', dest="own", action='store_const', const=True,
                     help=f"limits the search to data objects owned by the identity used (refer to --keystore-id)"),

            Argument('pattern', metavar='pattern', type=str, nargs="*",
                     help="limits the search to data objects whose tag (key or value) contains the pattern(s)")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')

        dor = DORProxy(args['address'].split(':'))
        db = NodeDBProxy(args['address'].split(':'))

        # determine the owner iid to limit the search (if applicable)
        owner_iid = None
        if args['own']:
            prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                              path=args['keystore'],
                              message="Select the keystore:")
            prompt_if_missing(args, 'password', prompt_for_password, confirm=False)
            keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
            if keystore is not None:
                owner_iid = keystore.identity.id

            else:
                print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")
                return None

        # perform the search
        result = dor.search(patterns=args['pattern'], owner_iid=owner_iid)

        # do we have any results?
        if len(result) == 0:
            print(f"No data objects found that match the criteria.")
            return None

        # display what we have found
        print(f"Found {len(result)} data objects that match the criteria:")
        for obj_id, tags in result.items():
            owner_iid = dor.get_owner(obj_id)['owner_iid']
            owner = db.get_identity(owner_iid)
            print(f"[{obj_id}]\n   Owner: {owner.name}/{owner.email}/{owner.id}\n   Tags: ")
            for tag in tags:
                tag = tag.split('=')
                print(f"      {tag[0]}: {tag[1]}")


class DORAccessShow(CLICommand):
    def __init__(self):
        super().__init__('show', 'shows the identities who have been granted access to a data object', arguments=[
            Argument('--obj-id', dest='obj-id', action='store', required=False,
                     help=f"the id of the data object"),
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')

        dor = DORProxy(args['address'].split(':'))
        db = NodeDBProxy(args['address'].split(":"))

        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                          path=args['keystore'],
                          message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)
        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            # do we have object ids?
            if not args['obj-id']:
                obj_id = prompt_for_data_object_selection(args['address'],
                                                          keystore.identity,
                                                          "Select data object:",
                                                          allow_multiple=False)
                if obj_id is None:
                    print(f"No data objects found. Aborting.")
                    return None

                args['obj-id'] = obj_id

            else:
                # check if the object ids exist/owned by this entity
                result = dor.search(owner_iid=keystore.identity.id)
                if args['obj-id'] not in result:
                    print(f"Data object '{args['obj-id']}' does not exist or is not owned by "
                          f"'{keystore.identity.name}/{keystore.identity.email}/{keystore.identity.id}'. Aborting.")
                    return None

            # get the identities known to the node
            identities = db.get_identities()

            # get the identities that have access
            access = dor.get_access_overview(args['obj-id'])
            if len(access) == 0:
                print(f"No access granted to any identity.")

            else:
                print(f"Access granted to {len(access)} identities:")

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

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class DORAccessGrant(CLICommand):
    def __init__(self):
        super().__init__('grant', 'grants access to one or more data objects', arguments=[
            Argument('--iid', dest='iid', action='store',
                     help=f"the id of the identity who will be granted access"),

            Argument('obj-ids', metavar='obj-ids', type=str, nargs='*',
                     help="the ids of the data objects to which access will be granted")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                          path=args['keystore'],
                          message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        dor = DORProxy(args['address'].split(':'))
        db = NodeDBProxy(args['address'].split(":"))

        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            # do we have object ids?
            if len(args['obj-ids']) == 0:
                args['obj-ids'] = prompt_for_data_object_selection(args['address'],
                                                                   keystore.identity,
                                                                   "Select data objects:",
                                                                   allow_multiple=True)

            else:
                # check if the object ids exist/owned by this entity
                result = dor.search(owner_iid=keystore.identity.id)
                removable = []
                for obj_id in args['obj-ids']:
                    if obj_id not in result:
                        print(f"Ignoring data object '{obj_id}': does not exist or is not owned by "
                              f"'{keystore.identity.name}/{keystore.identity.email}/{keystore.identity.id}'")
                    else:
                        removable.append(obj_id)
                args['obj-ids'] = removable

            # do we have data objects?
            if len(args['obj-ids']) == 0:
                print("No data objects. Aborting.")
                return None

            # get the identities known to the node
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
                print(f"Target node does not know identity {args['iid']}. Aborting.")
                return None

            # grant access
            for obj_id in args['obj-ids']:
                print(f"Granting access to data object {obj_id} for identity {args['iid']}...", end='')
                result = dor.grant_access(obj_id, keystore, identities[args['iid']])
                if obj_id not in result or result[obj_id] != args['iid']:
                    print(f"Failed")
                else:
                    print(f"Done")

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")


class DORAccessRevoke(CLICommand):
    def __init__(self):
        super().__init__('revoke', 'revokes access to a data object', arguments=[
            Argument('--obj-id', dest='obj-id', action='store',
                     help="the id of the data objects to which access will be revoked"),

            Argument('iids', metavar='iids', type=str, nargs='*',
                     help=f"the ids of the identities whose access will be revoked")
        ])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')
        prompt_if_missing(args, 'keystore-id', prompt_for_keystore_selection,
                          path=args['keystore'],
                          message="Select the keystore:")
        prompt_if_missing(args, 'password', prompt_for_password, confirm=False)

        dor = DORProxy(args['address'].split(':'))
        db = NodeDBProxy(args['address'].split(":"))

        keystore = unlock_keystore(args['keystore'], args['keystore-id'], args['password'])
        if keystore is not None:
            # do we have object ids?
            if args['obj-id'] is None:
                obj_id = prompt_for_data_object_selection(args['address'],
                                                          keystore.identity,
                                                          "Select data object:",
                                                          allow_multiple=False)
                if obj_id is None:
                    print(f"No data objects found. Aborting.")
                    return None

                args['obj-id'] = obj_id

            else:
                # check if the object ids exist/owned by this entity
                result = dor.search(owner_iid=keystore.identity.id)
                for obj_id in args['obj-id']:
                    if obj_id not in result:
                        print(f"Data object {obj_id} does not exist or is not owned by "
                              f"'{keystore.identity.name}/{keystore.identity.email}/{keystore.identity.id}'")

            # get the identities known to the node
            identities = db.get_identities()

            # do we have an identity?
            if not args['iids']:
                # get the identities that have currently access
                choices = []
                access = dor.get_access_overview(args['obj-id'])
                for iid in access:
                    identity = identities[iid]
                    choices.append({
                        'label': f"{identity.name}/{identity.email}/{identity.id}",
                        'iid': iid
                    })

                for selected in prompt_for_selection(choices,
                                                     "Select the identities whose access should be removed:",
                                                     allow_multiple=True):
                    args['iids'].append(selected['iid'])

            # revoke access
            for iid in args['iids']:
                print(f"Revoking access to data object {args['obj-id']} for identity {iid}...", end='')
                result = dor.revoke_access(args['obj-id'], keystore, identities[iid])
                if args['obj-id'] not in result or result[args['obj-id']] != iid:
                    print(f"Failed")
                else:
                    print(f"Done")

        else:
            print(f"Could not open keystore. Incorrect password? Keystore corrupted? Aborting.")
