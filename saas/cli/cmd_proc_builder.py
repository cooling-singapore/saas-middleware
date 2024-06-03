import json
import os
import shutil
import tempfile
from typing import Optional, Tuple

import docker
from git import Repo, NoSuchPathError, GitCommandError

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_for_string, prompt_if_missing, load_keystore, \
    default_if_missing
from saas.dor.schemas import ProcessorDescriptor, DataObject, GitProcessorPointer
from saas.helpers import docker_export_image
from saas.sdk.base import connect


def clone_repository(repository_url: str, repository_path: str, commit_id: str = None,
                     credentials: Optional[Tuple[str, str]] = None) -> int:
    # do we have credentials? inject it into the repo URL
    if credentials:
        idx = repository_url.index('github.com')
        url0 = repository_url[:idx]
        url1 = repository_url[idx:]
        repository_url = f"{url0}{credentials[0]}:{credentials[1]}@{url1}"

    # does the destination already exist?
    shutil.rmtree(repository_path, ignore_errors=True)

    try:
        # clone the repo
        Repo.clone_from(repository_url, repository_path)
        repo = Repo(repository_path)

        # checkout a specific commit
        repo.git.checkout(commit_id)

        # determine the commit timestamp
        commit = repo.commit(commit_id)
        commit_timestamp = commit.authored_datetime.timestamp()

        return int(commit_timestamp)

    except NoSuchPathError as e:
        raise CLIRuntimeError(reason=str(e))

    except GitCommandError as e:
        raise CLIRuntimeError(reason=str(e))

    except Exception as e:
        raise CLIRuntimeError(reason=f"Unexpected: {e}")


def build_processor_image(repository_path: str, processor_path: str,
                          force_build: bool = False, use_cache: bool = True) -> Tuple[str, ProcessorDescriptor, bool]:
    # does the path exist?
    processor_path = os.path.join(repository_path, processor_path)
    if not os.path.isdir(processor_path):
        raise CLIRuntimeError(f"Processor path not found at {processor_path}")

    # see if required files do exist
    missing = []
    for required in ['descriptor.json', 'processor.py', 'Dockerfile']:
        path = os.path.join(processor_path, required)
        if not os.path.isfile(path):
            missing.append(required)

    # anything missing?
    if missing:
        raise CLIRuntimeError(f"Processor folder missing files: {missing}")

    # does the descriptor file exist?
    descriptor_path = os.path.join(processor_path, 'descriptor.json')
    if not os.path.isfile(descriptor_path):
        raise CLIRuntimeError(f"Processor descriptor not found at {descriptor_path}")

    # read the descriptor
    with open(descriptor_path, 'r') as f:
        try:
            descriptor = ProcessorDescriptor.parse_obj(json.load(f))
        except Exception as e:
            raise CLIRuntimeError(f"Cannot read processor descriptor at {descriptor_path}: {e}")

    # determine the image name
    repo = Repo(repository_path)
    username, repo_name = repo.remotes.origin.url.split("/")[-2:]
    repo_name = repo_name.rstrip(".git")
    commit_id = repo.head.commit.hexsha
    image_name = f"{username}/{repo_name}/{descriptor.name}:{commit_id}"

    # check if the image already exists
    client = docker.from_env()
    image_existed = False
    try:
        # get a list of all images and check if it has the name.
        for image in client.images.list():
            if image_name in image.tags:
                # if we are forced to build a new image, delete the existing one first
                if force_build:
                    client.images.remove(image.id, force=True)

                image_existed = True
                break

    except Exception as e:
        raise CLIRuntimeError("Deleting existing docker image failed.", details={
            'exception': e
        })

    # build the processor docker image
    if force_build or not image_existed:
        try:
            image, _ = client.images.build(path=processor_path, tag=image_name, nocache=not use_cache, rm=True)

        except Exception as e:
            raise CLIRuntimeError("Creating docker image failed.", details={
                'exception': e
            })

    return image_name, descriptor, image_existed


class ProcBuilder(CLICommand):
    default_store_image = False
    default_force_build = False
    default_use_cache = True
    default_keep_image = True

    def __init__(self):
        super().__init__('build', 'build a processor', arguments=[
            Argument('--repository', dest='repository', action='store', help="URL of the repository"),
            Argument('--commit-id', dest='commit_id', action='store', help="the commit id"),
            Argument('--proc-path', dest='proc_path', action='store', help="path to the processor"),
            Argument('--git-username', dest='git_username', action='store', help="GitHub username"),
            Argument('--git-token', dest='git_token', action='store', help="GitHub personal access token"),
            Argument('--store-image', dest="store_image", action='store_const', const=True,
                     help="Store the image in the DOR not just a reference."),
            Argument('--force-build', dest="force_build", action='store_const', const=True,
                     help="Force building a processor docker image even if one already exists."),
            Argument('--no-build-cache', dest="use_build_cache", action='store_const', const=False,
                     help="Don't use cache when building the processor docker image."),
            Argument('--delete-image', dest="keep_image", action='store_const', const=False,
                     help="Deletes the newly created image after exporting it - note: if an image with the same "
                          "name already existed, this flag will be ignored, effectively resulting in the existing "
                          "image being replaced with the newly created one.")
        ])

    def execute(self, args: dict) -> Optional[dict]:
        # load keystore
        keystore = load_keystore(args, ensure_publication=True)

        # connect to network
        context = connect(args['address'], keystore)
        if not context.has_dor_node():
            raise CLIRuntimeError("No DOR-enabled node found.")

        prompt_if_missing(args, 'repository', prompt_for_string, message="Enter URL of the repository:")
        prompt_if_missing(args, 'commit_id', prompt_for_string, message="Enter the commit id:")
        prompt_if_missing(args, 'proc_path', prompt_for_string, message="Enter path to the processor:")
        default_if_missing(args, 'store_image', self.default_store_image)
        default_if_missing(args, 'force_build', self.default_force_build)
        default_if_missing(args, 'use_cache', self.default_use_cache)
        default_if_missing(args, 'keep_image', self.default_keep_image)

        print(f"Using repository at {args['repository']} with commit id {args['commit_id']}.")
        print(f"Using processor path '{args['proc_path']}'.")

        # determine credentials (if any)
        if args.get('git_username') and args.get('git_token'):
            credentials = (args.get('git_username'), args.get('git_token'))
            print(f"Using GitHub credentials for user '{credentials[0]}'.")
        else:
            credentials = None
            print("Not using any GitHub credentials.")

        with tempfile.TemporaryDirectory() as tempdir:
            # clone the repository and checkout the specified commit
            repo_path = os.path.join(tempdir, 'repository')
            commit_timestamp = clone_repository(args['repository'], repo_path, commit_id=args['commit_id'],
                                                credentials=credentials)
            print(f"Done cloning {args['repository']}.")

            # build the image
            image_name, descriptor, image_existed = \
                build_processor_image(repo_path, args['proc_path'], force_build=args['force_build'],
                                      use_cache=args['use_cache'])
            if args['force_build'] or not image_existed:
                print(f"Done building image '{image_name}'.")
            else:
                print(f"Using existing building image '{image_name}'.")

            if args['store_image']:
                # export the image
                export_path = os.path.join(tempdir, 'image.tar')
                docker_export_image(image_name, export_path, keep_image=image_existed or args['keep_image'])
                print(f"Done exporting image to '{export_path}'.")

                # upload the image to the DOR and set GPP tags
                obj = context.upload_content(export_path, 'ProcessorDockerImage', 'tar', False)
                obj.update_tags([
                    DataObject.Tag(key='repository', value=args['repository']),
                    DataObject.Tag(key='commit_id', value=args['commit_id']),
                    DataObject.Tag(key='commit_timestamp', value=commit_timestamp),
                    DataObject.Tag(key='proc_path', value=args['proc_path']),
                    DataObject.Tag(key='proc_descriptor', value=descriptor.dict()),
                    DataObject.Tag(key='image_name', value=image_name)
                ])
                print(f"Done uploading image to DOR -> object id: {obj.meta.obj_id}")
                os.remove(export_path)
                return {
                    'pdi': obj.meta
                }

            else:
                # store the GPP information in a file
                gpp_path = os.path.join(tempdir, 'gpp.json')
                with open(gpp_path, 'w') as f:
                    gpp = GitProcessorPointer(repository=args['repository'], commit_id=args['commit_id'],
                                              proc_path=args['proc_path'], proc_descriptor=descriptor)
                    json.dump(gpp.dict(), f)

                # upload the image to the DOR and set GPP tags
                pdi = context.upload_content(gpp_path, 'ProcessorDockerImage', 'json', False)
                pdi.update_tags([
                    DataObject.Tag(key='repository', value=args['repository']),
                    DataObject.Tag(key='commit_id', value=args['commit_id']),
                    DataObject.Tag(key='commit_timestamp', value=commit_timestamp),
                    DataObject.Tag(key='proc_path', value=args['proc_path']),
                    DataObject.Tag(key='proc_descriptor', value=descriptor.dict()),
                    DataObject.Tag(key='image_name', value=image_name)
                ])
                print(f"Done uploading PDI to DOR -> object id: {pdi.meta.obj_id}")
                os.remove(gpp_path)
                return {
                    'pdi': pdi.meta
                }
