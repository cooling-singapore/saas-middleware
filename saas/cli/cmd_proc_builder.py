import json
import os
import shutil
import subprocess
import tempfile
from typing import Optional, Tuple

from git import Repo, NoSuchPathError, GitCommandError

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_for_string, prompt_if_missing, load_keystore
from saas.dor.schemas import ProcessorDescriptor, DataObject, GitProcessorPointer
from saas.sdk.base import connect


def clone_repository(repository_url: str, repository_path: str, commit_id: str = None,
                     credentials: Optional[Tuple[str, str]] = None) -> None:
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

    except NoSuchPathError as e:
        raise CLIRuntimeError(reason=str(e))

    except GitCommandError as e:
        raise CLIRuntimeError(reason=str(e))

    except Exception as e:
        raise CLIRuntimeError(reason=f"Unexpected: {e}")


def build_processor_image(repository_path: str, processor_path: str,
                          use_cache: bool = True) -> Tuple[str, ProcessorDescriptor]:
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

    # determine command
    command = ['docker', 'build']
    if not use_cache:
        command.append('--no-cache')
    command.extend(['-t', image_name, '.'])

    # build the docker image
    result = subprocess.run(command, cwd=processor_path, capture_output=True)
    if result.returncode != 0:
        raise CLIRuntimeError(f"Creating docker image failed.", details={
            'returncode': result.returncode,
            'stdout': result.stdout.decode('utf-8'),
            'stderr': result.stderr.decode('utf-8')
        })

    return image_name, descriptor


def export_processor_image(image_name: str, output_path: str, delete_from_docker: bool = True) -> None:
    # save the docker image
    result = subprocess.run(['docker', 'save', '-o', output_path, image_name], capture_output=True)
    if result.returncode != 0:
        raise CLIRuntimeError(f"Saving docker image '{image_name}' failed.", details={
            'returncode': result.returncode,
            'stdout': result.stdout.decode('utf-8'),
            'stderr': result.stderr.decode('utf-8')
        })

    # delete the image (if applicable)
    if delete_from_docker:
        result = subprocess.run(['docker', 'rmi', image_name], capture_output=True)
        if result.returncode != 0:
            raise CLIRuntimeError(f"Removing docker image '{image_name}' failed.", details={
                'returncode': result.returncode,
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })


class ProcBuilder(CLICommand):
    def __init__(self):
        super().__init__('build', 'build a processor', arguments=[
            Argument('--repository', dest='repository', action='store', help=f"URL of the repository"),
            Argument('--commit-id', dest='commit_id', action='store', help=f"the commit id"),
            Argument('--proc-path', dest='proc_path', action='store', help=f"path to the processor"),
            Argument('--git-username', dest='git_username', action='store', help=f"GitHub username"),
            Argument('--git-token', dest='git_token', action='store', help=f"GitHub personal access token")
        ])

    def execute(self, args: dict) -> None:
        # load keystore
        keystore = load_keystore(args, ensure_publication=True)

        # connect to network
        context = connect(args['address'], keystore)
        if not context.has_dor_node():
            raise CLIRuntimeError(f"No DOR-enabled node found.")

        prompt_if_missing(args, 'repository', prompt_for_string, message="Enter URL of the repository:")
        prompt_if_missing(args, 'commit_id', prompt_for_string, message="Enter the commit id:")
        prompt_if_missing(args, 'proc_path', prompt_for_string, message="Enter path to the processor:")

        print(f"Using repository at {args['repository']} with commit id {args['commit_id']}.")
        print(f"Using processor path '{args['proc_path']}'.")

        # determine credentials (if any)
        if args.get('git_username') and args.get('git_token'):
            credentials = (args.get('git_username'), args.get('git_token'))
            print(f"Using GitHub credentials for user '{credentials[0]}'.")
        else:
            credentials = None
            print(f"Not using any GitHub credentials.")

        with tempfile.TemporaryDirectory() as tempdir:
            # clone the repository and checkout the specified commit
            repo_path = os.path.join(tempdir, 'repository')
            clone_repository(args['repository'], repo_path, commit_id=args['commit_id'], credentials=credentials)
            print(f"Done cloning {args['repository']}.")

            # build the image
            image_name, descriptor = build_processor_image(repo_path, args['proc_path'], use_cache=True)
            print(f"Done building image '{image_name}'.")

            # export the image
            export_path = os.path.join(tempdir, 'image.tar')
            export_processor_image(image_name, export_path, delete_from_docker=True)
            print(f"Done exporting image to '{export_path}'.")

            # upload the image to the DOR and set GPP tags
            gpp = GitProcessorPointer(repository=args['repository'],
                                      commit_id=args['commit_id'],
                                      proc_path=args['proc_path'],
                                      proc_descriptor=descriptor)
            obj = context.upload_content(export_path, 'ProcessorDockerImage', 'tar', False)
            obj.update_tags([
                DataObject.Tag(key='gpp', value=gpp.dict()),
                DataObject.Tag(key='name', value=image_name)
            ])
            print(f"Done uploading image to DOR -> object id: {obj.meta.obj_id}")
