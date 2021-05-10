import collections
import json
import os
import shutil
import subprocess
import typing

from saas.cryptography.hashing import hash_string_object

if typing.TYPE_CHECKING:
    from saas.rti.rti import RuntimeInfrastructure

_GitSpec = collections.namedtuple('GitSpec', ['source', 'commit_id', 'processor_path'])


class GitSpec(_GitSpec):
    def hash(self):
        return hash_string_object(".".join([_attr for _attr in self])).hex()


class GitProcessorHelper:
    # TODO: Maybe looking into using GitPython for interacting with git
    def __init__(self, rti: 'RuntimeInfrastructure'):
        self._check_for_git()  # Methods here require `git` to be installed
        self.git_repo_store = os.path.join(rti.node.datastore_path, '_git_repos')

    @staticmethod
    def _check_for_git():
        if shutil.which('git') is None:
            raise OSError('`git` is not installed on this machine.')

    @staticmethod
    def _clone_repo(git_url: str, commit_id: str, git_local_path: str):
        if not os.path.exists(git_local_path):  # Only clone if path does not exist
            subprocess.run(['git', 'clone', git_url, git_local_path], check=True)
        # else:  # Try pulling new commits if exist
        #     subprocess.run(['git', 'pull'], cwd=git_local_path, check=True)

        result = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=git_local_path, check=True, capture_output=True)
        current_commit_id = str(result.stdout)
        if not current_commit_id.startswith(commit_id):
            subprocess.run(['git', 'checkout', commit_id], cwd=git_local_path, check=True)

    def get_git_local_path(self, git_spec: GitSpec):
        # git clone directory name will be the hash of the values of git spec file
        return os.path.join(self.git_repo_store, git_spec.hash())

    # TODO: Add descriptor validation
    def get_processor_descriptor(self, git_spec: GitSpec):
        local_git_dir = self.get_git_local_path(git_spec)
        self._clone_repo(git_spec.source, git_spec.commit_id, local_git_dir)  # Make sure its the correct commit

        proc_path = os.path.join(local_git_dir, git_spec.processor_path)
        descriptor_path = os.path.join(proc_path, 'descriptor.json')
        if not os.path.exists(proc_path) or not os.path.exists(descriptor_path):
            # Delete local git directory since it is invalid
            shutil.rmtree(local_git_dir)
            raise FileNotFoundError(f'Could not find processor descriptor in path `{git_spec.processor_path}`')

        with open(descriptor_path, 'r') as descriptor_file:
            descriptor = json.load(descriptor_file)

        # Add version info (commit id) to descriptor
        descriptor['version'] = git_spec.commit_id

        return descriptor

    def get_repo_descriptor(self, git_spec: GitSpec):
        local_git_dir = self.get_git_local_path(git_spec)
        self._clone_repo(git_spec.source, git_spec.commit_id, local_git_dir)  # Make sure its the correct commit

        # repo descriptor is in the root of the git directory
        descriptor_path = os.path.join(local_git_dir, 'descriptor.json')
        if not os.path.exists(descriptor_path):
            raise FileNotFoundError(f'Could not find processor descriptor in path `{git_spec.processor_path}`')

        with open(descriptor_path, 'r') as descriptor_file:
            descriptor = json.load(descriptor_file)

        return descriptor
