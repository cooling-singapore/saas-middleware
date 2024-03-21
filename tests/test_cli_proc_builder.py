import json
import os
import socket
import tempfile
from typing import Dict, Tuple

import pytest
from docker.errors import ImageNotFound

from saas.cli.cmd_proc_builder import clone_repository, build_processor_image, ProcBuilder
from saas.cli.exceptions import CLIRuntimeError
from saas.core.keystore import Keystore
from saas.core.logging import Logging
from saas.helpers import find_available_port, docker_export_image
from tests.conftest import commit_id

logger = Logging.get(__name__)

@pytest.fixture(scope="function")
def temp_dir():
    with tempfile.TemporaryDirectory() as tempdir:
        yield tempdir


@pytest.fixture(scope="module")
def github_credentials() -> Dict[str, Tuple[str, str]]:
    credentials_path = os.path.join(os.environ['HOME'], '.saas-credentials.json')
    result = {}
    if os.path.isfile(credentials_path):
        with open(credentials_path) as f:
            content = json.load(f)
            if 'github-credentials' in content:
                for item in content['github-credentials']:
                    repository = item['repository']
                    login = item['login']
                    token = item['personal_access_token']
                    result[repository] = (login, token)

    yield result


def test_find_open_port():
    # block port 5995
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5995))
    server_socket.listen(1)

    port = find_available_port(host='localhost', port_range=(5990, 5994))
    assert(port == 5990)

    port = find_available_port(host='localhost', port_range=(5995, 5999))
    assert(port == 5996)


def test_cli_builder_clone_repo(temp_dir, github_credentials):
    repo_url = 'https://github.com/cooling-singapore/saas-middleware'
    credentials = github_credentials.get(repo_url)
    repo_path = os.path.join(temp_dir, 'repository')

    try:
        clone_repository(repo_url+"_doesnt_exist", temp_dir, credentials=credentials)
        assert False
    except CLIRuntimeError:
        assert True

    try:
        clone_repository(repo_url, repo_path, commit_id="doesntexist", credentials=credentials)
        assert False
    except CLIRuntimeError:
        assert os.path.isdir(repo_path)
        assert True

    try:
        clone_repository(repo_url, repo_path, commit_id=commit_id, credentials=credentials)
        assert os.path.isdir(repo_path)
        assert True
    except CLIRuntimeError:
        assert False


def test_cli_builder_build_image(temp_dir, github_credentials):
    # clone the repository
    repo_url = 'https://github.com/cooling-singapore/saas-middleware'
    credentials = github_credentials.get(repo_url)
    repo_path = os.path.join(temp_dir, 'repository')
    clone_repository(repo_url, repo_path, commit_id=commit_id, credentials=credentials)

    proc_path = "examples/adapters/proc_example"

    try:
        build_processor_image(repo_path+"_wrong", proc_path)
        assert False
    except CLIRuntimeError:
        assert True

    try:
        proc_path_wrong = "examples/adapters"
        build_processor_image(repo_path, proc_path_wrong)
        assert False
    except CLIRuntimeError:
        assert True

    try:
        build_processor_image(repo_path, proc_path)
    except CLIRuntimeError:
        assert False


def test_cli_builder_export_image(temp_dir, github_credentials):
    image_path = os.path.join(temp_dir, 'image.tar')

    try:
        docker_export_image('doesnt-exist', image_path)
        assert False
    except ImageNotFound:
        assert True

    # clone the repository
    repo_url = 'https://github.com/cooling-singapore/saas-middleware'
    credentials = github_credentials.get(repo_url)
    repo_path = os.path.join(temp_dir, 'repository')
    clone_repository(repo_url, repo_path, commit_id=commit_id, credentials=credentials)

    # build image
    proc_path = "examples/adapters/proc_example"
    image_name, _, _ = build_processor_image(repo_path, proc_path, use_cache=True)

    # export image
    try:
        docker_export_image(image_name, image_path, keep_image=True)
        assert os.path.isfile(image_path)
    except Exception:
        assert False


def test_cli_builder_cmd(node, temp_dir, github_credentials):
    address = node.rest.address()
    repo_url = 'https://github.com/cooling-singapore/saas-middleware'
    credentials = github_credentials.get(repo_url)

    # define arguments
    args = {
        'repository': repo_url,
        'commit_id': commit_id,
        'proc_path': 'examples/adapters/proc_example',
        'address': f"{address[0]}:{address[1]}",
        'git_username': credentials[0],
        'git_token': credentials[1]
    }

    # create keystore
    password = 'password'
    keystore = Keystore.create(temp_dir, 'name', 'email', password)
    args['keystore-id'] = keystore.identity.id
    args['keystore'] = temp_dir
    args['password'] = password

    # ensure the node knows about this identity
    node.db.update_identity(keystore.identity)

    try:
        cmd = ProcBuilder()
        obj_id = cmd.execute(args)

        obj = node.dor.get_meta(obj_id)
        assert obj is not None
        assert obj.data_type == 'ProcessorDockerImage'
        assert obj.data_format == 'json'

    except CLIRuntimeError:
        assert False


def test_cli_builder_cmd_store_image(node, temp_dir, github_credentials):
    address = node.rest.address()
    repo_url = 'https://github.com/cooling-singapore/saas-middleware'
    credentials = github_credentials.get(repo_url)

    # define arguments
    args = {
        'repository': repo_url,
        'commit_id':  commit_id,
        'proc_path': 'examples/adapters/proc_example',
        'address': f"{address[0]}:{address[1]}",
        'git_username': credentials[0],
        'git_token': credentials[1],
        'store_image': True
    }

    # create keystore
    password = 'password'
    keystore = Keystore.create(temp_dir, 'name', 'email', password)
    args['keystore-id'] = keystore.identity.id
    args['keystore'] = temp_dir
    args['password'] = password

    # ensure the node knows about this identity
    node.db.update_identity(keystore.identity)

    try:
        cmd = ProcBuilder()
        obj_id = cmd.execute(args)

        obj = node.dor.get_meta(obj_id)
        assert obj is not None
        assert obj.data_type == 'ProcessorDockerImage'
        assert obj.data_format == 'tar'

    except CLIRuntimeError:
        assert False
