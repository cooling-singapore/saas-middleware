import logging
import os
import shutil
import sys
import traceback
import pytest

from saas.core.logging import Logging
from saas.rti.adapters.base import run_command, determine_home_path, determine_if_cygwin, get_pid, check_if_path_exists, \
    join_paths, scp_local_to_remote, scp_remote_to_local, run_command_async, monitor_command

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


@pytest.fixture(scope="module")
def remote_linux_credentials(keystore):
    cred = keystore.ssh_credentials.get('vm-test-linux')
    if cred is None:
        pytest.skip("SSH credentials not found")
    cred.is_cygwin = False
    return cred


@pytest.fixture(scope="module")
def remote_cygwin_credentials(keystore):
    cred = keystore.ssh_credentials.get('vm-test-cygwin')
    if cred is None:
        pytest.skip("SSH credentials not found")
    cred.is_cygwin = True
    return cred


@pytest.fixture()
def echo_hello() -> str:
    return 'echo -n "hello"'


def create_pid_file(folder_path: str, pid: str) -> str:
    return f"mkdir {folder_path} && cd {folder_path} && echo {pid} > pid.txt"


def remove_pid_file(folder_path: str) -> str:
    return f"cd {folder_path} && rm pid.txt && cd .. && rmdir {folder_path}"


def delete_folder(folder_path: str) -> str:
    return f"cd {folder_path} && rm * && cd .. && rmdir {folder_path}"


def test_join_paths():
    components = ['a', 'b', 'c.tmp']

    # are we on windows or unix?
    if sys.platform.startswith('win'):
        path = join_paths(components)
        assert path == 'a\\b\\c.tmp'

    else:
        path = join_paths(components)
        assert path == 'a/b/c.tmp'


def test_run_command_local(echo_hello):
    try:
        result = run_command(echo_hello)
        stdout = result.stdout.decode('utf-8')
        stderr = result.stderr.decode('utf-8')
        print(stdout)
        print(stderr)
        assert(stdout == 'hello')
        assert(len(stderr) == 0)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_run_command_remote_linux(echo_hello, remote_linux_credentials):
    try:
        result = run_command(echo_hello, ssh_credentials=remote_linux_credentials)
        stdout = result.stdout.decode('utf-8')
        stderr = result.stderr.decode('utf-8')
        print(stdout)
        print(stderr)
        assert(stdout == 'hello')
        assert(len(stderr) == 0)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_run_command_remote_cywgin(echo_hello, remote_cygwin_credentials):
    try:
        result = run_command(echo_hello, ssh_credentials=remote_cygwin_credentials)
        stdout = result.stdout.decode('utf-8')
        stderr = result.stderr.decode('utf-8')
        print(stdout)
        print(stderr)
        assert(stdout == 'hello')
        assert(len(stderr) == 0)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_determine_home_path_local():
    try:
        result = determine_home_path()
        print(result)
        assert(result == os.environ['HOME'])

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_determine_home_path_remote_linux(remote_linux_credentials):
    try:
        result = determine_home_path(remote_linux_credentials)
        assert(result.startswith('/home/'))

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_determine_home_path_remote_cygwin(remote_cygwin_credentials):
    pass


def test_determine_if_cygwin_remote_linux(remote_linux_credentials):
    try:
        result = determine_if_cygwin(remote_linux_credentials)
        assert(result is False)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_determine_if_cygwin_remote_cygwin(remote_cygwin_credentials):
    try:
        result = determine_if_cygwin(remote_cygwin_credentials)
        assert(result is True)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_check_if_path_exists_local():
    home_path = determine_home_path()
    folder = 'lskdfhs478'
    folder_path = join_paths([home_path, folder])

    try:
        result = check_if_path_exists(home_path)
        assert(result is True)

        result = check_if_path_exists(folder_path)
        assert(result is False)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_check_if_path_exists_remote_linux(remote_linux_credentials):
    home_path = determine_home_path(remote_linux_credentials)
    folder = 'lskdfhs478'
    folder_path = join_paths([home_path, folder], remote_linux_credentials)

    try:
        result = check_if_path_exists(home_path, ssh_credentials=remote_linux_credentials)
        assert(result is True)

        result = check_if_path_exists(folder_path, ssh_credentials=remote_linux_credentials)
        assert(result is False)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_check_if_path_exists_remote_cygwin(remote_cygwin_credentials):
    home_path = determine_home_path(remote_cygwin_credentials)
    folder = 'lskdfhs478'
    folder_path = join_paths([home_path, folder], remote_cygwin_credentials)

    try:
        result = check_if_path_exists(home_path, ssh_credentials=remote_cygwin_credentials)
        assert(result is True)

        result = check_if_path_exists(folder_path, ssh_credentials=remote_cygwin_credentials)
        assert(result is False)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_get_pid_local():
    # ensure the test folder doesn't exist!
    home_path = determine_home_path()
    folder = '__test_get_pid_local'
    folder_path = join_paths([home_path, folder])
    assert(not check_if_path_exists(folder_path))

    try:
        run_command(create_pid_file(folder_path, '123'))

        pid_path = join_paths([folder_path, 'pid.txt'])
        result = get_pid(pid_path)
        assert(result == '123')

        run_command(remove_pid_file(folder_path))

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_get_pid_remote_linux(remote_linux_credentials):
    # ensure the test folder doesn't exist!
    home_path = determine_home_path(remote_linux_credentials)
    folder = '__test_get_pid_remote_linux'
    folder_path = join_paths([home_path, folder], ssh_credentials=remote_linux_credentials)
    if check_if_path_exists(folder_path, ssh_credentials=remote_linux_credentials):
        run_command(delete_folder(folder_path), ssh_credentials=remote_linux_credentials)

    try:
        run_command(create_pid_file(folder_path, '123'), ssh_credentials=remote_linux_credentials)

        pid_path = join_paths([folder_path, 'pid.txt'])
        result = get_pid(pid_path, ssh_credentials=remote_linux_credentials)
        assert(result == '123')

        run_command(remove_pid_file(folder_path), ssh_credentials=remote_linux_credentials)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_get_pid_remote_cygwin(remote_cygwin_credentials):
    # ensure the test folder doesn't exist!
    home_path = determine_home_path(remote_cygwin_credentials)
    folder = '__test_get_pid_remote_cygwin'
    folder_path = join_paths([home_path, folder], ssh_credentials=remote_cygwin_credentials)
    if check_if_path_exists(folder_path, ssh_credentials=remote_cygwin_credentials):
        run_command(delete_folder(folder_path), ssh_credentials=remote_cygwin_credentials)

    try:
        run_command(create_pid_file(folder_path, '123'), ssh_credentials=remote_cygwin_credentials)

        pid_path = join_paths([folder_path, 'pid.txt'])
        result = get_pid(pid_path, ssh_credentials=remote_cygwin_credentials)
        assert(result == '123')

        run_command(remove_pid_file(folder_path), ssh_credentials=remote_cygwin_credentials)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_scp_local_to_remote_to_local_linux(remote_linux_credentials):
    filename = '__test_scp_local_to_remote_to_local_linux'

    home_path_local = determine_home_path()
    local_path = join_paths([home_path_local, filename], ssh_credentials=None)
    if check_if_path_exists(local_path, ssh_credentials=None):
        run_command(delete_folder(local_path), ssh_credentials=None)

    home_path_remote = determine_home_path(ssh_credentials=remote_linux_credentials)
    remote_path = join_paths([home_path_remote, filename], ssh_credentials=remote_linux_credentials)
    if check_if_path_exists(remote_path, ssh_credentials=remote_linux_credentials):
        run_command(delete_folder(remote_path), ssh_credentials=remote_linux_credentials)

    # create test file
    with open(local_path, 'w') as f:
        f.write('test')

    try:
        assert check_if_path_exists(local_path, ssh_credentials=None)
        assert not check_if_path_exists(remote_path, ssh_credentials=remote_linux_credentials)

        scp_local_to_remote(local_path, remote_path, ssh_credentials=remote_linux_credentials)

        assert check_if_path_exists(local_path, ssh_credentials=None)
        assert check_if_path_exists(remote_path, ssh_credentials=remote_linux_credentials)

        os.remove(local_path)

        assert not check_if_path_exists(local_path, ssh_credentials=None)
        assert check_if_path_exists(remote_path, ssh_credentials=remote_linux_credentials)

        scp_remote_to_local(remote_path, local_path, ssh_credentials=remote_linux_credentials)

        assert check_if_path_exists(local_path, ssh_credentials=None)
        assert check_if_path_exists(remote_path, ssh_credentials=remote_linux_credentials)

        os.remove(local_path)
        run_command(f'rm {remote_path}', ssh_credentials=remote_linux_credentials)

        assert not check_if_path_exists(local_path, ssh_credentials=None)
        assert not check_if_path_exists(remote_path, ssh_credentials=remote_linux_credentials)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_scp_local_to_remote_to_local_cygwin(remote_cygwin_credentials):
    filename = '__test_scp_local_to_remote_to_local_cygwin'

    home_path_local = determine_home_path()
    local_path = join_paths([home_path_local, filename], ssh_credentials=None)
    if check_if_path_exists(local_path, ssh_credentials=None):
        run_command(delete_folder(local_path), ssh_credentials=None)

    home_path_remote = determine_home_path(ssh_credentials=remote_cygwin_credentials)
    remote_path = join_paths([home_path_remote, filename], ssh_credentials=remote_cygwin_credentials)
    if check_if_path_exists(remote_path, ssh_credentials=remote_cygwin_credentials):
        run_command(delete_folder(remote_path), ssh_credentials=remote_cygwin_credentials)

    # create test file
    with open(local_path, 'w') as f:
        f.write('test')

    try:
        assert check_if_path_exists(local_path, ssh_credentials=None)
        assert not check_if_path_exists(remote_path, ssh_credentials=remote_cygwin_credentials)

        scp_local_to_remote(local_path, remote_path, ssh_credentials=remote_cygwin_credentials)

        assert check_if_path_exists(local_path, ssh_credentials=None)
        assert check_if_path_exists(remote_path, ssh_credentials=remote_cygwin_credentials)

        os.remove(local_path)

        assert not check_if_path_exists(local_path, ssh_credentials=None)
        assert check_if_path_exists(remote_path, ssh_credentials=remote_cygwin_credentials)

        scp_remote_to_local(remote_path, local_path, ssh_credentials=remote_cygwin_credentials)

        assert check_if_path_exists(local_path, ssh_credentials=None)
        assert check_if_path_exists(remote_path, ssh_credentials=remote_cygwin_credentials)

        os.remove(local_path)
        run_command(f'rm {remote_path}', ssh_credentials=remote_cygwin_credentials)

        assert not check_if_path_exists(local_path, ssh_credentials=None)
        assert not check_if_path_exists(remote_path, ssh_credentials=remote_cygwin_credentials)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_run_command_async_local():
    ssh_credentials = None
    folder = '__test_run_command_async_local'

    # ensure the test folder doesn't exist!
    local_home_path = determine_home_path()
    local_folder_path = join_paths([local_home_path, folder])
    if check_if_path_exists(local_folder_path, ssh_credentials=None):
        run_command(delete_folder(local_folder_path), ssh_credentials=None)

    command = 'sleep 20 && echo trigger:progress 100'

    def update_progress(line: str, context=None) -> None:
        print(line)

    try:
        pid, paths = run_command_async(command, local_output_path=local_folder_path,
                                       name='test', ssh_credentials=ssh_credentials)
        assert check_if_path_exists(paths['wd_path'], ssh_credentials=ssh_credentials)

        triggers = {'trigger:progress': {'func': update_progress, 'context': None}}
        monitor_command(pid, paths, triggers=triggers, ssh_credentials=ssh_credentials)

        run_command(f"rm -rf {paths['wd_path']}", ssh_credentials=ssh_credentials)
        assert not check_if_path_exists(paths['wd_path'], ssh_credentials=ssh_credentials)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_run_command_async_remote_linux(remote_linux_credentials):
    ssh_credentials = remote_linux_credentials
    folder = '__test_run_command_async_remote_linux'

    # update the remote home path
    ssh_credentials.home_path = determine_home_path(ssh_credentials=ssh_credentials)

    # ensure the test folder doesn't exist!
    local_home_path = determine_home_path()
    local_folder_path = join_paths([local_home_path, folder])
    if check_if_path_exists(local_folder_path, ssh_credentials=None):
        run_command(delete_folder(local_folder_path), ssh_credentials=None)

    command = 'sleep 20 && echo trigger:progress 100'

    def update_progress(line: str, context=None) -> None:
        print(line)

    try:
        pid, paths = run_command_async(command, local_output_path=local_folder_path,
                                       name='test', ssh_credentials=ssh_credentials)
        assert check_if_path_exists(paths['wd_path'], ssh_credentials=ssh_credentials)
        assert check_if_path_exists(local_folder_path, ssh_credentials=None)

        triggers = {'trigger:progress': {'func': update_progress, 'context': None}}
        monitor_command(pid, paths, triggers=triggers, ssh_credentials=ssh_credentials)

        run_command(f"rm -rf {paths['wd_path']}", ssh_credentials=ssh_credentials)
        shutil.rmtree(local_folder_path)
        assert not check_if_path_exists(paths['wd_path'], ssh_credentials=ssh_credentials)
        assert not check_if_path_exists(local_folder_path, ssh_credentials=None)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False


def test_run_command_async_remote_cygwin(remote_cygwin_credentials):
    ssh_credentials = remote_cygwin_credentials
    folder = '__test_run_command_async_remote_cygwin'

    # update the remote home path
    ssh_credentials.home_path = determine_home_path(ssh_credentials=ssh_credentials)

    # ensure the test folder doesn't exist!
    local_home_path = determine_home_path()
    local_folder_path = join_paths([local_home_path, folder])
    if check_if_path_exists(local_folder_path, ssh_credentials=None):
        run_command(delete_folder(local_folder_path), ssh_credentials=None)

    command = 'sleep 20'

    try:
        pid, paths = run_command_async(command, local_output_path=local_folder_path,
                                       name='test', ssh_credentials=ssh_credentials)
        assert check_if_path_exists(paths['wd_path'], ssh_credentials=ssh_credentials)
        assert check_if_path_exists(local_folder_path, ssh_credentials=None)

        monitor_command(pid, paths, ssh_credentials=ssh_credentials)

        run_command(f"rm -rf {paths['wd_path']}", ssh_credentials=ssh_credentials)
        shutil.rmtree(local_folder_path)
        assert not check_if_path_exists(paths['wd_path'], ssh_credentials=ssh_credentials)
        assert not check_if_path_exists(local_folder_path, ssh_credentials=None)

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        assert False
