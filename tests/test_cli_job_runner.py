import json
import logging
import multiprocessing
import os
import tempfile
import time
from typing import Any

import pytest

from examples.adapters.proc_example.processor import write_value
from saas.cli.cmd_job_runner import JobRunner, JobWorker, wait_for_job_runner
from saas.core.logging import Logging
from saas.rti.proxy import JobRESTProxy
from saas.rti.schemas import JobResult, ExitCode
from saas.sdk.processor import find_processors
from tests.base_testcase import PortMaster

logger = Logging.get(__name__)


@pytest.fixture(scope="function")
def temp_dir():
    with tempfile.TemporaryDirectory() as tempdir:
        yield tempdir


def prepare_job_folder(jobs_root_path: str, job_id: str, a: Any = 1, b: Any = 1) -> str:
    # create the job folder
    job_path = os.path.join(jobs_root_path, job_id)
    os.makedirs(job_path, exist_ok=True)

    # write the data objects 'a' and 'b'
    write_value(os.path.join(job_path, 'a'), a)
    write_value(os.path.join(job_path, 'b'), b)

    return job_path


def run_job_cmd(job_path: str, host: str, port: int) -> None:
    cmd = JobRunner()
    args = {
        'job_path': job_path,
        'proc_path': os.path.join(os.path.abspath(os.getcwd()), '..', 'examples'),
        'proc_name': 'example-processor',
        'rest_address': f"{host}:{port}"
    }
    cmd.execute(args)


def run_job_cmd_noname(job_path: str, host: str, port: int) -> None:
    cmd = JobRunner()
    args = {
        'job_path': job_path,
        'proc_path': os.path.join(os.path.abspath(os.getcwd()), '..', 'examples', 'adapters', 'proc_example'),
        'rest_address': f"{host}:{port}"
    }
    cmd.execute(args)


def test_job_worker_done(temp_dir):
    job_id = 'abcd1234'
    job_path = os.path.join(temp_dir, job_id)
    prepare_job_folder(temp_dir, job_id, 1, 1)

    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(proc is not None)

    worker = JobWorker(proc, job_path, logging.INFO)
    worker.start()
    worker.join()

    expected_files = ['c', 'job.exitcode', 'job.status', 'job.log']
    for file in expected_files:
        if not os.path.isfile(os.path.join(job_path, file)):
            assert False

    exitcode_path = os.path.join(job_path, 'job.exitcode')
    with open(exitcode_path, 'r') as f:
        result = JobResult.parse_obj(json.load(f))

    assert result.exitcode == ExitCode.DONE


def test_job_worker_interrupted(temp_dir):
    job_id = 'abcd1234'
    job_path = os.path.join(temp_dir, job_id)
    prepare_job_folder(temp_dir, job_id, 5, 5)

    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(proc is not None)

    worker = JobWorker(proc, job_path, logging.INFO)
    worker.start()
    worker.interrupt()
    worker.join()

    expected_files = ['job.exitcode', 'job.status', 'job.log']
    for file in expected_files:
        if not os.path.isfile(os.path.join(job_path, file)):
            assert False

    exitcode_path = os.path.join(job_path, 'job.exitcode')
    with open(exitcode_path, 'r') as f:
        result = JobResult.parse_obj(json.load(f))

    assert result.exitcode == ExitCode.INTERRUPTED


def test_job_worker_error(temp_dir):
    job_id = 'abcd1234'
    job_path = os.path.join(temp_dir, job_id)
    prepare_job_folder(temp_dir, job_id, 1, 'sdf')

    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(proc is not None)

    worker = JobWorker(proc, job_path, logging.INFO)
    worker.start()
    worker.join()

    expected_files = ['job.exitcode', 'job.status', 'job.log']
    for file in expected_files:
        if not os.path.isfile(os.path.join(job_path, file)):
            assert False

    exitcode_path = os.path.join(job_path, 'job.exitcode')
    with open(exitcode_path, 'r') as f:
        result = JobResult.parse_obj(json.load(f))

    assert result.exitcode == ExitCode.ERROR
    assert "ValueError: invalid literal for int() with base 10: 'sdf'" in result.trace


def test_cli_runner_success(temp_dir):
    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_job_folder(temp_dir, job_id, a=1, b=1)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    runner_result, job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 100
    assert job_result.exitcode == ExitCode.DONE
    assert runner_result.exitcode == ExitCode.DONE


def test_cli_runner_success_no_name(temp_dir):
    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_job_folder(temp_dir, job_id, a=1, b=1)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd_noname, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    runner_result, job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 100
    assert job_result.exitcode == ExitCode.DONE
    assert runner_result.exitcode == ExitCode.DONE


def test_cli_runner_failing(temp_dir):
    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_job_folder(temp_dir, job_id, a='one', b=1)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    runner_result, job_result, status = wait_for_job_runner(job_path, rest_address)
    assert runner_result.exitcode == ExitCode.DONE  # the runner shouldn't have failed.
    assert job_result.exitcode == ExitCode.ERROR  # the job should have failed
    assert "ValueError: invalid literal for int() with base 10: 'one'" in job_result.trace


def test_cli_runner_cancelled(temp_dir):
    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_job_folder(temp_dir, job_id, a=5, b=6)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # try to cancel the job
    proxy = JobRESTProxy(rest_address)
    while proxy.job_cancel() is None:
       time.sleep(1)

    # wait for the job to be finished
    runner_result, job_result, status = wait_for_job_runner(job_path, rest_address)
    assert runner_result.exitcode == ExitCode.DONE  # the runner shouldn't have failed.
    assert job_result.exitcode == ExitCode.INTERRUPTED
