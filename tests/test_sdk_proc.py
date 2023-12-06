import os
import tempfile
import threading
import time
from typing import Any

import pytest

from examples.adapters.proc_example.processor import write_value
from saas.core.helpers import get_timestamp_now
from saas.core.logging import Logging
from saas.rti.proc_wrapper import ProcessorRESTWrapper, ProcessorRESTProxy
from saas.rti.schemas import JobStatus
from saas.sdk.processor import find_processors, ProgressListener, Severity
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


def test_example_proc_success(temp_dir):
    write_value(os.path.join(temp_dir, 'a'), 1)
    write_value(os.path.join(temp_dir, 'b'), 1)

    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(proc is not None)

    # define the expected sequence of feedback from the Example processor
    expected_progress = [0, 30, 60, 90, 100]
    expected_messages = [
        (Severity.INFO, 'This is a message at the very beginning of the process.'),
        (Severity.INFO, 'a=1'),
        (Severity.INFO, 'b=1'),
        (Severity.INFO, 'c=2'),
        (Severity.INFO, '...and we are done!')
    ]
    expected_outputs = ['c']

    class ProgressListenerImpl(ProgressListener):
        def on_progress_update(self, progress: int) -> None:
            expected = expected_progress.pop(0)
            print(f"on_progress_update: {progress} | expected: {expected}")
            assert progress == expected

        def on_output_available(self, output_name: str) -> None:
            expected = expected_outputs.pop(0)
            print(f"on_output_available: {output_name} | expected: {expected}")
            assert output_name == expected

        def on_message(self, severity: Severity, message: str) -> None:
            expected = expected_messages.pop(0)
            print(f"on_message: {severity} {message} | expected: {expected}")
            assert severity == expected[0]
            assert message == expected[1]

    proc.run(temp_dir, ProgressListenerImpl(), logger)


def test_example_proc_failing(temp_dir):
    write_value(os.path.join(temp_dir, 'a'), 1)
    write_value(os.path.join(temp_dir, 'b'), 'wrong_type')

    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(result is not None)

    class ProgressListenerImpl(ProgressListener):
        def on_progress_update(self, progress: int) -> None:
            pass

        def on_output_available(self, output_name: str) -> None:
            pass

        def on_message(self, severity: Severity, message: str) -> None:
            pass

    try:
        proc.run(temp_dir, ProgressListenerImpl(), logger)
        assert False
    except Exception as e:
        assert str(e) == "invalid literal for int() with base 10: 'wrong_type'"


def test_example_proc_cancelled(temp_dir):
    write_value(os.path.join(temp_dir, 'a'), 5)
    write_value(os.path.join(temp_dir, 'b'), 5)

    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(result is not None)

    class ProgressListenerImpl(ProgressListener):
        def on_progress_update(self, progress: int) -> None:
            pass

        def on_output_available(self, output_name: str) -> None:
            pass

        def on_message(self, severity: Severity, message: str) -> None:
            pass

    # start the job and measure start/end time. if the job doesn't get interrupted it will take 10+ seconds
    # because 'a' and 'b' are used as delays in the Example proc. if it does get interrupted, it should be
    # significantly shorter.
    t0 = get_timestamp_now()
    worker = threading.Thread(target=proc.run,
                              kwargs={
                                  "wd_path": temp_dir,
                                  "listener": ProgressListenerImpl(),
                                  "logger": logger
                              })
    worker.start()
    time.sleep(0.5)  # give it some time to get going
    proc.interrupt()  # interrupt...
    worker.join()  # wait for the thread to return
    t1 = get_timestamp_now()
    dt = t1 - t0
    assert dt < 10000


def test_rest_wrapper_success(temp_dir):
    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(result is not None)

    # create the wrapper
    rest_address = PortMaster.generate_rest_address()
    wrapper = ProcessorRESTWrapper(proc, rest_address, temp_dir)
    wrapper.startup()

    # prepare the job folder
    job_id = '398h36g3'
    prepare_job_folder(temp_dir, job_id, a=1, b=1)

    # submit a job
    proxy = ProcessorRESTProxy(rest_address)
    proxy.job_submit(job_id)

    while True:
        time.sleep(0.5)
        status: JobStatus = proxy.job_status()
        print(status.dict())

        if status.state not in [JobStatus.State.INITIALISED, JobStatus.State.RUNNING]:
            break

    assert status.state == JobStatus.State.POSTPROCESSING


def test_rest_wrapper_failing(temp_dir):
    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(result is not None)

    # create the wrapper
    rest_address = PortMaster.generate_rest_address()
    wrapper = ProcessorRESTWrapper(proc, rest_address, temp_dir)
    wrapper.startup()

    # prepare the job folder
    job_id = '398h36g3'
    prepare_job_folder(temp_dir, job_id, a='wrong_type', b=1)

    # submit a job
    proxy = ProcessorRESTProxy(rest_address)
    proxy.job_submit(job_id)

    while True:
        time.sleep(0.5)
        status: JobStatus = proxy.job_status()
        print(status.dict())

        if status.state not in [JobStatus.State.INITIALISED, JobStatus.State.RUNNING]:
            break

    assert status.state == JobStatus.State.FAILED
    assert "invalid literal for int() with base 10: 'wrong_type'" in status.errors[0].message


def test_rest_wrapper_cancelled(temp_dir):
    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(result is not None)

    # create the wrapper
    rest_address = PortMaster.generate_rest_address()
    wrapper = ProcessorRESTWrapper(proc, rest_address, temp_dir)
    wrapper.startup()

    # prepare the job folder
    job_id = '398h36g3'
    prepare_job_folder(temp_dir, job_id, a=5, b=5)

    # submit a job
    proxy = ProcessorRESTProxy(rest_address)

    t0 = get_timestamp_now()
    proxy.job_submit(job_id)
    time.sleep(0.5)
    proxy.job_cancel()

    while True:
        time.sleep(0.1)
        status: JobStatus = proxy.job_status()
        print(status.dict())

        if status.state not in [JobStatus.State.INITIALISED, JobStatus.State.RUNNING]:
            break

    t1 = get_timestamp_now()
    dt = t1 - t0

    assert status.state == JobStatus.State.CANCELLED
    assert dt < 10000
