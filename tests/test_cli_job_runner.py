import json
import logging
import multiprocessing
import os
import tempfile
import threading
import time
import traceback
from typing import Any, Optional, Tuple, List, Union

import pytest

from examples.adapters.proc_example.processor import write_value
from saas.cli.cmd_job_runner import JobRunner
from saas.core.identity import Identity
from saas.core.logging import Logging
from saas.dor.proxy import DORProxy
from saas.dor.schemas import GitProcessorPointer, ProcessorDescriptor, DataObject
from saas.node import Node
from saas.rti.proxy import JobRESTProxy
from saas.rti.schemas import JobResult, ExitCode, Job, JobStatus, Severity, Task
from saas.sdk.processor import find_processors, ProgressListener, ProcessorBase, ProcessorRuntimeError
from tests.base_testcase import PortMaster

logger = Logging.get(__name__)


@pytest.fixture(scope="function")
def temp_dir():
    with tempfile.TemporaryDirectory() as tempdir:
        yield tempdir


def prepare_data_object(content_path: str, node: Node, v: int = 1, data_type: str = 'JSONObject',
                        data_format: str = 'json', access: List[Identity] = None) -> DataObject:
    with open(content_path, 'w') as f:
        json.dump({'v': v}, f, indent=2)

    proxy = DORProxy(node.rest.address())
    if access:
        obj = proxy.add_data_object(content_path, node.identity, True, False, data_type, data_format)
        for identity in access:
            obj = proxy.grant_access(obj.obj_id, node.keystore, identity)

    else:
        obj = proxy.add_data_object(content_path, node.identity, False, False, data_type, data_format)

    return obj


def prepare_plain_job_folder(jobs_root_path: str, job_id: str, a: Any = 1, b: Any = 1) -> str:
    # create the job folder
    job_path = os.path.join(jobs_root_path, job_id)
    os.makedirs(job_path, exist_ok=True)

    # write the data objects 'a' and 'b'
    write_value(os.path.join(job_path, 'a'), a)
    write_value(os.path.join(job_path, 'b'), b)

    return job_path


def prepare_full_job_folder(jobs_root_path: str, node: Node, user: Identity, proc: DataObject, job_id: str,
                            a: Union[dict, int, str, DataObject], b: Union[dict, int, str, DataObject],
                            sig_a: str = None, sig_b: str = None, target_node: Node = None) -> str:
    proc_descriptor = ProcessorDescriptor.parse_obj(proc.tags['proc_descriptor'])

    if a is None:
        a = {'v': 1}
    elif isinstance(a, (int, str)):
        a = {'v': a}

    if b is None:
        b = {'v': 1}
    elif isinstance(b, (int, str)):
        b = {'v': b}

    a = Task.InputReference(name='a', type='reference', obj_id=a.obj_id, user_signature=sig_a) \
        if isinstance(a, DataObject) else Task.InputValue(name='a', type='value', value=a)

    b = Task.InputReference(name='b', type='reference', obj_id=b.obj_id, user_signature=sig_b) \
        if isinstance(b, DataObject) else Task.InputValue(name='b', type='value', value=b)

    c = Task.Output(name='c', owner_iid=user.id, restricted_access=False, content_encrypted=False,
                    target_node_iid=target_node.identity.id if target_node else node.identity.id)

    task = Task(proc_id=proc.obj_id, user_iid=user.id, input=[a, b], output=[c], name='test', description='')

    # create job
    job = Job(id=job_id, task=task, retain=False, custodian=node.info, proc_name=proc_descriptor.name, t_submitted=0)

    # create gpp
    gpp = GitProcessorPointer(repository=proc.tags['repository'], commit_id=proc.tags['commit_id'],
                              proc_path=proc.tags['proc_path'], proc_descriptor=proc_descriptor)

    # create the job folder
    job_path = os.path.join(jobs_root_path, job.id)
    os.makedirs(job_path, exist_ok=True)

    # write job descriptor
    job_descriptor_path = os.path.join(job_path, 'job.descriptor')
    with open(job_descriptor_path, 'w') as f:
        json.dump(job.dict(), f, indent=2)

    # write gpp descriptor
    gpp_descriptor_path = os.path.join(job_path, 'gpp.descriptor')
    with open(gpp_descriptor_path, 'w') as f:
        json.dump(gpp.dict(), f, indent=2)

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


class ProcessorRunner(threading.Thread, ProgressListener):
    def __init__(self, proc: ProcessorBase, wd_path: str, log_level: int = logging.INFO) -> None:
        super().__init__()

        self._mutex = threading.Lock()
        self._proc = proc
        self._wd_path = wd_path
        self._interrupted = False

        # setup logger
        log_path = os.path.join(wd_path, 'job.log')
        self._logger = Logging.get('cli.job_runner', level=log_level, custom_log_path=log_path)

        # initialise job status
        self._job_status = JobStatus(state=JobStatus.State.UNINITIALISED, progress=0, output={}, notes={},
                                     errors=[], message=None)
        self._store_job_status()

    def on_progress_update(self, progress: int) -> None:
        self._logger.info(f"on_progress_update: progress={progress}")
        self._job_status.progress = progress
        self._store_job_status()

    def on_output_available(self, output_name: str) -> None:
        if output_name not in self._job_status.output:
            self._logger.info(f"on_output_available: output_name={output_name}")
            self._job_status.output[output_name] = None
            self._store_job_status()

    def on_message(self, severity: Severity, message: str) -> None:
        self._logger.info(f"on_message: severity={severity} message={message}")
        self._job_status.message = JobStatus.Message(severity=severity, content=message)
        self._store_job_status()

    def _store_job_status(self) -> None:
        job_status_path = os.path.join(self._wd_path, 'job.status')
        with open(job_status_path, 'w') as f:
            json.dump(self._job_status.dict(), f, indent=2)

    def _write_exitcode(self, exitcode: ExitCode, e: Exception = None) -> None:
        exitcode_path = os.path.join(self._wd_path, 'job.exitcode')
        with open(exitcode_path, 'w') as f:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__)) if e else None
            result = JobResult(exitcode=exitcode, trace=trace)
            json.dump(result.dict(), f, indent=2)

    def run(self) -> None:
        try:
            self._logger.info(f"begin processing job at {self._wd_path}")

            self._proc.run(self._wd_path, self, self._logger)

            if self._interrupted:
                self._logger.info(f"end processing job at {self._wd_path} -> INTERRUPTED")
                self._write_exitcode(ExitCode.INTERRUPTED)

            else:
                self._logger.info(f"end processing job at {self._wd_path} -> DONE")
                self._write_exitcode(ExitCode.DONE)

        except ProcessorRuntimeError as e:
            self._logger.error(f"end processing job at {self._wd_path} -> FAILED: {e.reason}")
            self._write_exitcode(ExitCode.ERROR, e)

        except Exception as e:
            self._logger.error(f"end processing job at {self._wd_path} -> FAILED: {e}")
            self._write_exitcode(ExitCode.ERROR, e)

    def status(self) -> JobStatus:
        with self._mutex:
            return self._job_status

    def interrupt(self) -> JobStatus:
        with self._mutex:
            self._logger.info(f"attempt to interrupt job at {self._wd_path}...")
            self._interrupted = True
            self._proc.interrupt()
            return self._job_status


def wait_for_job_runner(job_path: str, rest_address: (str, int)) -> Tuple[Optional[JobResult], Optional[JobStatus]]:
    job_exitcode_path = os.path.join(job_path, 'job.exitcode')
    job_status_path = os.path.join(job_path, 'job.status')
    proxy = JobRESTProxy(rest_address)
    while True:
        status: JobStatus = proxy.job_status()
        if status is None:
            # is there a job.exitcode and runner.exitcode file?
            has_job_exitcode = os.path.isfile(job_exitcode_path)
            has_job_status = os.path.isfile(job_status_path)
            if has_job_exitcode:
                job_result = JobResult.parse_file(job_exitcode_path) if has_job_exitcode else None
                status = JobStatus.parse_file(job_status_path) if has_job_status else None
                return job_result, status

            else:
                pass

        else:
            pass

        time.sleep(0.5)


def test_job_worker_done(temp_dir):
    job_id = 'abcd1234'
    job_path = os.path.join(temp_dir, job_id)
    prepare_plain_job_folder(temp_dir, job_id, 1, 1)

    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(proc is not None)

    worker = ProcessorRunner(proc, job_path, logging.INFO)
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
    prepare_plain_job_folder(temp_dir, job_id, 5, 5)

    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(proc is not None)

    worker = ProcessorRunner(proc, job_path, logging.INFO)
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
    prepare_plain_job_folder(temp_dir, job_id, 1, 'sdf')

    # find the Example processor
    search_path = os.path.join(os.path.abspath(os.getcwd()), '..', 'examples')
    result = find_processors(search_path)
    proc = result.get('example-processor')
    assert(proc is not None)

    worker = ProcessorRunner(proc, job_path, logging.INFO)
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


def test_cli_runner_success_by_value(temp_dir, node, deployed_test_processor):
    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, node.identity, deployed_test_processor, job_id, a=1, b=1)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 100
    assert job_result.exitcode == ExitCode.DONE


def test_cli_runner_failing_validation(temp_dir, node, deployed_test_processor):
    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, node.identity, deployed_test_processor, job_id,
                                       a={'wrong': 55}, b=1)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 0
    assert job_result.exitcode == ExitCode.ERROR
    assert 'InvalidJSONDataObjectError' in job_result.trace


def test_cli_runner_success_by_reference(temp_dir, node, deployed_test_processor):
    # prepare input data objects
    a = prepare_data_object(os.path.join(temp_dir, 'a'), node, 1)
    b = prepare_data_object(os.path.join(temp_dir, 'b'), node, 1)

    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, node.identity, deployed_test_processor, job_id, a=a, b=b)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 100
    assert job_result.exitcode == ExitCode.DONE


def test_cli_runner_failing_no_access(temp_dir, node, deployed_test_processor, extra_keystores):
    user = extra_keystores[0]
    node.db.update_identity(user.identity)

    # prepare input data objects
    a = prepare_data_object(os.path.join(temp_dir, 'a'), node, 1, access=[node.identity])
    b = prepare_data_object(os.path.join(temp_dir, 'b'), node, 1, access=[node.identity])

    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, user.identity, deployed_test_processor, job_id, a=a, b=b)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 0
    assert job_result.exitcode == ExitCode.ERROR
    assert 'AccessNotPermittedError' in job_result.trace


def test_cli_runner_failing_no_signature(temp_dir, node, deployed_test_processor):
    # prepare input data objects
    a = prepare_data_object(os.path.join(temp_dir, 'a'), node, 1, access=[node.identity])
    b = prepare_data_object(os.path.join(temp_dir, 'b'), node, 1, access=[node.identity])

    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, node.identity, deployed_test_processor, job_id, a=a, b=b)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 0
    assert job_result.exitcode == ExitCode.ERROR
    assert 'MissingUserSignatureError' in job_result.trace


def test_cli_runner_failing_no_data_object(temp_dir, node, deployed_test_processor):
    # prepare input data objects
    a = prepare_data_object(os.path.join(temp_dir, 'a'), node, 1)
    b = prepare_data_object(os.path.join(temp_dir, 'b'), node, 1)

    # delete the object so it can't be found
    proxy = DORProxy(node.rest.address())
    proxy.delete_data_object(b.obj_id, node.keystore)

    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, node.identity, deployed_test_processor, job_id, a=a, b=b)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 0
    assert job_result.exitcode == ExitCode.ERROR
    assert 'UnresolvedInputDataObjectsError' in job_result.trace


def test_cli_runner_failing_wrong_data_type(temp_dir, node, deployed_test_processor):
    # prepare input data objects
    a = prepare_data_object(os.path.join(temp_dir, 'a'), node, 1, data_type='wrong')
    b = prepare_data_object(os.path.join(temp_dir, 'b'), node, 1)

    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, node.identity, deployed_test_processor, job_id, a=a, b=b)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 0
    assert job_result.exitcode == ExitCode.ERROR
    assert 'MismatchingDataTypeOrFormatError' in job_result.trace


def test_cli_runner_failing_wrong_data_format(temp_dir, node, deployed_test_processor):
    # prepare input data objects
    a = prepare_data_object(os.path.join(temp_dir, 'a'), node, 1, data_format='wrong')
    b = prepare_data_object(os.path.join(temp_dir, 'b'), node, 1)

    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, node.identity, deployed_test_processor, job_id, a=a, b=b)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 0
    assert job_result.exitcode == ExitCode.ERROR
    assert 'MismatchingDataTypeOrFormatError' in job_result.trace


def test_cli_runner_success_no_name(temp_dir, node, deployed_test_processor):
    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, node.identity, deployed_test_processor, job_id, a=1, b=1)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd_noname, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.progress == 100
    assert job_result.exitcode == ExitCode.DONE


def test_cli_runner_cancelled(temp_dir, node, deployed_test_processor):
    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, node.identity, deployed_test_processor, job_id, a=5, b=6)

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
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert job_result.exitcode == ExitCode.INTERRUPTED


def test_cli_runner_success_non_dor_target(temp_dir, node, exec_only_node, deployed_test_processor):
    # prepare input data objects
    a = prepare_data_object(os.path.join(temp_dir, 'a'), node, 1)
    b = prepare_data_object(os.path.join(temp_dir, 'b'), node, 1)

    # prepare the job folder
    job_id = '398h36g3'
    job_path = prepare_full_job_folder(temp_dir, node, node.identity, deployed_test_processor, job_id,
                                       a=a, b=b, target_node=exec_only_node)

    # determine REST address
    rest_address = PortMaster.generate_rest_address()

    # execute the job runner command
    job_process = multiprocessing.Process(target=run_job_cmd, args=(job_path, rest_address[0], rest_address[1]))
    job_process.start()

    # wait for the job to be finished
    job_result, status = wait_for_job_runner(job_path, rest_address)
    assert status.state == JobStatus.State.FAILED
    assert "Pushing output data object 'c' failed." in status.errors[0].message
    assert status.errors[0].exception.reason == 'Target node does not support DOR capabilities'
    assert job_result.exitcode == ExitCode.ERROR
