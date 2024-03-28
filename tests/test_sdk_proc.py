import os
import tempfile
import threading
import time

import pytest

from examples.adapters.proc_example.processor import write_value
from saas.core.helpers import get_timestamp_now
from saas.core.logging import Logging
from saas.sdk.processor import find_processors, ProgressListener, Severity

logger = Logging.get(__name__)


@pytest.fixture(scope="function")
def temp_dir():
    with tempfile.TemporaryDirectory() as tempdir:
        yield tempdir


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
