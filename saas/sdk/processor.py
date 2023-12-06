import abc
import importlib
import inspect
import logging
import os
import threading

from importlib.util import spec_from_file_location
from typing import Dict

from saas.core.exceptions import ExceptionContent
from saas.core.helpers import generate_random_string
from saas.core.logging import Logging
from saas.dor.schemas import ProcessorDescriptor
from saas.rti.schemas import Severity

logger = Logging.get(__name__)


class ProcessorRuntimeError(Exception):
    def __init__(self, reason: str, details: dict = None, ex_id: int = None):
        self._content = ExceptionContent(id=ex_id if ex_id else generate_random_string(16),
                                         reason=reason,
                                         details=details)

    @property
    def id(self):
        return self._content.id

    @property
    def reason(self):
        return self._content.reason

    @property
    def details(self):
        return self._content.details

    @property
    def content(self) -> ExceptionContent:
        return self._content


class ProgressListener(abc.ABC):
    @abc.abstractmethod
    def on_progress_update(self, progress: float) -> None:
        pass

    @abc.abstractmethod
    def on_output_available(self, output_name: str) -> None:
        pass

    @abc.abstractmethod
    def on_message(self, severity: Severity, message: str) -> None:
        pass


class ProcessorBase(abc.ABC):
    def __init__(self, proc_path: str) -> None:
        self._mutex = threading.Lock()
        self._proc_path = proc_path
        self._descriptor = ProcessorDescriptor.parse_file(os.path.join(proc_path, 'descriptor.json'))

    @property
    def path(self) -> str:
        return self._proc_path

    @property
    def name(self) -> str:
        return self._descriptor.name

    @property
    def descriptor(self) -> ProcessorDescriptor:
        return self._descriptor

    @abc.abstractmethod
    def run(self, wd_path: str, listener: ProgressListener, logger: logging.Logger) -> None:
        pass

    @abc.abstractmethod
    def interrupt(self) -> None:
        pass


def find_processors(search_path: str) -> Dict[str, ProcessorBase]:
    result = {}
    for root, dirs, files in os.walk(search_path):
        for file in files:
            if file.endswith(".py"):
                module_path = os.path.join(root, file)
                module_name = os.path.splitext(os.path.basename(module_path))[0]

                spec = importlib.util.spec_from_file_location(module_name, module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and obj != ProcessorBase and issubclass(obj, ProcessorBase):
                        try:
                            instance: ProcessorBase = obj(root)
                            result[instance.name] = instance
                        except Exception as e:
                            logger.warning(f"creating instance of {obj} failed: {e}")

    return result
