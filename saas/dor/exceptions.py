from saas.core.exceptions import SaaSRuntimeException


class DORException(SaaSRuntimeException):
    """
    Base exception class used for errors originating in the DOR subsystem.
    """


class DataObjectNotFoundError(DORException):
    def __init__(self, obj_id) -> None:
        super().__init__('Data object not found', details={
            'obj_id': obj_id
        })


class DataObjectContentNotFoundError(DORException):
    def __init__(self, details: dict) -> None:
        super().__init__('Data object content not found', details=details)


class ProcessorDescriptorNotFoundError(DORException):
    def __init__(self, details: dict) -> None:
        super().__init__('Processor descriptor not found', details=details)


class InvalidProcessorDescriptorError(DORException):
    def __init__(self, details: dict) -> None:
        super().__init__('Processor descriptor not valid', details=details)


class CloneRepositoryError(DORException):
    def __init__(self, details: dict) -> None:
        super().__init__('Error encountered while trying to clone repository', details=details)


class CheckoutCommitError(DORException):
    def __init__(self, details: dict) -> None:
        super().__init__('Error encountered while trying to checkout commit', details=details)


class FetchDataObjectFailedError(DORException):
    def __init__(self, details: dict) -> None:
        super().__init__('Data object could not be fetched', details=details)
