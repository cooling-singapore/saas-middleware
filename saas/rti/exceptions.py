from saas.exceptions import SaaSException


class RTIException(SaaSException):
    """
    Base exception class used for errors originating in the RTI subsystem.
    """


class UnexpectedGPPMetaInformation(RTIException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unexpected meta information for GPP data object', details=details)


class ProcessorNotDeployedError(RTIException):
    def __init__(self, details: dict) -> None:
        super().__init__('Processor not deployed', details=details)


class JobDescriptorNotFoundError(RTIException):
    def __init__(self, details: dict) -> None:
        super().__init__('Job descriptor not found', details=details)


class JobStatusNotFoundError(RTIException):
    def __init__(self, details: dict) -> None:
        super().__init__('Job status not found', details=details)


class GPPDataObjectNotFound(RTIException):
    def __init__(self, details: dict) -> None:
        super().__init__('GPP data object not found', details=details)


class ProcessorNotAcceptingJobsError(RTIException):
    def __init__(self, details: dict) -> None:
        super().__init__('Processor is not accepting job submissions (probably because it is shutting down)', details=details)


class UnresolvedInputDataObjectsError(RTIException):
    def __init__(self, details: dict) -> None:
        super().__init__('One or more input data object reference cannot be resolved', details=details)


class AccessNotPermittedError(RTIException):
    def __init__(self, details: dict) -> None:
        super().__init__('Identity does not have access to data object', details=details)


class MissingUserSignatureError(RTIException):
    def __init__(self, details: dict) -> None:
        super().__init__('Missing user signature for access to data object', details=details)

