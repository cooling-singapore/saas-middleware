from saas.exceptions import SaaSException


class CLIException(SaaSException):
    """
    Base exception class used for errors originating in the CLI subsystem.
    """


class CLIRuntimeError(CLIException):
    def __init__(self, reason: str, details: dict = None) -> None:
        super().__init__(reason, details=details)
