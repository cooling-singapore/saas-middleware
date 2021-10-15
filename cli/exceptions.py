from saas.exceptions import SaaSException


class CLIException(SaaSException):
    """
    Base exception class used for errors originating in the CLI subsystem.
    """


class CLIRuntimeErrorWrapper(CLIException):
    def __init__(self, e: SaaSException) -> None:
        super().__init__(f"Error while executing CLI command. Aborting. Hint: {e.reason} {e.id}", details=e.details)


class CLIRuntimeError(CLIException):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
