from saas import helpers


class SaaSException(Exception):
    def __init__(self, reason: str, details: dict = None):
        self._reason = reason
        self._details = details
        self._id = helpers.generate_random_string(16)

    @property
    def reason(self):
        return self._reason

    @property
    def details(self):
        return self._details

    @property
    def id(self):
        return self._id


class DORServiceNotSupportedError(SaaSException):
    def __init__(self) -> None:
        super().__init__('DOR service is not supported by node')


class RTIServiceNotSupportedError(SaaSException):
    def __init__(self) -> None:
        super().__init__('RTI service is not supported by node')


class RunCommandError(SaaSException):
    def __init__(self, details: dict, reason: str = 'Error while running command') -> None:
        super().__init__(reason, details=details)


class RunCommandTimeoutError(RunCommandError):
    def __init__(self, details: dict) -> None:
        super().__init__(details=details, reason='Timeout while running command')


class UnexpectedHTTPError(SaaSException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unexpected HTTP error encountered', details=details)


class MalformedRequestError(SaaSException):
    def __init__(self, details: dict) -> None:
        super().__init__('Malformed request message', details=details)


class MalformedResponseError(SaaSException):
    def __init__(self, details: dict) -> None:
        super().__init__('Malformed response message', details=details)


class UnsuccessfulRequestError(SaaSException):
    def __init__(self, reason: str, exception_id: str, details: dict) -> None:
        super().__init__(f"Unsuccessful request: {reason} ({exception_id})", details=details)


class AuthorisationFailedError(SaaSException):
    def __init__(self, details: dict) -> None:
        super().__init__('Authorisation failed', details=details)


class UnexpectedContentType(SaaSException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unexpected content type', details=details)


class MissingResponseSchemaError(SaaSException):
    def __init__(self, details: dict) -> None:
        super().__init__('Response schema is missing', details=details)


class UnsuccessfulConnectionError(SaaSException):
    def __init__(self, url: str, details: dict = None) -> None:
        super().__init__(f"Cannot establish connection to '{url}'", details=details)
