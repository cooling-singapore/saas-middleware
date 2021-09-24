from saas.exceptions import SaaSException


class RESTException(SaaSException):
    """
    Base exception class used for errors originating in the REST subsystem.
    """


class UnexpectedHTTPError(RESTException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unexpected HTTP error encountered', details=details)


class MalformedRequestError(RESTException):
    def __init__(self, details: dict) -> None:
        super().__init__('Malformed request message', details=details)


class EndpointNotSupportedError(RESTException):
    def __init__(self, details: dict) -> None:
        super().__init__('Endpoint not supported', details=details)


class MalformedResponseError(RESTException):
    def __init__(self, details: dict) -> None:
        super().__init__('Malformed response message', details=details)


class UnsuccessfulRequestError(RESTException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unsuccessful request', details=details)


class AuthorisationFailedError(RESTException):
    def __init__(self, details: dict) -> None:
        super().__init__('Authorisation failed', details=details)


class UnexpectedContentType(RESTException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unexpected content type', details=details)
