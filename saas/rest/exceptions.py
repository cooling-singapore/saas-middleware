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


class MissingResponseSchemaError(RESTException):
    def __init__(self, details: dict) -> None:
        super().__init__('Response schema is missing', details=details)


class UnsuccessfulConnectionError(RESTException):
    def __init__(self, url: str, details: dict = None) -> None:
        super().__init__(f"Cannot establish connection to '{url}'", details=details)
