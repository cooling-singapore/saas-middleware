from saascore.exceptions import SaaSException


class RESTException(SaaSException):
    """
    Base exception class used for errors originating in the REST subsystem.
    """


class UnsupportedRESTMethod(RESTException):
    def __init__(self, method: str, route: str) -> None:
        super().__init__('REST method not supported', details={
            'method': method,
            'route': route
        })
