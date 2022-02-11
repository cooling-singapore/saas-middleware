from saascore.exceptions import SaaSException


class RESTException(SaaSException):
    """
    Base exception class used for errors originating in the REST subsystem.
    """
