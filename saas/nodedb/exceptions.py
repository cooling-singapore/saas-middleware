from saas.exceptions import SaaSException


class NodeDBException(SaaSException):
    """
    Base exception class used for errors originating in the NodeDB subsystem.
    """


class DataObjectNotFoundError(NodeDBException):
    def __init__(self, details: dict) -> None:
        super().__init__('Data object not found', details=details)


class InvalidIdentityError(NodeDBException):
    def __init__(self, details: dict) -> None:
        super().__init__('Identity is not valid', details=details)


class UnexpectedIdentityError(NodeDBException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unexpected identity encountered', details=details)
