from saas.exceptions import SaaSException


class NodeDBException(SaaSException):
    pass


class DataObjectNotFoundError(NodeDBException):
    def __init__(self, details: dict) -> None:
        NodeDBException.__init__(self, 'Data object not found', details=details)


class DataObjectAlreadyExistsError(NodeDBException):
    def __init__(self, details: dict) -> None:
        NodeDBException.__init__(self, 'Data object already exists', details=details)


class RecordNotFoundError(NodeDBException):
    def __init__(self, details: dict) -> None:
        NodeDBException.__init__(self, 'NodeDB record not found', details=details)


class InvalidIdentityError(NodeDBException):
    def __init__(self, details: dict) -> None:
        NodeDBException.__init__(self, 'Identity is not valid', details=details)
