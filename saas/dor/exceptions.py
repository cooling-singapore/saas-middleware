from saas.exceptions import SaaSException
from saas.schemas import processor_descriptor_schema


class DORException(SaaSException):
    """
    Base exception class used for errors originating in the DOR subsystem.
    """


class DataObjectNotFoundError(DORException):
    def __init__(self, obj_id) -> None:
        super().__init__('Data object not found', details={
            'obj_id': obj_id
        })


class DataObjectDescriptorNotFoundError(DORException):
    def __init__(self, path: str) -> None:
        super().__init__('Data object descriptor not found', details={
            'path': path
        })


class InvalidDataObjectDescriptorError(DORException):
    def __init__(self, descriptor: str) -> None:
        super().__init__('Data object descriptor is not valid', details={
            'descriptor': descriptor,
            'schema': processor_descriptor_schema
        })


class DataObjectContentNotFoundError(DORException):
    def __init__(self, details: dict) -> None:
        super().__init__('Data object content not found', details=details)


class IdentityNotFoundError(DORException):
    def __init__(self, iid: str) -> None:
        super().__init__('Identity not found', details={
            'iid': iid
        })


class OwnerIdentityNotFoundError(DORException):
    def __init__(self, obj_id: str, owner_iid: str) -> None:
        super().__init__('Owner identity not found', details={
            'obj_id': obj_id,
            'owner_iid': owner_iid
        })


class CloneRepositoryError(DORException):
    def __init__(self, details: dict) -> None:
        super().__init__('Error encountered while trying to clone repository', details=details)


class CheckoutCommitError(DORException):
    def __init__(self, details: dict) -> None:
        super().__init__('Error encountered while trying to checkout commit', details=details)


class FetchDataObjectFailedError(DORException):
    def __init__(self, details: dict) -> None:
        super().__init__('Data object could not be fetched', details=details)



