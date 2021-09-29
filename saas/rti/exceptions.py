from saas.exceptions import SaaSException
from saas.schemas import processor_descriptor_schema


class RTIException(SaaSException):
    """
    Base exception class used for errors originating in the RTI subsystem.
    """
