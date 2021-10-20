from saas.exceptions import SaaSException


class CryptographyException(SaaSException):
    """
    Base exception class used for errors originating in the cryptography subsystem.
    """


class NoPrivateKeyFoundError(CryptographyException):
    def __init__(self, details: dict = None) -> None:
        super().__init__('Key pair does not have a private key', details=details if details else {})



