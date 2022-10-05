from saas.exceptions import SaaSException


class KeystoreException(SaaSException):
    """
    Base exception class used for errors originating in the keystore module.
    """


class KeystoreCredentialsException(KeystoreException):
    def __init__(self, path: str, content: dict, schema: dict) -> None:
        super().__init__('Invalid keystore credentials format', details={
            'path': path,
            'content': content,
            'schema': schema
        })
