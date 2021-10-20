from saas.exceptions import SaaSException


class KeystoreException(SaaSException):
    """
    Base exception class used for errors originating in the NodeDB subsystem.
    """


class InvalidAssetContentError(KeystoreException):
    def __init__(self, content, schema):
        self.message = f"Asset content not compliant with json schema: content={content} schema={schema}."


class InvalidProtectedAssetContentError(KeystoreException):
    def __init__(self, protected_property):
        self.message = f"Protected asset content property '{protected_property}' not found."

