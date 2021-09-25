from saas.helpers import generate_random_string


class SaaSException(Exception):
    def __init__(self, reason: str, details: dict = None):
        self._reason = reason
        self._details = details
        self._id = generate_random_string(16)

    @property
    def reason(self):
        return self._reason

    @property
    def details(self):
        return self._details

    @property
    def id(self):
        return self._id


# TODO: the following exception classes will have to be moved to their corresponding module eventually

class NodeDBException(SaaSException):
    pass


class InvalidSignatureError(SaaSException):
    pass