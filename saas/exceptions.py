from saas.helpers import generate_random_string


class SaaSException(Exception):
    def __init__(self):
        self._id = generate_random_string(16)

    @property
    def id(self):
        return self._id


class P2PMessengerException(SaaSException):
    pass


class PeerUnavailableError(P2PMessengerException):
    def __init__(self, address: (str, int)):
        self.address = address


class ConnectionBrokenError(P2PMessengerException):
    pass


class TransmissionError(P2PMessengerException):
    def __init__(self, info: dict):
        self._info = info


class HandshakeFailedError(P2PMessengerException):
    pass