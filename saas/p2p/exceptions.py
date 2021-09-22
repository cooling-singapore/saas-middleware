from saas.exceptions import SaaSException


class P2PException(SaaSException):
    pass


class P2PMessengerError(P2PException):
    pass


class ReceiveDataError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Problem encountered while receiving data', details=details)


class SendDataError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Problem encountered while sending data', details=details)


class MalformedPreambleError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Preamble does not contain all the required elements', details=details)


class MismatchingBytesWrittenError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Unexpected number of bytes written', details=details)


class ResourceNotFoundError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Resource not found', details=details)


class DecodingJSONError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Problem encountered while decoding JSON object', details=details)


class EncodingJSONError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Problem encountered while decoding JSON object', details=details)


class HandshakeFailedError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Could not perform handshake', details=details)


class MalformedMessageError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Message does not contain all the required elements', details=details)


class UnexpectedMessageTypeError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Unexpected message type', details=details)


class MismatchingRequestIdError(P2PMessengerError):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Request ids do not match', details=details)


class PeerUnavailableError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PMessengerError.__init__(self, 'Peer is not available', details=details)


class P2PMessengerError(SaaSException):
    pass


class P2PProtocolError(SaaSException):
    pass

