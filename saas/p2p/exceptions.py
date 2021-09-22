from saas.exceptions import SaaSException


class P2PException(SaaSException):
    pass


class ReceiveDataError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Problem encountered while receiving data', details=details)


class SendDataError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Problem encountered while sending data', details=details)


class MalformedPreambleError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Preamble does not contain all the required elements', details=details)


class MismatchingBytesWrittenError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Unexpected number of bytes written', details=details)


class ResourceNotFoundError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Resource not found', details=details)


class DecodingJSONError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Problem encountered while decoding JSON object', details=details)


class EncodingJSONError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Problem encountered while decoding JSON object', details=details)


class HandshakeFailedError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Could not perform handshake', details=details)


class MalformedMessageError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Message does not contain all the required elements', details=details)


class UnexpectedMessageTypeError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Unexpected message type', details=details)


class UnsupportedProtocolError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Protocol not supported', details=details)


class MismatchingRequestIdError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Request ids do not match', details=details)


class PeerUnavailableError(P2PException):
    def __init__(self, details: dict) -> None:
        P2PException.__init__(self, 'Peer is not available', details=details)
