from saas.core.exceptions import SaaSRuntimeException


class P2PException(SaaSRuntimeException):
    """
    Base exception class used for errors originating in the P2P subsystem.
    """


class ReceiveDataError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Problem encountered while receiving data', details=details)


class SendDataError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Problem encountered while sending data', details=details)


class MalformedPreambleError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Preamble does not contain all the required elements', details=details)


class MismatchingBytesWrittenError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unexpected number of bytes written', details=details)


class ResourceNotFoundError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Resource not found', details=details)


class DecodingJSONError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Problem encountered while decoding JSON object', details=details)


class EncodingJSONError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Problem encountered while decoding JSON object', details=details)


class HandshakeFailedError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Could not perform handshake', details=details)


class MalformedMessageError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Message does not contain all the required elements', details=details)


class UnexpectedMessageTypeError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unexpected message type', details=details)


class UnsupportedProtocolError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Protocol not supported', details=details)


class MismatchingRequestIdError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Request ids do not match', details=details)


class PeerUnavailableError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Peer is not available', details=details)


class BootNodeUnavailableError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Boot node is not available', details=details)


class AttachmentNotFoundError(P2PException):
    def __init__(self, details: dict) -> None:
        super().__init__('Attachment expected but not found', details=details)
