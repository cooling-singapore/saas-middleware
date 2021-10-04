import saas.helpers as helpers


class SaaSException(Exception):
    def __init__(self, reason: str, details: dict = None):
        self._reason = reason
        self._details = details
        self._id = helpers.generate_random_string(16)

    @property
    def reason(self):
        return self._reason

    @property
    def details(self):
        return self._details

    @property
    def id(self):
        return self._id


class DORServiceNotSupportedError(SaaSException):
    def __init__(self) -> None:
        super().__init__('DOR service is not supported by node')


class RTIServiceNotSupportedError(SaaSException):
    def __init__(self) -> None:
        super().__init__('RTI service is not supported by node')


class RunCommandError(SaaSException):
    def __init__(self, details: dict) -> None:
        super().__init__('Error while running command', details=details)
