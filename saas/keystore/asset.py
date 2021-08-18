import json

from saas.cryptography.keypair import KeyPair


def serialise(content: dict, protect_with: KeyPair = None, protected_properties: list = None) -> dict:
    # encrypt protected content (if applicable)
    content = dict(content)
    if protect_with and protected_properties:
        for p in protected_properties:
            if p in content:
                serialised = json.dumps(content[p]).encode('utf-8')
                content[p] = protect_with.encrypt(serialised, base64_encoded=True).decode('utf-8')

    return content


def deserialise(content: dict, protected_properties: list, master_key: KeyPair) -> dict:
    # decrypt protected content (if applicable)
    content = dict(content)
    for p in protected_properties:
        if p in content:
            serialised = master_key.decrypt(content[p].encode('utf-8'), base64_encoded=True)
            content[p] = json.loads(serialised.decode('utf-8'))

    return content


class Asset:
    def __init__(self, key: str) -> None:
        self._key = key

    @property
    def key(self):
        return self._key
    #     self._content = content
    #
    # @property
    # def content(self):
    #     return self._content

    # def _serialise(self, content: dict, protect_with: KeyPair = None, protected_properties: list = None) -> dict:
    #     content = dict(content)
    #
    #     # encrypt protected content (if applicable)
    #     if protect_with and protected_properties:
    #         for p in protected_properties:
    #             if p in content:
    #                 serialised = json.dumps(content[p]).encode('utf-8')
    #                 content[p] = protect_with.encrypt(serialised, base64_encoded=True).decode('utf-8')
    #
    #     return {
    #         'type': type(self).__name__,
    #         'key': self._key,
    #         'content': content
    #     }

    # def unlock(self, master_key: KeyPair, protected_property: str = 'protected') -> bool:
    #     # decrypt protected content (if applicable)
    #     if master_key and protected_property in self._content:
    #         serialised = master_key.decrypt(self._content[protected_property].encode('utf-8'), base64_encoded=True)
    #         self._content[protected_property] = json.loads(serialised.decode('utf-8'))
    #         return True
    #
    #     return False

    # def lock(self, master_key: KeyPair, locked_property: str = 'protected') -> str:
    #     # check if the property exists
    #     if locked_property not in self._content:
    #         raise InvalidProtectedAssetContentError(locked_property)
    #
    #     # serialise protected content and encrypt
    #     serialised = json.dumps(self._content[locked_property]).encode('utf-8')
    #     self._content[locked_property] = master_key.encrypt(serialised, base64_encoded=True).decode('utf-8')
    #
    #     return self._content[locked_property]
