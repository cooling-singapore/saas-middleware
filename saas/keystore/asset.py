import json
from copy import copy

from saas.cryptography.keypair import KeyPair


def serialise(content: dict, protect_with: KeyPair = None, protected_properties: list = None) -> dict:
    # encrypt protected content (if applicable)
    content = copy(content)
    if protect_with and protected_properties:
        for p in protected_properties:
            if p in content:
                serialised = json.dumps(content[p]).encode('utf-8')
                content[p] = protect_with.encrypt(serialised, base64_encoded=True).decode('utf-8')

    return content


def deserialise(content: dict, protected_properties: list, master_key: KeyPair) -> dict:
    # decrypt protected content (if applicable)
    content = copy(content)
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