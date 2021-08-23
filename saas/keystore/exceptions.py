class KeystoreException(Exception):
    pass


class InvalidAssetContentError(Exception):
    def __init__(self, content, schema):
        self.message = f"Asset content not compliant with json schema: content={content} schema={schema}."


class InvalidProtectedAssetContentError(Exception):
    def __init__(self, protected_property):
        self.message = f"Protected asset content property '{protected_property}' not found."

