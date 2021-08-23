keystore_asset_schema = {
    'type': 'object',
    'properties': {
        'type': {'type': 'string'},
        'key': {'type': 'string'},
        'content': {'type': 'object'},
    },
    'required': ['type', 'key', 'content']
}

keystore_profile_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string'},
        'email': {'type': 'string'},
        'notes': {'type': 'string'}
    },
    'required': ['name', 'email', 'notes']
}

keystore_schema = {
    'type': 'object',
    'properties': {
        'iid': {'type': 'string'},
        'profile': keystore_profile_schema,
        'assets': {
            'type': 'array',
            'items': keystore_asset_schema
        },
        'nonce': {'type': 'number'},
        'signature': {'type': 'string'}
    },
    'required': ['iid', 'profile', 'assets', 'nonce', 'signature']
}

identity_schema = {
    'type': 'object',
    'properties': {
        'iid': {'type': 'string'},
        'name': {'type': 'string'},
        'email': {'type': 'string'},
        's_public_key': {'type': 'string'},
        'e_public_key': {'type': 'string'},
        'nonce': {'type': 'number'},
        'signature': {'type': 'string'}
    },
    'required': ['iid', 'name', 'email', 's_public_key', 'e_public_key', 'nonce', 'signature']
}
