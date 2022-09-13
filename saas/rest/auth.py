import json

from fastapi import Request
from saascore.api.sdk.exceptions import AuthorisationFailedError
from saascore.api.sdk.helpers import verify_authorisation_token
from saascore.keystore.identity import Identity


class VerifyAuthorisation:
    def __init__(self, node):
        self.node = node

    async def __call__(self, request: Request):
        # check if there is the required saasauth header information
        if 'saasauth-iid' not in request.headers or 'saasauth-signature' not in request.headers:
            raise AuthorisationFailedError({
                'reason': 'saasauth information missing',
                'header_keys': list(request.headers.keys())
            })

        # check if the node knows about the identity
        iid = request.headers['saasauth-iid']
        identity: Identity = self.node.db.get_identity(iid)
        if identity is None:
            raise AuthorisationFailedError({
                'reason': 'identity not known to node',
                'iid': iid
            })

        # verify the signature
        signature = request.headers['saasauth-signature']
        body = await request.body()
        body = json.loads(body.decode('utf-8'))
        if not verify_authorisation_token(identity, signature, f"{request.method}:{request.url}", body):
            raise AuthorisationFailedError({
                'reason': 'authorisation failed',
                'iid': iid,
                'signature': signature
            })
