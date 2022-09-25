import json
import os

from fastapi import Request
from saascore.api.sdk.exceptions import AuthorisationFailedError
from saascore.api.sdk.helpers import verify_authorisation_token
from saascore.keystore.identity import Identity

from saas.rti.exceptions import JobDescriptorNotFoundError, ProcessorNotDeployedError
from saas.schemas import JobDescriptor


class VerifyAuthorisation:
    def __init__(self, node):
        self.node = node

    async def __call__(self, request: Request) -> (Identity, dict):
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
                'reason': 'unknown identity',
                'iid': iid
            })

        # verify the signature
        signature = request.headers['saasauth-signature']
        body = await request.body()
        body = body.decode('utf-8')
        body = json.loads(body) if body != '' else {}
        if not verify_authorisation_token(identity, signature, f"{request.method}:{request.url}", body):
            raise AuthorisationFailedError({
                'reason': 'invalid signature',
                'iid': iid,
                'signature': signature
            })

        return identity, body


class VerifyIsOwner:
    def __init__(self, node):
        self.node = node

    async def __call__(self, obj_id: str, request: Request):
        identity, body = await VerifyAuthorisation(self.node).__call__(request)

        # get the meta information of the object
        meta = self.node.dor.get_meta(obj_id)
        if meta is None:
            raise AuthorisationFailedError({
                'reason': 'data object does not exist',
                'obj_id': obj_id
            })

        # check if the identity is the owner of that data object
        if meta.owner_iid != identity.id:
            raise AuthorisationFailedError({
                'reason': 'user is not the data object owner',
                'obj_id': obj_id,
                'user_iid': identity.id
            })


class VerifyUserHasAccess:
    def __init__(self, node):
        self.node = node

    async def __call__(self, obj_id: str, request: Request):
        identity, body = await VerifyAuthorisation(self.node).__call__(request)

        # get the meta information of the object
        meta = self.node.dor.get_meta(obj_id)
        if meta is None:
            raise AuthorisationFailedError({
                'reason': 'data object does not exist',
                'obj_id': obj_id
            })

        # check if the identity has access to the data object content
        if identity.id not in meta.access:
            raise AuthorisationFailedError({
                'reason': 'user has no access to the data object content',
                'obj_id': obj_id,
                'user_iid': identity.id
            })


class VerifyProcessorDeployed:
    def __init__(self, node):
        self.node = node

    async def __call__(self, proc_id: str):
        # is the processor already deployed?
        for deployed in self.node.rti.deployed():
            if deployed.proc_id == proc_id:
                return

        raise ProcessorNotDeployedError({
            'proc_id': proc_id
        })


class VerifyUserIsJobOwner:
    def __init__(self, node):
        self.node = node

    async def __call__(self, job_id: str, request: Request):
        identity, _ = await VerifyAuthorisation(self.node).__call__(request)

        # does the descriptor exist?
        descriptor_path = self.node.rti.job_descriptor_path(job_id)
        if not os.path.isfile(descriptor_path):
            raise JobDescriptorNotFoundError({
                'job_id': job_id
            })

        with open(descriptor_path, 'r') as f:
            descriptor = JobDescriptor.parse_obj(json.load(f))

            if descriptor.owner_iid != identity.id:
                raise AuthorisationFailedError({
                    'reason': 'user is not the job owner',
                    'job_id': job_id,
                    'user_iid': identity.id,
                    'owner_iid': descriptor.owner_iid
                })
