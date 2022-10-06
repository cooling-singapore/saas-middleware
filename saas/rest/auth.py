import json
import os
import time

from fastapi import Request

from saas.core.helpers import hash_string_object, hash_json_object, hash_bytes_object
from saas.core.identity import Identity
from saas.rest.exceptions import AuthorisationFailedError
from saas.rti.exceptions import JobDescriptorNotFoundError, ProcessorNotDeployedError
from saas.rti.schemas import Job


def verify_authorisation_token(identity: Identity, signature: str, url: str, body: dict = None,
                               precision: int = 5) -> bool:
    # determine time slots (we allow for some variation before and after)
    ref = int(time.time() / precision)
    slots = [ref - 1, ref, ref + 1]

    # generate the token for each time slot and check if for one the signature is valid.
    for slot in slots:
        # logger.info("verify_authorisation_token\tH(url)={}".format(hash_json_object(url).hex()))
        token = hash_string_object(url).hex()

        if body:
            # logger.info("verify_authorisation_token\tH(body)={}".format(hash_json_object(body).hex()))
            token += hash_json_object(body).hex()

        # logger.info("verify_authorisation_token\tH(bytes(slot))={}".format(hash_bytes_object(bytes(slot)).hex()))
        token += hash_bytes_object(bytes(slot)).hex()

        # logger.info("verify_authorisation_token\tH(self.public_as_string())={}".format(
        #     hash_string_object(self.public_as_string()).hex()))
        token += hash_string_object(identity.s_public_key).hex()

        token = hash_string_object(token)
        # logger.info("verify_authorisation_token\ttoken={}".format(token.hex()))

        if identity.verify(token, signature):
            return True

    # no valid signature for any of the eligible timeslots
    return False


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
            job = Job.parse_obj(json.load(f))

            if job.task.user_iid != identity.id:
                raise AuthorisationFailedError({
                    'reason': 'user is not the job owner',
                    'job_id': job_id,
                    'user_iid': identity.id,
                    'owner_iid': job.task.user_iid
                })
