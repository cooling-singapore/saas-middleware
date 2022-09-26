import os
from typing import List, Optional, Dict

from pydantic import BaseModel
from saascore.log import Logging
from saascore.keystore.identity import Identity
from saascore.helpers import write_json_to_file

from saas.dor.exceptions import FetchDataObjectFailedError
from saas.dor.schemas import CDataObject, GPPDataObject
from saas.p2p.exceptions import AttachmentNotFoundError
from saas.p2p.protocol import P2PProtocol
from saas.schemas import GitProcessorPointer

logger = Logging.get('dor.protocol')


class LookupRequest(BaseModel):
    obj_ids: List[str]


class LookupResponse(BaseModel):
    records: Dict[str, dict]


class LookupGPPRequest(BaseModel):
    obj_id: str


class LookupGPPResponse(BaseModel):
    successful: bool
    meta: Optional[GPPDataObject]
    details: Optional[Dict]


class FetchRequest(BaseModel):
    obj_id: str
    user_iid: Optional[str]
    user_signature: Optional[str]


class FetchResponse(BaseModel):
    successful: bool
    meta: Optional[Dict]
    details: Optional[Dict]


class DataObjectRepositoryP2PProtocol(P2PProtocol):
    id = "data_object_repository"

    def __init__(self, node) -> None:
        super().__init__(node, DataObjectRepositoryP2PProtocol.id, [
            (LookupRequest, self._handle_lookup, LookupResponse),
            (LookupGPPRequest, self._handle_lookup_gpp, LookupGPPResponse),
            (FetchRequest, self._handle_fetch, FetchResponse)
        ])

    def lookup(self, peer_address: (str, int), obj_ids: List[str]) -> Dict[str, dict]:
        response, _, _ = self.request(peer_address, LookupRequest(obj_ids=obj_ids))
        return response.records

    def _handle_lookup(self, request: LookupRequest, _) -> LookupResponse:
        records = {obj_id: self.node.dor.get_meta(obj_id) for obj_id in request.obj_ids}
        return LookupResponse(records=records)

    def lookup_gpp(self, peer_address: (str, int), obj_id: str) -> Optional[GitProcessorPointer]:
        response, _, _ = self.request(peer_address, LookupGPPRequest(obj_id=obj_id))
        return response.meta.gpp if response.successful else None

    def _handle_lookup_gpp(self, request: LookupGPPRequest, _) -> LookupGPPResponse:
        # get the meta information for this object id
        meta = self.node.dor.get_meta(request.obj_id)
        if meta is None or isinstance(meta, CDataObject):
            return LookupGPPResponse(successful=False, details={
                'reason': 'object not found or not a GPP',
                'obj_id': request.obj_id,
                'meta': meta
            })

        # check if the user has access to the object
        if meta.access_restricted:
            return LookupGPPResponse(successful=False, details={
                'reason': 'access to this GPP is restricted',
                'obj_id': request.obj_id
            })

        return LookupGPPResponse(successful=True, meta=meta)

    def fetch(self, peer_address: (str, int), obj_id: str,
              destination_meta_path: str, destination_content_path: str,
              user_iid: str = None, user_signature: str = None) -> None:

        response, attachment, _ = self.request(peer_address, FetchRequest(obj_id=obj_id, user_iid=user_iid,
                                                                          user_signature=user_signature))

        # was the fetch attempt successful?
        if not response.successful:
            raise FetchDataObjectFailedError(details=response.details)

        # have we received an attachment?
        if not attachment or not os.path.isfile(attachment):
            raise AttachmentNotFoundError({
                'peer_address': peer_address,
                'obj_id': obj_id,
                'user_iid': user_iid,
                'user_signature': user_signature,
                'response': response.dict()
            })

        # write the data object descriptor to the destination path
        write_json_to_file(response.meta, destination_meta_path)

        # move the data object content to the destination path
        os.rename(attachment, destination_content_path)

    def _handle_fetch(self, request: FetchRequest, peer: Identity) -> (FetchResponse, str):
        # check if we have that data object
        meta = self.node.dor.get_meta(request.obj_id)
        if not meta:
            return FetchResponse(successful=False, details={
                'reason': 'object not found',
                'obj_id': request.obj_id
            })

        # check if the data object access is restricted and (if so) if the user has the required permission
        if meta.access_restricted:
            # get the identity of the user
            user = self.node.db.get_identity(request.user_iid)
            if user is None:
                return FetchResponse(successful=False, details={
                    'reason': 'identity of user not found',
                    'user_iid': request.user_iid
                })

            # check if the user has permission to access this data object
            if user.id not in meta.access:
                return FetchResponse(successful=False, details={
                    'reason': 'user does not have access',
                    'user_iid': request.user_iid,
                    'obj_id': request.obj_id
                })

            # verify the access request
            token = f"{peer.id}:{request.obj_id}".encode('utf-8')
            if not user.verify(token, request.user_signature):
                return FetchResponse(successful=False, details={
                    'reason': 'authorisation failed',
                    'user_iid': request.user_iid,
                    'obj_id': request.obj_id,
                    'token': token.decode('utf-8'),
                    'signature': request.user_signature
                })

        # we should have the data object content in our local DOR
        content_path = self.node.dor.obj_content_path(meta.c_hash)
        if not os.path.isfile(content_path):
            return FetchResponse(successful=False, details={
                'reason': 'data object content not found',
                'user_iid': request.user_iid,
                'obj_id': request.obj_id,
                'c_hash': meta.c_hash
            })

        # if all is good, send a reply with the meta information followed by the data object content as attachment
        return FetchResponse(successful=True, meta=meta), content_path
