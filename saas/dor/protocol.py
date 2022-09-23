import os
from typing import List, Optional, Dict

from pydantic import BaseModel
from saascore.log import Logging
from saascore.keystore.identity import Identity
from saascore.helpers import write_json_to_file

from saas.dor.exceptions import FetchDataObjectFailedError
from saas.dor.schemas import DataObject
from saas.p2p.exceptions import AttachmentNotFoundError
from saas.p2p.protocol import P2PProtocol, P2PMessage

logger = Logging.get('dor.protocol')


class LookupRequest(BaseModel):
    obj_ids: List[str]
    user_iid: Optional[str]


class LookupResponse(BaseModel):
    class LookupRecord(DataObject):
        user_has_access: Optional[bool]

    successful: bool
    records: Optional[Dict[str, LookupRecord]]
    reason: Optional[str]
    user_iid: Optional[str]


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
        super().__init__(node, DataObjectRepositoryP2PProtocol.id, {
            'lookup': (self._handle_lookup, LookupRequest),
            'fetch': (self._handle_fetch, FetchRequest)
        })

    def lookup(self, peer_address: (str, int), obj_ids: List[str], user: Identity = None) -> LookupResponse:
        result, _ = self.request(peer_address, self.prepare_message("lookup", LookupRequest.parse_obj({
            'obj_ids': obj_ids,
            'user_iid': user.id if user else None
        })))

        result = LookupResponse.parse_obj(result.content)
        return result

    def _handle_lookup(self, request: LookupRequest, _) -> P2PMessage:
        # get the records for all the objects
        records = {}
        for obj_id in request.obj_ids:
            # do we have a record for this data object?
            record = self.node.db.get_object_by_id(obj_id)
            if record is not None:
                records[obj_id] = record

        # if we have a user id, then we need to check if this user has access to the objects
        if request.user_iid and len(records) > 0:
            # do we have an identity for the user?
            user = self.node.db.get_identity(request.user_iid, raise_if_unknown=False)
            if user is None:
                return self.prepare_message('lookup_response', LookupResponse.parse_obj({
                    'successful': False,
                    'reason': 'identity of user not found',
                    'user_iid': request.user_iid
                }))

            # check for every object
            for obj_id, record in records.items():
                record['user_has_permission'] = self.node.db.has_access(obj_id, user)

        return self.prepare_message('lookup_response', LookupResponse.parse_obj({
            'successful': True,
            'records': records
        }))

    def fetch(self, peer_address: (str, int), obj_id: str,
              destination_meta_path: str, destination_content_path: str,
              user_iid: str = None, user_signature: str = None) -> None:

        response, _ = self.request(peer_address, self.prepare_message("fetch", FetchRequest.parse_obj({
            'obj_id': obj_id,
            'user_iid': user_iid,
            'user_signature': user_signature
        })))

        # was the fetch attempt successful?
        payload = FetchResponse.parse_obj(response.content)
        if not payload.successful:
            raise FetchDataObjectFailedError({
                'peer_address': peer_address,
                'obj_id': obj_id,
                'user_iid': user_iid,
                'user_signature': user_signature,
                'response': response
            })

        # have we received an attachment?
        if not response.attachment or not os.path.isfile(response.attachment):
            raise AttachmentNotFoundError({
                'peer_address': peer_address,
                'obj_id': obj_id,
                'user_iid': user_iid,
                'user_signature': user_signature,
                'response': response.dict()
            })

        # write the data object descriptor to the destination path
        write_json_to_file(payload.meta, destination_meta_path)

        # move the data object content to the destination path
        os.rename(response.attachment, destination_content_path)

    def _handle_fetch(self, request: FetchRequest, peer: Identity) -> P2PMessage:
        # check if we have that data object
        obj_id = request.obj_id
        obj_record = self.node.dor.get_meta(obj_id)
        if not obj_record:
            return self.prepare_message('fetch_data_object_response', FetchResponse.parse_obj({
                'successful': False,
                'details': {
                    'reason': 'object not found',
                    'obj_id': obj_id
                }
            }))

        # check if the data object access is restricted and (if so) if the user has the required permission
        if obj_record.access_restricted:
            # get the identity of the user
            user = self.node.db.get_identity(request.user_iid)
            if user is None:
                return self.prepare_message('fetch_data_object_response', FetchResponse.parse_obj({
                    'successful': False,
                    'details': {
                        'reason': 'identity of user not found',
                        'user_iid': request.user_iid
                    }
                }))

            # check if the user has permission to access this data object
            if user.id not in obj_record.access:
                return self.prepare_message('fetch_data_object_response', FetchResponse.parse_obj({
                    'successful': False,
                    'details': {
                        'reason': 'user does not have access',
                        'user_iid': request.user_iid,
                        'object_id': obj_id
                    }
                }))

            # verify the access request
            token = f"{peer.id}:{obj_id}".encode('utf-8')
            if not user.verify(token, request.user_signature):
                return self.prepare_message('fetch_data_object_response', FetchResponse.parse_obj({
                    'successful': False,
                    'details': {
                        'reason': 'authorisation failed',
                        'user_iid': request.user_iid,
                        'object_id': obj_id,
                        'token': token.decode('utf-8'),
                        'signature': request.user_signature
                    }
                }))

        # we should have the data object content in our local DOR
        content_path = self.node.dor.obj_content_path(obj_record.c_hash)
        if not os.path.isfile(content_path):
            return self.prepare_message('fetch_data_object_response', FetchResponse.parse_obj({
                'successful': False,
                'details': {
                    'reason': 'data object content not found',
                    'user_iid': request.user_iid,
                    'object_id': obj_id,
                    'c_hash': obj_record.c_hash
                }
            }))

        # if all is good, send a reply with the meta information followed by the data object content as attachment
        record = self.node.dor.get_meta(obj_id)
        return self.prepare_message('fetch_data_object_response', FetchResponse.parse_obj({
            'successful': True,
            'meta': record.dict()
        }), content_path)
