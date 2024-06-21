from __future__ import annotations

from typing import Optional, List, Tuple

from saas.dor.schemas import DORStatistics, DataObjectProvenance, DataObject
from saas.core.identity import Identity
from saas.core.keystore import Keystore
from saas.rest.proxy import EndpointProxy, Session, get_proxy_prefix

DOR_ENDPOINT_PREFIX = "/api/v1/dor"


class DORProxy(EndpointProxy):
    @classmethod
    def from_session(cls, session: Session) -> DORProxy:
        return DORProxy(remote_address=session.address, credentials=session.credentials,
                        endpoint_prefix=(session.endpoint_prefix_base, 'dor'))

    def __init__(self, remote_address: (str, int), credentials: (str, str) = None,
                 endpoint_prefix: Tuple[str, str] = get_proxy_prefix(DOR_ENDPOINT_PREFIX)):
        super().__init__(endpoint_prefix, remote_address, credentials=credentials)

    def search(self, patterns: list[str] = None, owner_iid: str = None,
               data_type: str = None, data_format: str = None,
               c_hashes: list[str] = None) -> List[DataObject]:
        body = {
            'patterns': patterns if patterns is not None and len(patterns) > 0 else None,
            'owner_iid': owner_iid,
            'data_type': data_type,
            'data_format': data_format,
            'c_hashes': c_hashes
        }

        results = self.get('', body=body)
        return [DataObject.parse_obj(result) for result in results]

    def statistics(self) -> DORStatistics:
        result = self.get('statistics')
        return DORStatistics.parse_obj(result)

    def add_data_object(self, content_path: str, owner: Identity, access_restricted: bool, content_encrypted: bool,
                        data_type: str, data_format: str, creators: List[Identity] = None, recipe: dict = None,
                        tags: List[DataObject.Tag] = None, license_by: bool = False, license_sa: bool = False,
                        license_nc: bool = False, license_nd: bool = False) -> DataObject:
        body = {
            'owner_iid': owner.id,
            'creators_iid': [creator.id for creator in creators] if creators else [owner.id],
            'data_type': data_type,
            'data_format': data_format,
            'access_restricted': access_restricted,
            'content_encrypted': content_encrypted,
            'license': {
                'by': license_by,
                'sa': license_sa,
                'nc': license_nc,
                'nd': license_nd
            },
            'recipe': recipe if recipe else None,
            'tags': {tag.key: tag.value for tag in tags} if tags else None
        }

        result = self.post('add', body=body, attachment_path=content_path)
        return DataObject.parse_obj(result)

    def delete_data_object(self, obj_id: str, with_authorisation_by: Keystore) -> Optional[DataObject]:
        result = self.delete(f"{obj_id}", with_authorisation_by=with_authorisation_by)
        return DataObject.parse_obj(result) if result else None

    def get_meta(self, obj_id: str) -> Optional[DataObject]:
        result = self.get(f"{obj_id}/meta")
        return DataObject.parse_obj(result) if result else None

    def get_content(self, obj_id: str, with_authorisation_by: Keystore, download_path: str) -> None:
        self.get(f"{obj_id}/content", download_path=download_path, with_authorisation_by=with_authorisation_by)

    def get_provenance(self, c_hash: str) -> DataObjectProvenance:
        result = self.get(f"{c_hash}/provenance")
        return DataObjectProvenance.parse_obj(result)

    def grant_access(self, obj_id: str, authority: Keystore, identity: Identity) -> DataObject:
        result = self.post(f"{obj_id}/access/{identity.id}", with_authorisation_by=authority)
        return DataObject.parse_obj(result)

    def revoke_access(self, obj_id: str, authority: Keystore, identity: Identity) -> DataObject:
        result = self.delete(f"{obj_id}/access/{identity.id}", with_authorisation_by=authority)
        return DataObject.parse_obj(result)

    def transfer_ownership(self, obj_id: str, authority: Keystore, new_owner: Identity) -> DataObject:
        # TODO: reminder that the application layer is responsible to transfer the content_key to the new owner
        result = self.put(f"{obj_id}/owner/{new_owner.id}", with_authorisation_by=authority)
        return DataObject.parse_obj(result)

    def update_tags(self, obj_id: str, authority: Keystore, tags: List[DataObject.Tag]) -> DataObject:
        tags = [tag.dict() for tag in tags]

        result = self.put(f"{obj_id}/tags", body=tags, with_authorisation_by=authority)
        return DataObject.parse_obj(result)

    def remove_tags(self, obj_id: str, authority: Keystore, keys: List[str]) -> DataObject:
        result = self.delete(f"{obj_id}/tags", body=keys, with_authorisation_by=authority)
        return DataObject.parse_obj(result)
