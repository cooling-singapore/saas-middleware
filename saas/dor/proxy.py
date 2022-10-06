from typing import Union, Optional, List

from saas.dor.schemas import DORStatistics, DataObjectProvenance, DataObject, GPPDataObject, CDataObject
from saas.core.schemas import GithubCredentials
from saas.core.identity import Identity
from saas.core.keystore import Keystore
from saas.rest.proxy import EndpointProxy

DOR_ENDPOINT_PREFIX = "/api/v1/dor"


class DORProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int)):
        super().__init__(DOR_ENDPOINT_PREFIX, remote_address)

    def search(self, patterns: list[str] = None, owner_iid: str = None,
               data_type: str = None, data_format: str = None,
               c_hashes: list[str] = None) -> List[DataObject]:
        body = {}

        if patterns is not None and len(patterns) > 0:
            body['patterns'] = patterns

        if owner_iid is not None:
            body['owner_iid'] = owner_iid

        if data_type is not None:
            body['data_type'] = data_type

        if data_format is not None:
            body['data_format'] = data_format

        if c_hashes is not None:
            body['c_hashes'] = c_hashes

        results = self.get('', body=body)
        return [DataObject.parse_obj(result) for result in results]

    def statistics(self) -> DORStatistics:
        result = self.get('/statistics')
        return DORStatistics.parse_obj(result)

    def add_data_object(self, content_path: str, owner: Identity, access_restricted: bool, content_encrypted: bool,
                        data_type: str, data_format: str, creators: List[Identity] = None, recipe: dict = None,
                        license_by: bool = False, license_sa: bool = False, license_nc: bool = False,
                        license_nd: bool = False) -> CDataObject:
        body = {
            'owner_iid': owner.id,
            'creators_iid': [creator.id for creator in creators] if creators else [owner.id],
            'data_type': data_type,
            'data_format': data_format,
            'access_restricted': access_restricted,
            'content_encrypted': content_encrypted,
            'recipe': recipe if recipe else None,
            'license': {
                'by': license_by,
                'sa': license_sa,
                'nc': license_nc,
                'nd': license_nd
            }
        }

        result = self.post('/add-c', body=body, attachment_path=content_path)
        return CDataObject.parse_obj(result)

    def add_gpp_data_object(self, source: str, commit_id: str, proc_path: str, proc_config: str,
                            owner: Identity, creators: List[Identity] = None,
                            github_credentials: GithubCredentials = None) -> GPPDataObject:
        body = {
            'owner_iid': owner.id,
            'creators_iid': [creator.id for creator in creators] if creators else [owner.id],
            'source': source,
            'commit_id': commit_id,
            'proc_path': proc_path,
            'proc_config': proc_config,
            'github_credentials': {
                'login': github_credentials.login,
                'personal_access_token': github_credentials.personal_access_token
            } if github_credentials else None
        }

        result = self.post('/add-gpp', body=body)
        return GPPDataObject.parse_obj(result)

    def delete_data_object(self, obj_id: str,
                           with_authorisation_by: Keystore) -> Optional[Union[CDataObject, GPPDataObject]]:

        result = self.delete(f"/{obj_id}", with_authorisation_by=with_authorisation_by)
        if not result:
            return None

        if 'gpp' in result:
            return GPPDataObject.parse_obj(result)
        else:
            return CDataObject.parse_obj(result)

    def get_meta(self, obj_id: str) -> Optional[Union[CDataObject, GPPDataObject]]:
        result = self.get(f"/{obj_id}/meta")
        if not result:
            return None

        if 'gpp' in result:
            return GPPDataObject.parse_obj(result)
        else:
            return CDataObject.parse_obj(result)

    def get_content(self, obj_id: str, with_authorisation_by: Keystore, download_path: str) -> None:
        self.get(f"/{obj_id}/content", download_path=download_path, with_authorisation_by=with_authorisation_by)

    def get_provenance(self, c_hash: str) -> DataObjectProvenance:
        result = self.get(f"/{c_hash}/provenance")
        return DataObjectProvenance.parse_obj(result)

    def grant_access(self, obj_id: str, authority: Keystore, identity: Identity) -> Union[CDataObject, GPPDataObject]:
        result = self.post(f"/{obj_id}/access/{identity.id}", with_authorisation_by=authority)
        if 'gpp' in result:
            return GPPDataObject.parse_obj(result)
        else:
            return CDataObject.parse_obj(result)

    def revoke_access(self, obj_id: str, authority: Keystore, identity: Identity) -> Union[CDataObject, GPPDataObject]:
        result = self.delete(f"/{obj_id}/access/{identity.id}", with_authorisation_by=authority)
        if 'gpp' in result:
            return GPPDataObject.parse_obj(result)
        else:
            return CDataObject.parse_obj(result)

    def transfer_ownership(self, obj_id: str, authority: Keystore, new_owner: Identity) -> Union[CDataObject,
                                                                                                 GPPDataObject]:
        # TODO: reminder that the application layer is responsible to transfer the content_key to the new owner
        result = self.put(f"/{obj_id}/owner/{new_owner.id}", with_authorisation_by=authority)
        if 'gpp' in result:
            return GPPDataObject.parse_obj(result)
        else:
            return CDataObject.parse_obj(result)

    def update_tags(self, obj_id: str, authority: Keystore, tags: List[DataObject.Tag]) -> Union[CDataObject,
                                                                                                 GPPDataObject]:
        tags = [tag.dict() for tag in tags]

        result = self.put(f"/{obj_id}/tags", body=tags, with_authorisation_by=authority)
        if 'gpp' in result:
            return GPPDataObject.parse_obj(result)
        else:
            return CDataObject.parse_obj(result)

    def remove_tags(self, obj_id: str, authority: Keystore, keys: List[str]) -> Union[CDataObject, GPPDataObject]:
        result = self.delete(f"/{obj_id}/tags", body=keys, with_authorisation_by=authority)
        if 'gpp' in result:
            return GPPDataObject.parse_obj(result)
        else:
            return CDataObject.parse_obj(result)
