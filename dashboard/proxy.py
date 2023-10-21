from typing import List, Union

from saas.dor.schemas import CDataObject, GPPDataObject, DataObject, GPP_DATA_TYPE
from saas.rest.proxy import EndpointProxy
from saas.rti.schemas import Processor, Task, Job
from saas.sdk.app.auth import User

from dashboard import schemas


endpoint_prefix_base = "/dashboard/v1"


class DashboardProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int), user: User, password: str):
        super().__init__((endpoint_prefix_base, None), remote_address, (user.login, password))

        self._authority = user.keystore

    def get_processors(self) -> List[Processor]:
        results = self.get("processors")
        return [Processor.parse_obj(result) for result in results]

    def submit_job(self, name: str, description: str, proc_id: str,
                   job_input: List[Union[Task.InputValue, Task.InputReference]], job_output: List[Task.Output]) -> Job:

        p = {
            'name': name,
            'description': description,
            'proc_id': proc_id,
            'input': [{
                'name': item.name,
                'content': item.obj_id if isinstance(item, Task.InputReference) else item.value
            } for item in job_input],
            'output': [{
                'name': item.name,
                'restricted_access': item.restricted_access,
                'content_encrypted': item.content_encrypted,
                'target_node_iid': item.target_node_iid
            } for item in job_output]
        }

        result = self.post("job", body=p)
        return Job.parse_obj(result)

    def get_job(self, job_id: str) -> dict:
        return self.get(f"job/{job_id}", with_authorisation_by=self._authority)

    def get_all_jobs(self) -> List[dict]:
        return self.get("jobs", with_authorisation_by=self._authority)

    def cancel_job(self, job_id: str) -> dict:
        return self.delete(f"job/{job_id}", with_authorisation_by=self._authority)

    def upload_content(self, content_path: str, data_type: str, data_format: str, restricted_access: bool = False,
                       content_encrypted: bool = False, license_by: bool = False, license_sa: bool = False,
                       license_nc: bool = False, license_nd: bool = False, preferred_dor_iid: str = None,
                       tags: List[DataObject.Tag] = None) -> CDataObject:

        p = {
            'data_type': data_type,
            'data_format': data_format,
            'restricted_access': restricted_access,
            'content_encrypted': content_encrypted,
            'license_by': license_by,
            'license_sa': license_sa,
            'license_nc': license_nc,
            'license_nd': license_nd,
            'preferred_dor_iid': preferred_dor_iid,
            'tags': [tag.dict() for tag in tags]
        }

        result = self.post('data/content', body=p, attachment_path=content_path, use_snappy=False)
        return CDataObject.parse_obj(result)

    def upload_gpp(self, source: str, commit_id: str, proc_path: str, proc_config: str, preferred_dor_iid: str = None,
                   tags: List[DataObject.Tag] = None) -> GPPDataObject:

        p = {
            'source': source,
            'commit_id': commit_id,
            'proc_path': proc_path,
            'proc_config': proc_config,
            'preferred_dor_iid': preferred_dor_iid,
            'tags': [tag.dict() for tag in tags]
        }

        result = self.post('data/gpp', body=p)
        return GPPDataObject.parse_obj(result)

    def search_data(self, patterns: List[str] = None, owned_by_user: bool = False, data_type: str = None,
                    data_format: str = None, c_hashes: List[str] = None) -> List[Union[CDataObject, GPPDataObject]]:

        # create query parameter components (if any)
        q = []
        if patterns:
            q.append(f"patterns={','.join(patterns)}")
        if owned_by_user:
            q.append("owned_by_user=True")
        if data_type:
            q.append(f"data_type={data_type}")
        if data_format:
            q.append(f"data_format={data_format}")
        if c_hashes:
            q.append(f"c_hashes={','.join(c_hashes)}")

        # create query parameter string
        q = f"?{'&'.join(q)}" if q else ""

        results = self.get(f"data{q}")
        return [
            GPPDataObject.parse_obj(result) if result['data_type'] == GPP_DATA_TYPE else CDataObject.parse_obj(result)
            for result in results
        ]

    def get_meta(self, obj_id: str) -> Union[CDataObject, GPPDataObject]:
        result = self.get(f"data/{obj_id}/meta")
        return GPPDataObject.parse_obj(result) \
            if result['data_type'] == GPP_DATA_TYPE else CDataObject.parse_obj(result)

    def download_content(self, obj_id: str, download_path: str) -> None:
        self.get(f"data/{obj_id}/content", download_path=download_path, with_authorisation_by=self._authority)

    def download_feature(self, obj_id: str, download_path: str, parameters: dict = None) -> None:
        self.get(f"data/{obj_id}/feature", download_path=download_path, body=parameters,
                 with_authorisation_by=self._authority)

    def delete_data(self, obj_id: str) -> Union[CDataObject, GPPDataObject]:
        result = self.delete(f"data/{obj_id}", with_authorisation_by=self._authority)
        return GPPDataObject.parse_obj(result) \
            if result['data_type'] == GPP_DATA_TYPE else CDataObject.parse_obj(result)

    def provenance(self, obj_id: str) -> schemas.DataObjectProvenance:
        result = self.get(f"provenance/{obj_id}")
        return schemas.DataObjectProvenance.parse_obj(result)
