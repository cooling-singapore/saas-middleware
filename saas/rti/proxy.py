from __future__ import annotations

from typing import List, Union, Tuple, Optional

from saas.core.keystore import Keystore
from saas.rest.exceptions import UnsuccessfulConnectionError
from saas.rest.proxy import EndpointProxy, Session, get_proxy_prefix
from saas.rti.schemas import Processor, Job, Task, JobStatus

RTI_ENDPOINT_PREFIX = "/api/v1/rti"
JOB_ENDPOINT_PREFIX = "/api/v1/job"


class RTIProxy(EndpointProxy):
    @classmethod
    def from_session(cls, session: Session) -> RTIProxy:
        return RTIProxy(remote_address=session.address, credentials=session.credentials,
                        endpoint_prefix=(session.endpoint_prefix_base, 'rti'))

    def __init__(self, remote_address: (str, int), credentials: (str, str) = None,
                 endpoint_prefix: Tuple[str, str] = get_proxy_prefix(RTI_ENDPOINT_PREFIX)):
        super().__init__(endpoint_prefix, remote_address, credentials=credentials)

    def get_all_procs(self) -> List[Processor]:
        results = self.get("proc")
        return [Processor.parse_obj(result) for result in results]

    def get_proc(self, proc_id: str) -> Processor:
        result = self.get(f"proc/{proc_id}")
        return Processor.parse_obj(result)

    def deploy(self, proc_id: str, authority: Keystore) -> Processor:
        result = self.post(f"proc/{proc_id}", with_authorisation_by=authority)
        return Processor.parse_obj(result)

    def undeploy(self, proc_id: str, authority: Keystore) -> Processor:
        result = self.delete(f"proc/{proc_id}", with_authorisation_by=authority)
        return Processor.parse_obj(result)

    def submit_job(self, proc_id: str, job_input: List[Union[Task.InputReference, Task.InputValue]],
                   job_output: List[Task.Output], with_authorisation_by: Keystore, name: str = None,
                   description: str = None) -> Job:

        # build the body
        body = {
            'proc_id': proc_id,
            'input': [i.dict() for i in job_input],
            'output': [o.dict() for o in job_output],
            'user_iid': with_authorisation_by.identity.id
        }

        if name is not None:
            body['name'] = name

        if description is not None:
            body['description'] = description

        # post the request
        result = self.post(f"proc/{proc_id}/jobs", body=body, with_authorisation_by=with_authorisation_by)

        return Job.parse_obj(result)

    def get_jobs_by_proc(self, proc_id: str) -> List[Job]:
        results = self.get(f"proc/{proc_id}/jobs")
        return [Job.parse_obj(result) for result in results]

    def get_jobs_by_user(self, authority: Keystore, period: Optional[int]) -> List[Job]:
        results = self.get("job", parameters={'period': period} if period else None, with_authorisation_by=authority)
        return [Job.parse_obj(result) for result in results]

    def get_job_status(self, job_id: str, with_authorisation_by: Keystore) -> JobStatus:
        result = self.get(f"job/{job_id}/status", with_authorisation_by=with_authorisation_by)
        return JobStatus.parse_obj(result)

    def update_job_status(self, job_id: str, status: JobStatus) -> None:
        self.put(f"job/{job_id}/status", body=status.dict())

    def cancel_job(self, job_id: str, with_authorisation_by: Keystore) -> JobStatus:
        result = self.delete(f"job/{job_id}/cancel", with_authorisation_by=with_authorisation_by)
        return JobStatus.parse_obj(result)

    def purge_job(self, job_id: str, with_authorisation_by: Keystore) -> JobStatus:
        result = self.delete(f"job/{job_id}/purge", with_authorisation_by=with_authorisation_by)
        return JobStatus.parse_obj(result)


class JobRESTProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int), credentials: (str, str) = None,
                 endpoint_prefix: Tuple[str, str] = get_proxy_prefix(JOB_ENDPOINT_PREFIX)):
        super().__init__(endpoint_prefix, remote_address, credentials=credentials)

    def job_status(self) -> Optional[JobStatus]:
        try:
            result = self.get("status")
            return JobStatus.parse_obj(result)
        except UnsuccessfulConnectionError:
            # the server might be down already (e.g., if job is done or failed) or not yet up (in case the job has
            # not been started yet).
            return None

    def job_cancel(self) -> Optional[JobStatus]:
        try:
            result = self.put("cancel")
            return JobStatus.parse_obj(result)
        except UnsuccessfulConnectionError:
            # the server might be down already (e.g., if job is done or failed) or not yet up (in case the job has
            # not been started yet).
            return None
        except Exception as e:
            print(e)
