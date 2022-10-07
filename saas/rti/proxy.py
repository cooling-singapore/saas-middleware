import json
from typing import List, Union

from saas.core.identity import Identity
from saas.core.keystore import Keystore
from saas.nodedb.proxy import NodeDBProxy
from saas.rest.proxy import EndpointProxy
from saas.rti.schemas import ProcessorStatus, Processor, Job, Task, JobStatus, ReconnectInfo
from saas.dor.schemas import GitProcessorPointer
from saas.core.schemas import GithubCredentials, SSHCredentials

RTI_ENDPOINT_PREFIX = "/api/v1/rti"


class RTIProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int)) -> None:
        EndpointProxy.__init__(self, RTI_ENDPOINT_PREFIX, remote_address)

    def get_deployed(self) -> List[Processor]:
        results = self.get(f"")
        return [Processor.parse_obj(result) for result in results]

    def deploy(self, proc_id: str, authority: Keystore, deployment: str = "native", gpp_custodian: str = None,
               ssh_credentials: SSHCredentials = None, github_credentials: GithubCredentials = None) -> Processor:

        body = {
            'deployment': deployment,
        }

        if gpp_custodian:
            body['gpp_custodian'] = gpp_custodian

        # do we have credentials to encrypt?
        if ssh_credentials or github_credentials:
            # get info about the node (TODO: there is probably a better way to get the id of the peer)
            db = NodeDBProxy(self.remote_address)
            peer_info = db.get_node()
            peer = Identity.parse_obj(peer_info.identity)

            if ssh_credentials:
                ssh_credentials_serialised = json.dumps({
                    'host': ssh_credentials.host,
                    'login': ssh_credentials.login,
                    'key': ssh_credentials.key,
                    'key_is_password': ssh_credentials.key_is_password
                })
                body['encrypted_ssh_credentials'] = peer.encrypt(ssh_credentials_serialised.encode('utf-8')).hex()

            if github_credentials:
                github_credentials_serialised = json.dumps({
                    'login': github_credentials.login,
                    'personal_access_token': github_credentials.personal_access_token
                })
                body['encrypted_github_credentials'] = peer.encrypt(github_credentials_serialised.encode('utf-8')).hex()

        result = self.post(f"/proc/{proc_id}", body=body, with_authorisation_by=authority)
        return Processor.parse_obj(result)

    def undeploy(self, proc_id: str, authority: Keystore) -> Processor:
        result = self.delete(f"/proc/{proc_id}", with_authorisation_by=authority)
        return Processor.parse_obj(result)

    def get_gpp(self, proc_id: str) -> GitProcessorPointer:
        result = self.get(f"/proc/{proc_id}/gpp")
        return GitProcessorPointer.parse_obj(result)

    def get_status(self, proc_id: str) -> ProcessorStatus:
        result = self.get(f"/proc/{proc_id}/status")
        return ProcessorStatus.parse_obj(result)

    def submit_job(self, proc_id: str, job_input: List[Union[Task.InputReference, Task.InputValue]],
                   job_output: List[Task.Output], with_authorisation_by: Keystore) -> Job:
        result = self.post(f"/proc/{proc_id}/jobs", body={
            'proc_id': proc_id,
            'input': [i.dict() for i in job_input],
            'output': [o.dict() for o in job_output],
            'user_iid': with_authorisation_by.identity.id
        }, with_authorisation_by=with_authorisation_by)

        return Job.parse_obj(result)

    def resume_job(self, proc_id: str, job: Job, reconnect: ReconnectInfo, with_authorisation_by: Keystore) -> Job:
        result = self.put(f"/proc/{proc_id}/jobs", body={
            'job': job.dict(),
            'reconnect': reconnect.dict()
        }, with_authorisation_by=with_authorisation_by)
        return Job.parse_obj(result)

    def get_jobs_by_proc(self, proc_id: str) -> List[Job]:
        results = self.get(f"/proc/{proc_id}/jobs")
        return [Job.parse_obj(result) for result in results]

    def get_jobs_by_user(self, authority: Keystore) -> List[Job]:
        results = self.get(f"/job", with_authorisation_by=authority)
        return [Job.parse_obj(result) for result in results]

    def get_job_status(self, job_id: str, with_authorisation_by: Keystore) -> JobStatus:
        result = self.get(f"/job/{job_id}/status", with_authorisation_by=with_authorisation_by)
        return JobStatus.parse_obj(result)

    def get_job_logs(self, job_id: str, with_authorisation_by: Keystore, download_path: str) -> None:
        self.get(f"/job/{job_id}/logs", download_path=download_path, with_authorisation_by=with_authorisation_by)

    def put_permission(self, req_id: str, content_key: str) -> None:
        self.post(f"/permission/{req_id}", body={
            'req_id': req_id,
            'content_key': content_key
        })
