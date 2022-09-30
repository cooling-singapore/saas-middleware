import json
from typing import List

from saas.dor.schemas import SSHCredentials, GithubCredentials
from saas.keystore.identity import Identity
from saas.keystore.keystore import Keystore
from saas.nodedb.proxy import NodeDBProxy
from saas.rest.proxy import EndpointProxy
from saas.rti.schemas import Processor, Job
from saas.schemas import GitProcessorPointer, ProcessorStatus, JobDescriptor

RTI_ENDPOINT_PREFIX = "/api/v1/rti"


class RTIProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int)) -> None:
        EndpointProxy.__init__(self, RTI_ENDPOINT_PREFIX, remote_address)

    def get_deployed(self) -> List[Processor]:
        results = self.get(f"")
        return [Processor.parse_obj(result) for result in results]

    def deploy(self, proc_id: str, deployment: str = "native", gpp_custodian: str = None,
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
                body['ssh_credentials'] = peer.encrypt(ssh_credentials_serialised.encode('utf-8')).hex()

            if github_credentials:
                github_credentials_serialised = json.dumps({
                    'login': github_credentials.login,
                    'personal_access_token': github_credentials.personal_access_token
                })
                body['github_credentials'] = peer.encrypt(github_credentials_serialised.encode('utf-8')).hex()

        result = self.post(f"/proc/{proc_id}", body=body)
        return Processor.parse_obj(result)

    def undeploy(self, proc_id: str) -> Processor:
        result = self.delete(f"/proc/{proc_id}")
        return Processor.parse_obj(result)

    def get_gpp(self, proc_id: str) -> GitProcessorPointer:
        result = self.get(f"/proc/{proc_id}/gpp")
        return GitProcessorPointer.parse_obj(result)

    def get_status(self, proc_id: str) -> ProcessorStatus:
        result = self.get(f"/proc/{proc_id}/status")
        return ProcessorStatus.parse_obj(result)

    def submit_job(self, proc_id: str, job_input: list, job_output: list,
                   with_authorisation_by: Keystore) -> JobDescriptor:
        result = self.post(f"/proc/{proc_id}/jobs", body={
            'processor_id': proc_id,
            'input': job_input,
            'output': job_output,
            'user_iid': with_authorisation_by.identity.id
        }, with_authorisation_by=with_authorisation_by)

        return JobDescriptor.parse_obj(result)

    # def resume_job(self, proc_id: str, reconnect_info: dict) -> dict:
    #     return self.put(f"/proc/{proc_id}/jobs", body=reconnect_info)

    def get_jobs(self, proc_id: str) -> List[JobDescriptor]:
        results = self.get(f"/proc/{proc_id}/jobs")
        return [JobDescriptor.parse_obj(result) for result in results]

    def get_job_info(self, job_id: str, with_authorisation_by: Keystore) -> Job:
        result = self.get(f"/job/{job_id}/info", with_authorisation_by=with_authorisation_by)
        return Job.parse_obj(result)

    def get_job_logs(self, job_id: str, with_authorisation_by: Keystore, download_path: str) -> None:
        self.get(f"/job/{job_id}/logs", download_path=download_path, with_authorisation_by=with_authorisation_by)

    def put_permission(self, req_id: str, content_key: str) -> None:
        self.post(f"/permission/{req_id}", body={
            'req_id': req_id,
            'content_key': content_key
        })
