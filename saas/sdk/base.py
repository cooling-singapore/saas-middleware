from __future__ import annotations

import os
import threading
import time
from typing import List, Union, Dict, Optional, Callable, Literal, Tuple

from pydantic import BaseModel

from saas.core.exceptions import SaaSRuntimeException
from saas.core.helpers import validate_json, get_timestamp_now
from saas.core.identity import Identity
from saas.core.keystore import Keystore
from saas.core.logging import Logging
from saas.dor.proxy import DORProxy
from saas.dor.schemas import CDataObject, DataObjectProvenance, GPPDataObject, DataObject
from saas.nodedb.proxy import NodeDBProxy
from saas.nodedb.schemas import NodeInfo
from saas.rest.proxy import Session
from saas.rti.proxy import RTIProxy
from saas.rti.schemas import JobStatus, Job, Task, ProcessorStatus, Processor

logger = Logging.get('saas.sdk.base')


class SDKProductSpecification(BaseModel):
    restricted_access: Optional[bool]
    content_encrypted: Optional[bool]
    target_node: Optional[NodeInfo]
    owner: Optional[Identity]


class LogMessage(BaseModel):
    severity: Literal['debug', 'info', 'warning', 'error']
    message: str


class SDKProcessor:
    def __init__(self, processor: Processor, authority: Keystore, node: NodeInfo, session: Session = None) -> None:
        self._processor = processor
        self._authority = authority
        self._rti = RTIProxy.from_session(session) if session else RTIProxy(node.rest_address)
        self._node = node
        self._session = session

    @property
    def name(self) -> str:
        return self._processor.gpp.proc_descriptor.name

    @property
    def descriptor(self) -> Processor:
        return self._processor

    def undeploy(self) -> None:
        self._rti.undeploy(self._processor.proc_id, self._authority)

    def status(self) -> ProcessorStatus:
        return self._rti.get_status(self._processor.proc_id)

    def submit(self, consume_specs: Dict[str, Union[SDKCDataObject, Dict]],
               product_specs: Dict[str, SDKProductSpecification] = None,
               name: str = None, description: str = None) -> SDKJob:

        # process consumed objects
        job_input = []
        for obj_desc in self._processor.gpp.proc_descriptor.input:
            # do we have the required object by name?
            if obj_desc.name not in consume_specs:
                raise SaaSRuntimeException(f"No input object '{obj_desc.name}' found.")

            # is it by-reference or by-value?
            obj = consume_specs[obj_desc.name]
            if isinstance(obj, SDKCDataObject):
                meta = consume_specs[obj_desc.name].meta

                # create a signature (if needed)
                signature = self._authority.sign(f"{self._node.identity.id}:{meta.obj_id}".encode('utf-8')) if \
                    meta.access_restricted else None

                job_input.append(Task.InputReference(
                    name=obj_desc.name,
                    type='reference',
                    obj_id=meta.obj_id,
                    user_signature=signature,
                    c_hash=meta.c_hash
                ))

            else:
                # validate the content (if there is a schema)
                if obj_desc.data_schema and not validate_json(obj, obj_desc.data_schema):
                    raise SaaSRuntimeException(f"By-value input object '{obj_desc.name}' does not comply with"
                                               f"schema {obj_desc.data_schema}.",
                                               details={'instance': obj, 'schema': obj_desc.data_schema})

                job_input.append(Task.InputValue(
                    name=obj_desc.name,
                    type='value',
                    value=obj
                ))

        # determine the default product specs
        default_restricted_access = False
        default_content_encrypted = False
        default_target_node_iid = self._node.identity.id
        default_owner_iid = self._authority.identity.id

        # process produced objects
        job_output = []
        product_spec = product_specs if product_specs else {}
        for obj in self._processor.gpp.proc_descriptor.output:
            # get the object-specific specs (if any)
            specs = product_spec[obj.name] if obj.name in product_spec else SDKProductSpecification()

            # add the task output
            job_output.append(Task.Output(
                name=obj.name,
                owner_iid=specs.owner.id if specs.owner is not None else default_owner_iid,

                restricted_access=specs.restricted_access
                if specs.restricted_access is not None else default_restricted_access,

                content_encrypted=specs.content_encrypted
                if specs.content_encrypted is not None else default_content_encrypted,

                target_node_iid=specs.target_node.identity.id
                if specs.target_node is not None else default_target_node_iid
            ))

        # try to submit the job
        job: Job = self._rti.submit_job(self._processor.proc_id, job_input, job_output,
                                        with_authorisation_by=self._authority,
                                        name=name, description=description)
        return SDKJob(self, job, self._authority, self._session)

    def submit_and_wait(self, consume_specs: Dict[str, Union[SDKCDataObject, Dict]],
                        product_specs: Dict[str, SDKProductSpecification] = None) -> Dict[str, SDKCDataObject]:

        # submit and wait
        job = self.submit(consume_specs, product_specs=product_specs)
        return job.wait()


class SDKDataObject:
    def __init__(self, meta: Union[CDataObject, GPPDataObject], authority: Keystore, session: Session) -> None:
        self._meta = meta
        self._authority = authority
        self._session = session
        self._dor = DORProxy.from_session(session) if session else DORProxy(meta.custodian.rest_address)

    def delete(self) -> Union[CDataObject, GPPDataObject]:
        return self._dor.delete_data_object(self._meta.obj_id, self._authority)

    def grant_access(self, identity: Identity) -> None:
        self._meta = self._dor.grant_access(self._meta.obj_id, self._authority, identity)

    def revoke_access(self, identity: Identity) -> None:
        self._meta = self._dor.revoke_access(self._meta.obj_id, self._authority, identity)

    def transfer_ownership(self, new_owner: Identity) -> None:
        self._meta = self._dor.transfer_ownership(self._meta.obj_id, self._authority, new_owner)

    def update_tags(self, tags: List[DataObject.Tag]) -> None:
        self._meta = self._dor.update_tags(self._meta.obj_id, self._authority, tags)

    def remove_tags(self, keys: List[str]) -> None:
        self._meta = self._dor.remove_tags(self._meta.obj_id, self._authority, keys)


class SDKGPPDataObject(SDKDataObject):
    def __init__(self, meta: GPPDataObject, authority: Keystore, session: Session = None) -> None:
        super().__init__(meta, authority, session)

    @property
    def meta(self) -> GPPDataObject:
        return self._meta

    def deploy(self, node: NodeInfo, ssh_profile: str = None) -> SDKProcessor:
        # does the node have an RTI?
        if not node.rti_service:
            raise SaaSRuntimeException("Node does not have an RTI service", details={
                'node': node
            })

        # do we have SSH credentials for this profile (if applicable)
        ssh_credentials = None
        if ssh_profile:
            ssh_credentials = self._authority.ssh_credentials.get(ssh_profile)
            if not ssh_credentials:
                raise SaaSRuntimeException("No SSH credentials found for profile", details={
                    'profile': ssh_profile
                })

        # do we have GitHub credentials for this repo?
        github_credentials = self._authority.github_credentials.get(self.meta.gpp.source)

        # try to deploy the processor
        rti = RTIProxy.from_session(self._session) if self._session else RTIProxy(node.rest_address)
        proc = rti.deploy(self.meta.obj_id, self._authority, gpp_custodian=self.meta.custodian.identity.id,
                          ssh_credentials=ssh_credentials, github_credentials=github_credentials)

        return SDKProcessor(proc, self._authority, node, self._session)


class SDKCDataObject(SDKDataObject):
    def __init__(self, meta: CDataObject, authority: Keystore, session: Session = None) -> None:
        super().__init__(meta, authority, session)

    @property
    def meta(self) -> CDataObject:
        return self._meta

    def download(self, download_path: str) -> str:
        # if the download path is a directory, use a default filename
        if os.path.isdir(download_path):
            download_path = os.path.join(download_path, f"{self.meta.obj_id}.{self.meta.data_format}")

        # download the content
        self._dor.get_content(self._meta.obj_id, self._authority, download_path)
        return download_path

    def get_provenance(self) -> DataObjectProvenance:
        return self._dor.get_provenance(self._meta.c_hash)


class SDKJob:
    def __init__(self, proc: SDKProcessor, job: Job, authority: Keystore, session: Session = None) -> None:
        self._mutex = threading.Lock()
        self._proc = proc
        self._job = job
        self._authority = authority
        self._rti = RTIProxy.from_session(session) if session else RTIProxy(job.custodian.rest_address)
        self._status = None
        self._status_last_refresh = get_timestamp_now()
        self._session = session

    def refresh_status(self) -> Optional[JobStatus]:
        try:
            # don't refresh too frequently (i.e., at most once a second)
            with self._mutex:
                t_now = get_timestamp_now()
                if t_now < self._status_last_refresh + 1000:
                    return None
                else:
                    self._status_last_refresh = t_now

            # get the job status from the RTI
            status = self._rti.get_job_status(self._job.id, self._authority)

            # update status
            with self._mutex:
                self._status = status
                return self._status

        except SaaSRuntimeException as e:
            logger.warning(f"failed to refresh job status -> id={e.id} reason={e.reason} details:{e.details}")
            return None

        except Exception as e:
            logger.warning(f"failed to refresh job status -> unexpected exception={e}")
            return None

    @property
    def content(self) -> Job:
        return self._job

    @property
    def status(self) -> Optional[JobStatus]:
        # do we need to refresh?
        with self._mutex:
            refresh_required = self._status is None or self._status.state in [JobStatus.State.UNINITIALISED,
                                                                              JobStatus.State.INITIALISED,
                                                                              JobStatus.State.RUNNING,
                                                                              JobStatus.State.POSTPROCESSING]

        # perform refresh (if required)
        if refresh_required:
            self.refresh_status()

        return self._status

    def cancel(self) -> JobStatus:
        with self._mutex:
            status = self._rti.cancel_job(self._job.id, self._authority)
            return status

    def wait(self, pace: float = 5.0, callback_progress: Callable[[int], None] = None,
             callback_message: Callable[[LogMessage], None] = None,
             max_no_status: int = 5) -> Optional[Dict[str, SDKCDataObject]]:
        # wait until the job has finished
        prev_progress = None
        prev_message = None
        no_status_count = 0
        while True:
            # wait for a bit...
            time.sleep(pace)

            # check the status (if we have one)
            status = self.status
            if status is None:
                no_status_count += 1
                if no_status_count >= max_no_status:
                    raise SaaSRuntimeException('Maximum number of consecutive unsuccessful job status requests '
                                               'exceeded')

            else:
                no_status_count = 0

                # only update progress if we have a callback and if necessary
                if callback_progress and (prev_progress is None or prev_progress != status.progress):
                    callback_progress(status.progress)
                    prev_progress = status.progress

                # only update message if we have a callback and if necessary
                if callback_message and status.message is not None and prev_message != status.message:
                    log_message = LogMessage(severity=status.message.severity, message=status.message.content)
                    callback_message(log_message)
                    prev_message = status.message

                # are we done?
                if status.state == JobStatus.State.SUCCESSFUL:
                    result = {
                        name: SDKCDataObject(meta=meta, authority=self._authority, session=self._session)
                        for name, meta in status.output.items()
                    }
                    return result

                elif status.state in [JobStatus.State.FAILED, JobStatus.State.CANCELLED]:
                    return None


class SDKContext:
    def __init__(self, dor_nodes: List[NodeInfo], rti_nodes: List[NodeInfo], authority: Keystore):
        self._dor_nodes = {node.identity.id: node for node in dor_nodes}
        self._rti_nodes = {node.identity.id: node for node in rti_nodes}
        self._authority = authority
        self._created = get_timestamp_now()

    @property
    def authority(self) -> Keystore:
        return self._authority

    @property
    def age(self) -> float:
        """
        The age (i.e., time since creation) of this context in minutes.
        :return:
        """
        return (get_timestamp_now() - self._created) / 60000.0

    def has_dor_node(self) -> bool:
        return len(self._dor_nodes) > 0

    def has_rti_node(self) -> bool:
        return len(self._rti_nodes) > 0

    def dor(self, preferred_iid: str = None) -> NodeInfo:
        # do we have any DOR?
        n = len(self._dor_nodes)
        if n == 0:
            raise SaaSRuntimeException("No DOR node found")

        # do we have the preferred node?
        if preferred_iid is not None:
            return self._dor_nodes[preferred_iid] if preferred_iid in self._dor_nodes else None

        # just use an arbitrary one
        return list(self._dor_nodes.values())[0]

    def rti(self, preferred_iid: str = None) -> NodeInfo:
        # do we have any RTI?
        n = len(self._rti_nodes)
        if n == 0:
            raise SaaSRuntimeException("No RTI node found")

        # do we have the preferred node?
        if preferred_iid is not None:
            return self._rti_nodes[preferred_iid] if preferred_iid in self._rti_nodes else None

        # just use an arbitrary one
        return list(self._rti_nodes.values())[0]

    def upload_content(self, content_path: str, data_type: str, data_format: str, access_restricted: bool,
                       content_encrypted: bool = False, creators: List[Identity] = None, license_by: bool = False,
                       license_sa: bool = False, license_nc: bool = False, license_nd: bool = False,
                       preferred_dor_iid: str = None) -> SDKCDataObject:

        # get DOR node
        dor = self.dor(preferred_iid=preferred_dor_iid)

        # upload data object to DOR
        dor = DORProxy(dor.rest_address)
        meta = dor.add_data_object(content_path, self._authority.identity, access_restricted, content_encrypted,
                                   data_type, data_format, creators=creators, license_by=license_by,
                                   license_sa=license_sa, license_nc=license_nc, license_nd=license_nd)

        return SDKCDataObject(meta, self._authority)

    def upload_gpp(self, source: str, commit_id: str, proc_path: str, proc_config: str,
                   creators: List[Identity] = None, preferred_dor_iid: str = None) -> SDKGPPDataObject:

        # get DOR node
        dor = self.dor(preferred_iid=preferred_dor_iid)

        # do we have GitHub credentials?
        github_credentials = self._authority.github_credentials.get(source)

        # upload data object to DOR
        dor = DORProxy(dor.rest_address)
        meta = dor.add_gpp_data_object(source, commit_id, proc_path, proc_config, self._authority.identity,
                                       creators=creators, github_credentials=github_credentials)

        return SDKGPPDataObject(meta, self._authority)

    def find_processor_by_id(self, proc_id: str) -> Optional[SDKProcessor]:
        for node in self._rti_nodes.values():
            rti = RTIProxy(node.rest_address)
            for proc in rti.get_deployed():
                if proc.proc_id == proc_id:
                    return SDKProcessor(proc, self._authority, node)
        return None

    def find_processor_by_name(self, proc_name: str) -> Optional[SDKProcessor]:
        for node in self._rti_nodes.values():
            rti = RTIProxy(node.rest_address)
            for proc in rti.get_deployed():
                if proc.gpp.proc_descriptor.name == proc_name:
                    return SDKProcessor(proc, self._authority, node)
        return None

    def find_processors(self, pattern: str = None) -> List[SDKProcessor]:
        result = []
        for node in self._rti_nodes.values():
            rti = RTIProxy(node.rest_address)
            for proc in rti.get_deployed():
                if not pattern or pattern in proc.gpp.proc_descriptor.name:
                    result.append(SDKProcessor(proc, self._authority, node))
        return result

    def find_data_object(self, obj_id: str) -> Optional[Union[SDKCDataObject, SDKGPPDataObject]]:
        for node in self._dor_nodes.values():
            dor = DORProxy(node.rest_address)
            meta = dor.get_meta(obj_id)
            if meta:
                if isinstance(meta, CDataObject):
                    return SDKCDataObject(meta, self._authority)
                else:
                    return SDKGPPDataObject(meta, self._authority)

        return None

    def find_data_objects(self, patterns: list[str] = None, owner_iid: str = None, data_type: str = None,
                          data_format: str = None, c_hashes: list[str] = None) -> List[Union[SDKCDataObject,
                                                                                             SDKGPPDataObject]]:

        result = []
        for node in self._dor_nodes.values():
            dor = DORProxy(node.rest_address)
            for meta in dor.search(patterns=patterns, owner_iid=owner_iid, data_type=data_type,
                                   data_format=data_format, c_hashes=c_hashes):

                if isinstance(meta, CDataObject):
                    result.append(SDKCDataObject(meta, self._authority))
                else:
                    result.append(SDKGPPDataObject(meta, self._authority))
        return result

    def find_all_jobs_with_status(self) -> List[SDKJob]:
        results = []
        for node in self._rti_nodes.values():
            rti = RTIProxy(node.rest_address)
            jobs = rti.get_jobs_by_user(self._authority)
            for job in jobs:
                # get the corresponding processor
                for proc in rti.get_deployed():
                    if proc.proc_id == job.task.proc_id:
                        proc = SDKProcessor(proc, self._authority, node)
                        results.append(SDKJob(proc, job, self._authority))
                        break

        return results

    def find_job(self, job_id) -> Optional[SDKJob]:
        for node in self._rti_nodes.values():
            rti = RTIProxy(node.rest_address)
            jobs = rti.get_jobs_by_user(self._authority)
            for job in jobs:
                # does the job id match?
                if job.id == job_id:
                    # get the corresponding processor
                    for proc in rti.get_deployed():
                        if proc.proc_id == job.task.proc_id:
                            proc = SDKProcessor(proc, self._authority, node)
                            return SDKJob(proc, job, self._authority)

                    # if we get here then we haven't been able to find the processor for this job
                    raise SaaSRuntimeException("No processor deployed for job", details={
                        'job_id': job_id,
                        'proc_id': job.task.proc_id
                    })

        return None

    def publish_identity(self, identity: Identity) -> None:
        # get the nodes
        nodes = list(self._rti_nodes.values()) + list(self._dor_nodes.values())
        if not nodes:
            raise SaaSRuntimeException("No nodes found")

        for node in nodes:
            db = NodeDBProxy(node.rest_address)
            db.update_identity(identity)


def publish_identity(address: (str, int), identity: Identity) -> None:
    db = NodeDBProxy(address)
    db.update_identity(identity)


def connect(address: Union[str, Tuple[str, int]], authority: Keystore) -> SDKContext:
    # parse the address (if necessary)
    if isinstance(address, str):
        if ':' in address:
            address = address.split(':')
            address = (address[0], int(address[1]))
        else:
            address = (address, None)

    # publish the user identity (may not be needed but just to be sure)
    publish_identity(address, authority.identity)

    # fetch information about the network
    db = NodeDBProxy(address)
    dor_nodes: List[NodeInfo] = []
    rti_nodes: List[NodeInfo] = []
    for node in db.get_network():
        if node.rti_service:
            rti_nodes.append(node)

        if node.dor_service:
            dor_nodes.append(node)

    return SDKContext(dor_nodes, rti_nodes, authority)


class SDKRelayContext:
    def __init__(self, session: Session, authority: Keystore, node: NodeInfo):
        self._authority = authority
        self._session = session
        self._node = node

    def close(self) -> None:
        # delete the ephemeral keystore
        os.remove(self._authority.path)

    def upload_content(self, content_path: str, data_type: str, data_format: str, access_restricted: bool,
                       content_encrypted: bool = False, creators: List[Identity] = None, license_by: bool = False,
                       license_sa: bool = False, license_nc: bool = False, license_nd: bool = False) -> SDKCDataObject:

        # upload data object to DOR
        dor = DORProxy.from_session(self._session)
        meta = dor.add_data_object(content_path, self._authority.identity, access_restricted, content_encrypted,
                                   data_type, data_format, creators=creators, license_by=license_by,
                                   license_sa=license_sa, license_nc=license_nc, license_nd=license_nd)

        return SDKCDataObject(meta, self._authority, self._session)

    def find_processor_by_id(self, proc_id: str) -> Optional[SDKProcessor]:
        rti = RTIProxy.from_session(self._session)
        for proc in rti.get_deployed():
            if proc.proc_id == proc_id:
                return SDKProcessor(proc, self._authority, self._node, self._session)
        return None

    def find_processor_by_name(self, proc_name: str) -> Optional[SDKProcessor]:
        rti = RTIProxy.from_session(self._session)
        for proc in rti.get_deployed():
            if proc.gpp.proc_descriptor.name == proc_name:
                return SDKProcessor(proc, self._authority, self._node, self._session)
        return None

    def find_processors(self, pattern: str = None) -> List[SDKProcessor]:
        result = []
        rti = RTIProxy.from_session(self._session)
        for proc in rti.get_deployed():
            if not pattern or pattern in proc.gpp.proc_descriptor.name:
                result.append(SDKProcessor(proc, self._authority, self._node, self._session))
        return result

    def find_data_object(self, obj_id: str) -> Optional[Union[SDKCDataObject, SDKGPPDataObject]]:
        dor = DORProxy.from_session(self._session)
        meta = dor.get_meta(obj_id)
        if meta:
            if isinstance(meta, CDataObject):
                return SDKCDataObject(meta, self._authority, self._session)
            else:
                return SDKGPPDataObject(meta, self._authority, self._session)

        return None

    def find_data_objects(self, patterns: list[str] = None, owner_iid: str = None, data_type: str = None,
                          data_format: str = None, c_hashes: list[str] = None) -> List[Union[SDKCDataObject,
                                                                                             SDKGPPDataObject]]:

        result = []
        dor = DORProxy.from_session(self._session)
        for meta in dor.search(patterns=patterns, owner_iid=owner_iid, data_type=data_type,
                               data_format=data_format, c_hashes=c_hashes):

            if isinstance(meta, CDataObject):
                result.append(SDKCDataObject(meta, self._authority, self._session))
            else:
                result.append(SDKGPPDataObject(meta, self._authority, self._session))
        return result

    def find_all_jobs_with_status(self) -> List[SDKJob]:
        results = []
        rti = RTIProxy.from_session(self._session)
        jobs = rti.get_jobs_by_user(self._authority)
        for job in jobs:
            # get the corresponding processor
            for proc in rti.get_deployed():
                if proc.proc_id == job.task.proc_id:
                    proc = SDKProcessor(proc, self._authority, self._node, self._session)
                    results.append(SDKJob(proc, job, self._authority, self._session))
                    break

        return results

    def find_job(self, job_id) -> Optional[SDKJob]:
        rti = RTIProxy.from_session(self._session)
        jobs = rti.get_jobs_by_user(self._authority)
        for job in jobs:
            # does the job id match?
            if job.id == job_id:
                # get the corresponding processor
                for proc in rti.get_deployed():
                    if proc.proc_id == job.task.proc_id:
                        proc = SDKProcessor(proc, self._authority, self._node, self._session)
                        return SDKJob(proc, job, self._authority, self._session)

                # if we get here then we haven't been able to find the processor for this job
                raise SaaSRuntimeException("No processor deployed for job", details={
                    'job_id': job_id,
                    'proc_id': job.task.proc_id
                })

        return None

    def publish_identity(self, identity: Identity) -> None:
        db = NodeDBProxy.from_session(self._session)
        db.update_identity(identity)


def connect_to_relay(wd_path: str, relay_address: (str, int), credentials: (str, str)) -> SDKRelayContext:
    # connect to the node and get info about it
    session = Session(endpoint_prefix_base='/relay/v1', remote_address=relay_address, credentials=credentials)
    db = NodeDBProxy.from_session(session)
    node = db.get_node()

    # create an ephemeral keystore that is only used for the Relay
    authority = Keystore.create(wd_path, f"relay_proxy:{session.credentials[0]}", 'none', session.credentials[1])
    user_identity = db.update_identity(authority.identity)

    print(f"Using ephemeral identity: {authority.identity.id}")
    print(f"Actual user identity: {user_identity.id}")

    return SDKRelayContext(session, authority, node)
