import json
import os
from typing import List, Union, Optional, Dict

from fastapi import Depends, Form, UploadFile, File
from snappy import snappy

from saas.core.exceptions import ExceptionContent
from saas.core.helpers import generate_random_string, get_timestamp_now
from saas.core.identity import Identity
from saas.core.logging import Logging
from saas.dor.proxy import DORProxy
from saas.dor.schemas import CDataObject, GPPDataObject, DataObject, DORStatistics, DataObjectProvenance, \
    GitProcessorPointer, SearchParameters, AddCDataObjectParameters, AddGPPDataObjectParameters
from saas.nodedb.proxy import NodeDBProxy
from saas.nodedb.schemas import NodeInfo
from saas.rest.schemas import EndpointDefinition
from saas.rti.proxy import RTIProxy
from saas.rti.schemas import Processor, Job, ProcessorStatus, JobStatus, DeployParameters, Task, ReconnectInfo, \
    Permission
from saas.sdk.app.auth import User
from saas.sdk.app.base import Application, get_current_active_user
from starlette.responses import Response, StreamingResponse

from relay.meta import __title__, __version__, __description__
from relay.checks import CheckIfUser

logger = Logging.get('relay.server')


RELAY_ENDPOINT_PREFIX_BASE = '/relay/v1'


class RelayRuntimeError(Exception):
    def __init__(self, reason: str, details: dict = None):
        self._content = ExceptionContent(id=generate_random_string(16), reason=reason, details=details)

    @property
    def id(self):
        return self._content.id

    @property
    def reason(self):
        return self._content.reason

    @property
    def details(self):
        return self._content.details

    @property
    def content(self) -> ExceptionContent:
        return self._content


def _stream_contents(content_path: str, delete_content_file: bool = True) -> Response:
    # read the contents into memory
    with open(content_path, 'rb') as f:
        contents = f.read()

    # delete the file
    if delete_content_file:
        os.remove(content_path)

    async def content_streamer():
        yield contents

    return StreamingResponse(
        content=content_streamer(),
        media_type='application/octet-stream'
    )


class RelayServer(Application):
    def __init__(self, server_address: (str, int), node_address: (str, int), wd_path: str) -> None:
        super().__init__(server_address, node_address, (RELAY_ENDPOINT_PREFIX_BASE, None), wd_path,
                         __title__, __version__, __description__)

        self._job_mapping: Dict[str, NodeInfo] = {}
        self._user_to_proxy: Dict[str, Identity] = {}

    def endpoints(self) -> List[EndpointDefinition]:
        check_if_user = Depends(CheckIfUser(self))

        db_endpoint_prefix = (RELAY_ENDPOINT_PREFIX_BASE, 'db')
        dor_endpoint_prefix = (RELAY_ENDPOINT_PREFIX_BASE, 'dor')
        rti_endpoint_prefix = (RELAY_ENDPOINT_PREFIX_BASE, 'rti')

        return [
            EndpointDefinition('GET', db_endpoint_prefix, 'node',
                               self.get_node, NodeInfo, [check_if_user]),

            EndpointDefinition('GET', db_endpoint_prefix, 'network',
                               self.get_network, List[NodeInfo], [check_if_user]),

            EndpointDefinition('GET', db_endpoint_prefix, 'identity/{iid}',
                               self.get_identity, Optional[Identity], [check_if_user]),

            EndpointDefinition('GET', db_endpoint_prefix, 'identity',
                               self.get_identities, List[Identity], [check_if_user]),

            EndpointDefinition('POST', db_endpoint_prefix, 'identity',
                               self.update_identity, Identity, [check_if_user]),


            EndpointDefinition('GET', dor_endpoint_prefix, '',
                               self.search, List[Union[CDataObject, GPPDataObject]], [check_if_user]),

            EndpointDefinition('GET', dor_endpoint_prefix, 'statistics',
                               self.statistics, DORStatistics, [check_if_user]),

            EndpointDefinition('POST', dor_endpoint_prefix, 'add-c',
                               self.add_c, CDataObject, [check_if_user]),

            EndpointDefinition('POST', dor_endpoint_prefix, 'add-gpp',
                               self.add_gpp, GPPDataObject, [check_if_user]),

            EndpointDefinition('DELETE', dor_endpoint_prefix, '{obj_id}',
                               self.remove, Union[CDataObject, GPPDataObject], [check_if_user]),

            EndpointDefinition('GET', dor_endpoint_prefix, '{obj_id}/meta',
                               self.get_meta, Optional[Union[CDataObject, GPPDataObject]], [check_if_user]),

            EndpointDefinition('GET', dor_endpoint_prefix, '{obj_id}/content',
                               self.get_content, None, [check_if_user]),

            EndpointDefinition('GET', dor_endpoint_prefix, '{c_hash}/provenance',
                               self.get_provenance, Optional[DataObjectProvenance], [check_if_user]),

            EndpointDefinition('POST', dor_endpoint_prefix, '{obj_id}/access/{target_user_iid}',
                               self.grant_access, Union[CDataObject, GPPDataObject], [check_if_user]),

            EndpointDefinition('DELETE', dor_endpoint_prefix, '{obj_id}/access/{target_user_iid}',
                               self.revoke_access, Union[CDataObject, GPPDataObject], [check_if_user]),

            EndpointDefinition('PUT', dor_endpoint_prefix, '{obj_id}/owner/{new_owner_iid}',
                               self.transfer_ownership, Union[CDataObject, GPPDataObject], [check_if_user]),

            EndpointDefinition('PUT', dor_endpoint_prefix, '{obj_id}/tags',
                               self.update_tags, Union[CDataObject, GPPDataObject],
                               [check_if_user]),

            EndpointDefinition('DELETE', dor_endpoint_prefix, '{obj_id}/tags',
                               self.remove_tags, Union[CDataObject, GPPDataObject], [check_if_user]),


            EndpointDefinition('GET', rti_endpoint_prefix, '',
                               self.deployed, List[Processor], [check_if_user]),

            EndpointDefinition('POST', rti_endpoint_prefix, 'proc/{proc_id}',
                               self.deploy, Processor, [check_if_user]),

            EndpointDefinition('DELETE', rti_endpoint_prefix, 'proc/{proc_id}',
                               self.undeploy, Processor, [check_if_user]),

            EndpointDefinition('GET', rti_endpoint_prefix, 'proc/{proc_id}/gpp',
                               self.gpp, GitProcessorPointer, [check_if_user]),

            EndpointDefinition('GET', rti_endpoint_prefix, 'proc/{proc_id}/status',
                               self.status, ProcessorStatus, [check_if_user]),

            EndpointDefinition('POST', rti_endpoint_prefix, 'proc/{proc_id}/jobs',
                               self.submit, Job, [check_if_user]),

            EndpointDefinition('PUT', rti_endpoint_prefix, 'proc/{proc_id}/jobs',
                               self.resume, Job, [check_if_user]),

            EndpointDefinition('GET', rti_endpoint_prefix, 'proc/{proc_id}/jobs',
                               self.jobs_by_proc, List[Job], [check_if_user]),

            EndpointDefinition('GET', rti_endpoint_prefix, 'job',
                               self.jobs_by_user, List[Job], [check_if_user]),

            EndpointDefinition('GET', rti_endpoint_prefix, 'job/{job_id}/status',
                               self.job_status, JobStatus, [check_if_user]),

            EndpointDefinition('GET', rti_endpoint_prefix, 'job/{job_id}/logs',
                               self.job_logs, None, [check_if_user]),

            EndpointDefinition('DELETE', rti_endpoint_prefix, 'job/{job_id}',
                               self.job_cancel, JobStatus, [check_if_user]),

            EndpointDefinition('POST', rti_endpoint_prefix, 'permission/{req_id}',
                               self.put_permission, None, [check_if_user])
        ]

    # NodeDB endpoints:

    def get_node(self) -> NodeInfo:
        """
        Retrieves information about the node.
        """
        proxy = NodeDBProxy(self._node_address)
        result = proxy.get_node()
        return result

    def get_network(self) -> List[NodeInfo]:
        """
        Retrieves information about all peers known to the node.
        """
        proxy = NodeDBProxy(self._node_address)
        result = proxy.get_network()
        return result

    def get_identity(self, iid: str) -> Optional[Identity]:
        """
        Retrieves the identity given its id (if the node db knows about it).
        """
        # if it's the iid of the Relay proxy identity, return the proxy
        if iid in self._user_to_proxy:
            return self._user_to_proxy[iid]
        else:
            proxy = NodeDBProxy(self._node_address)
            result = proxy.get_identity(iid)
            return result

    def get_identities(self) -> List[Identity]:
        """
        Retrieves a list of all identities known to the node.
        """
        proxy = NodeDBProxy(self._node_address)
        result = proxy.get_identities()
        return list(result.values())

    def update_identity(self, identity: Identity, user: User = Depends(get_current_active_user)) -> Identity:
        """
        Updates an existing identity or adds a new one in case an identity with the id does not exist yet.
        """

        # is this an update on a proxy identity to be used for the Relay only?
        if identity.name.startswith('relay_proxy:'):
            # check if the username checks out (it's not strictly speaking important but just an additional check)
            name = identity.name[len('relay_proxy:'):]
            if name != user.login:
                raise RelayRuntimeError(f"User login and relay proxy identity name don't match: {user.login} != {name}")

            # map the proxy identity to the user
            self._user_to_proxy[user.identity.id] = identity

            # we publish and return the actual identity of the user so the SDK may use it if/when needed.
            proxy = NodeDBProxy(self._node_address)
            result = proxy.update_identity(user.identity)
            return result

        else:
            proxy = NodeDBProxy(self._node_address)
            result = proxy.update_identity(identity)
            return result

    # DOR endpoints:

    def _find_all_dors(self) -> List[NodeInfo]:
        db = NodeDBProxy(self._node_address)
        result = []
        for node in db.get_network():
            if node.dor_service:
                result.append(node)
        return result

    def _find_dor_with_object(self, obj_id: str) -> (Optional[NodeInfo], Optional[Union[CDataObject, GPPDataObject]]):
        dors = self._find_all_dors()
        if len(dors) == 0:
            raise RelayRuntimeError("No DORs found")

        for node in dors:
            dor = DORProxy(node.rest_address)
            meta = dor.get_meta(obj_id)
            if meta is not None:
                return node, meta

        return None, None

    def search(self, p: SearchParameters) -> List[Union[CDataObject, GPPDataObject]]:
        """
        Searches a DOR for data objects that match the search criteria. There are two kinds of criteria: constraints
        and patterns. Search constraints are conjunctive, i.e., all constraints have to be matched in order for a data
        objective to be considered for inclusion in the search result. Constraints include: `owner_iid`, `data_type`,
        `data_format` or list of `c_hashes`. After applying the search constraints, the result set is further filtered
        by the search patterns. Unlike constraints, search patterns are disjunctive, i.e., so long as any of the
        patterns is matched, the data object is included in the final result set. Search patterns are applied to the
        data object tags only. A search pattern is considered matched if it is a substring of either tag key or value.
        """

        all_results = []
        for node in self._find_all_dors():
            dor = DORProxy(node.rest_address)
            result = dor.search(patterns=p.patterns, owner_iid=p.owner_iid, data_type=p.data_type,
                                data_format=p.data_format, c_hashes=p.c_hashes)
            all_results.extend(result)

        return all_results

    def statistics(self) -> DORStatistics:
        """
        Retrieves some statistics from the DOR. This includes a list of all data types and formats found in the DOR.
        """

        data_types = set()
        data_formats = set()
        for node in self._find_all_dors():
            dor = DORProxy(node.rest_address)
            stats = dor.statistics()

            data_types = data_types.union(stats.data_types)
            data_formats = data_formats.union(*stats.data_formats)

        return DORStatistics(data_types=list(data_types), data_formats=list(data_formats))

    def add_c(self, body: str = Form(...), attachment: UploadFile = File(...),
              user: User = Depends(get_current_active_user)) -> CDataObject:
        """
        Adds a new content data object to the DOR and returns the meta information for this data object. The content
        of the data object itself is uploaded as an attachment (binary). There is no restriction as to the nature or
        size of the content.
        """

        # create parameters object
        p = AddCDataObjectParameters.parse_obj(json.loads(body))

        # find all dors
        dors = self._find_all_dors()
        if len(dors) == 0:
            raise RelayRuntimeError("No DORs found")

        # temp file for attachment
        attachment_path = os.path.join(self._wd_path, f"{get_timestamp_now()}_{generate_random_string(4)}")
        try:
            with open(attachment_path, 'wb') as f:
                while True:
                    chunk = attachment.file.read(4)
                    if not chunk:
                        break

                    chunk_length = int.from_bytes(chunk, 'big')
                    chunk = attachment.file.read(chunk_length)
                    chunk = snappy.decompress(chunk)
                    f.write(chunk)

        except Exception as e:
            raise RelayRuntimeError("upload failed", details={'exception': e})

        finally:
            attachment.file.close()

        # pick one // TODO: users should be able to indicate preference
        dor = DORProxy(dors[0].rest_address)
        obj = dor.add_data_object(attachment_path, owner=user.identity, access_restricted=p.access_restricted,
                                  content_encrypted=p.content_encrypted, data_type=p.data_type,
                                  data_format=p.data_format, recipe=p.recipe, license_by=p.license.by,
                                  license_nc=p.license.nc, license_nd=p.license.nd, license_sa=p.license.sa)

        # delete the temp file
        os.remove(attachment_path)

        return obj

    def add_gpp(self, p: AddGPPDataObjectParameters, user: User = Depends(get_current_active_user)) -> GPPDataObject:
        """
        Adds a Git-Processor-Pointer (GPP) data object to the DOR and returns the meta information for this data object.
        If the repository specified in the GPP information is private, valid  credentials need to be provided. The DOR
        will use these credentials to access (i.e., clone) the repository. Note that the credentials information will
        not be stored by the DOR.
        """
        raise RelayRuntimeError("Adding GPP data objects is not supported by the Relay application.")

    def remove(self, obj_id: str,
               user: User = Depends(get_current_active_user)) -> Optional[Union[CDataObject, GPPDataObject]]:
        """
        Deletes a data object from the DOR and returns the meta information of that data object. Authorisation by the
        data object owner is required.
        """

        # find all dors
        dors = self._find_all_dors()
        if len(dors) == 0:
            raise RelayRuntimeError("No DORs found")

        for node in dors:
            dor = DORProxy(node.rest_address)
            meta = dor.delete_data_object(obj_id, with_authorisation_by=user.keystore)
            if meta is not None:
                return meta

        return None

    def get_meta(self, obj_id: str) -> Optional[Union[CDataObject, GPPDataObject]]:
        """
        Retrieves the meta information of a data object. Depending on the type of the data object, either a
        `CDataObject` or a `GPPDataObject` is returned, providing meta information for content and GPP data objects,
        respectively.
        """
        # find all dors
        dors = self._find_all_dors()
        if len(dors) == 0:
            raise RelayRuntimeError("No DORs found")

        for node in dors:
            dor = DORProxy(node.rest_address)
            meta = dor.get_meta(obj_id)
            if meta is not None:
                return meta

        return None

    def get_content(self, obj_id: str, user: User = Depends(get_current_active_user)) -> Response:
        """
        Retrieves the content of a data object. Authorisation required by a user who has been granted access to the
        data object.
        """

        # find all dors
        dors = self._find_all_dors()
        if len(dors) == 0:
            raise RelayRuntimeError("No DORs found")

        for node in dors:
            dor = DORProxy(node.rest_address)
            meta = dor.get_meta(obj_id)
            if meta is not None:
                # store the contents temporarily
                download_path = os.path.join(self._wd_path, f"{get_timestamp_now()}_{generate_random_string(4)}")
                dor.get_content(obj_id, with_authorisation_by=user.keystore, download_path=download_path)

                return _stream_contents(download_path)

        raise RelayRuntimeError(f"Data object {obj_id} not found.")

    def get_provenance(self, c_hash: str) -> Optional[DataObjectProvenance]:
        """
        Retrieves the provenance information of a data object (identified by its content hash `c_hash`). Provenance
        data includes detailed information how the content of a data object has been produced. In principle, this
        information enables users to reproduce the contents by repeating the exact same steps. Note that it is possible
        that there are multiple routes by which a content can be generated. Depending on the use case, this kind of
        situation is likely to be rare. However, careful analysis of the provenance information might be needed to
        understand how the content has been created.
        """

        # find all dors
        dors = self._find_all_dors()
        if len(dors) == 0:
            raise RelayRuntimeError("No DORs found")

        for node in dors:
            dor = DORProxy(node.rest_address)
            provenance = dor.get_provenance(c_hash)
            if provenance is not None:
                return provenance

        return None

    def grant_access(self, obj_id: str, target_user_iid: str,
                     user: User = Depends(get_current_active_user)) -> Union[CDataObject, GPPDataObject]:
        """
        Grants a user the right to access the contents of a restricted data object. Authorisation required by the owner
        of the data object. Note that access rights only matter if the data object has access restrictions.
        """

        # find dor with object
        node, meta = self._find_dor_with_object(obj_id)
        if node is None or meta is None:
            raise RelayRuntimeError(f"Data object {obj_id} not found.")

        # get the identity of the target user that we want to grant access
        identity = self.get_identity(target_user_iid)
        if identity is None:
            raise RelayRuntimeError(f"No user with iid={target_user_iid} found.")

        # is the calling user the data object owner?
        if meta.owner_iid != user.identity.id:
            raise RelayRuntimeError(f"Calling user (id={user.identity.id}, name={user.name}) "
                                    f"does not own data object {obj_id}.")

        # try to grant access
        dor = DORProxy(node.rest_address)
        meta = dor.grant_access(obj_id, authority=user.keystore, identity=identity)

        return meta

    def revoke_access(self, obj_id: str, target_user_iid: str,
                      user: User = Depends(get_current_active_user)) -> Union[CDataObject, GPPDataObject]:
        """
        Revokes the right to access the contents of a restricted data object from a user. Authorisation required by the
        owner of the data object. Note that access rights only matter if the data object has access restrictions.
        """

        # find dor with object
        node, meta = self._find_dor_with_object(obj_id)
        if node is None or meta is None:
            raise RelayRuntimeError(f"Data object {obj_id} not found.")

        # get the identity of the target user whose access we want to revoke
        identity = self.get_identity(target_user_iid)
        if identity is None:
            raise RelayRuntimeError(f"No user with iid={target_user_iid} found.")

        # is the calling user the data object owner?
        if meta.owner_iid != user.identity.id:
            raise RelayRuntimeError(f"Calling user (id={user.identity.id}, name={user.name}) "
                                    f"does not own data object {obj_id}.")

        # try to grant access
        dor = DORProxy(node.rest_address)
        meta = dor.revoke_access(obj_id, authority=user.keystore, identity=identity)

        return meta

    def transfer_ownership(self, obj_id: str, new_owner_iid: str,
                           user: User = Depends(get_current_active_user)) -> Union[CDataObject, GPPDataObject]:
        """
        Transfers the ownership of a data object to another user. Authorisation required by the current owner of the
        data object.
        """

        # find dor with object
        node, meta = self._find_dor_with_object(obj_id)
        if node is None or meta is None:
            raise RelayRuntimeError(f"Data object {obj_id} not found.")

        # get the identity of the new owner
        identity = self.get_identity(new_owner_iid)
        if identity is None:
            raise RelayRuntimeError(f"No user with iid={new_owner_iid} found.")

        # is the calling user the data object owner?
        if meta.owner_iid != user.identity.id:
            raise RelayRuntimeError(f"Calling user (id={user.identity.id}, name={user.name}) "
                                    f"does not own data object {obj_id}.")

        # try to grant access
        dor = DORProxy(node.rest_address)
        meta = dor.transfer_ownership(obj_id, authority=user.keystore, new_owner=identity)

        return meta

    def update_tags(self, obj_id: str, tags: List[DataObject.Tag],
                    user: User = Depends(get_current_active_user)) -> Union[CDataObject, GPPDataObject]:
        """
        Adds tags to a data object or updates tags in case they already exist. Authorisation required by the owner of
        the data object.
        """
        # find dor with object
        node, meta = self._find_dor_with_object(obj_id)
        if node is None or meta is None:
            raise RelayRuntimeError(f"Data object {obj_id} not found.")

        # is the calling user the data object owner?
        if meta.owner_iid != user.identity.id:
            raise RelayRuntimeError(f"Calling user (id={user.identity.id}, name={user.name}) "
                                    f"does not own data object {obj_id}.")

        # try to grant access
        dor = DORProxy(node.rest_address)
        meta = dor.update_tags(obj_id, authority=user.keystore, tags=tags)

        return meta

    def remove_tags(self, obj_id: str, keys: List[str],
                    user: User = Depends(get_current_active_user)) -> Union[CDataObject, GPPDataObject]:
        """
        Removes tags from a data object. Authorisation required by the owner of the data object.
        """
        # find dor with object
        node, meta = self._find_dor_with_object(obj_id)
        if node is None or meta is None:
            raise RelayRuntimeError(f"Data object {obj_id} not found.")

        # is the calling user the data object owner?
        if meta.owner_iid != user.identity.id:
            raise RelayRuntimeError(f"Calling user (id={user.identity.id}, name={user.name}) "
                                    f"does not own data object {obj_id}.")

        # try to grant access
        dor = DORProxy(node.rest_address)
        meta = dor.remove_tags(obj_id, authority=user.keystore, keys=keys)

        return meta

    # RTI endpoints:

    def _find_all_rtis(self) -> List[NodeInfo]:
        db = NodeDBProxy(self._node_address)
        result = []
        for node in db.get_network():
            if node.rti_service:
                result.append(node)
        return result

    def deployed(self) -> List[Processor]:
        """
        Retrieves a list of all processors that are deployed by the RTI.
        """

        all_results = []
        for node in self._find_all_rtis():
            rti = RTIProxy(node.rest_address)
            results = rti.get_deployed()
            all_results.extend(results)

        return all_results

    def deploy(self, proc_id: str, p: DeployParameters, user: User = Depends(get_current_active_user)) -> Processor:
        """
        Deploys a processor to the RTI. By default, the processor is deployed on the same machine that hosts the RTI.
        If the processor is supposed to be deployed on a remote machine, corresponding SSH credentials have to be
        provided which the RTI can use to access the remote machine. Note that SSH credentials will be stored and used
        by the RTI to be able to access the remotely deployed processor. Deployment requires the RTI to access the
        repository that contains the processor code. If the repository is not public, corresponding GitHub credentials
        need to be provided. Note that GitHub credentials are not stored. Note that all credentials information must
        not be sent in plaintext but instead encrypted using the corresponding public encryption key of the RTI node.
        """
        raise RelayRuntimeError("Processor deployment and undeployment not supported by Relay app.")

    def undeploy(self, proc_id: str, user: User = Depends(get_current_active_user)) -> Processor:
        """
        Shuts down a deployed processor and removes it from the list of deployed processor hosted by the RTI. If
        SSH credentials have been used by this processor for remote deployment, then the stored SSH credentials will
        be deleted as well.
        """
        raise RelayRuntimeError("Processor deployment and undeployment not supported by Relay app.")

    def gpp(self, proc_id: str) -> GitProcessorPointer:
        """
        Retrieves the Git-Processor-Pointer (GPP) information of a deployed processor.
        """
        for node in self._find_all_rtis():
            rti = RTIProxy(node.rest_address)
            for proc in rti.get_deployed():
                if proc.proc_id == proc_id:
                    return proc.gpp

        raise RelayRuntimeError(f"Processor {proc_id} not found/deployed.")

    def status(self, proc_id: str) -> ProcessorStatus:
        """
        Retrieves status information for a deployed processor.
        """
        for node in self._find_all_rtis():
            rti = RTIProxy(node.rest_address)
            for proc in rti.get_deployed():
                if proc.proc_id == proc_id:
                    return rti.get_status(proc_id)

        raise RelayRuntimeError(f"Processor {proc_id} not found/deployed.")

    def submit(self, proc_id: str, task: Task, user: User = Depends(get_current_active_user)) -> Job:
        """
        Submits a task to a deployed processor, thereby creating a new job. The job is queued and executed once the
        processor has the capacity to do so. Authorisation is required by the owner of the task/job.
        """
        # get the proxy identity for this user
        proxy_identity = self._user_to_proxy.get(user.identity.id)
        if not proxy_identity:
            raise RelayRuntimeError(f"No proxy identity found for user {user.login}")

        for node in self._find_all_rtis():
            rti = RTIProxy(node.rest_address)
            for proc in rti.get_deployed():
                if proc.proc_id == proc_id:
                    # update the references to the users' identity
                    for i in task.input:
                        if isinstance(i, Task.InputReference):
                            # do we need a user signature? verify against the proxy identity and recreate using the
                            # users' actual identity
                            if i.user_signature:
                                message = f"{node.identity.id}:{i.obj_id}".encode('utf-8')
                                if not proxy_identity.verify(message, i.user_signature):
                                    raise RelayRuntimeError(f"Signature verification failed for task input reference: "
                                                            f"{i.name}")

                                # update with new signature
                                i.user_signature = user.keystore.sign(f"{node.identity.id}:{i.obj_id}".encode('utf-8'))

                    # update output owners
                    for o in task.output:
                        if o.owner_iid == proxy_identity.id:
                            o.owner_iid = user.identity.id

                    job = rti.submit_job(proc_id, job_input=task.input, job_output=task.output,
                                         with_authorisation_by=user.keystore, name=task.name,
                                         description=task.description)
                    self._job_mapping[job.id] = node
                    return job

        raise RelayRuntimeError(f"Processor {proc_id} not found/deployed.")

    def resume(self, proc_id: str, job: Job, reconnect: ReconnectInfo,
               user: User = Depends(get_current_active_user)) -> Job:
        """
        Attempts to resume monitoring an existing job that may have lost connectivity. This may be the case for jobs
        that are executed remotely. It is not guaranteed that resume is successful and depends on whether the
        underlying reasons for the disconnect (e.g., network outage) have been resolved. Authorisation is required by
        the owner of the job (i.e., the user that has created the job by submitting the task in the first place).
        """
        for node in self._find_all_rtis():
            rti = RTIProxy(node.rest_address)
            for proc in rti.get_deployed():
                if proc.proc_id == proc_id:
                    job = rti.resume_job(proc_id, job, reconnect, with_authorisation_by=user.keystore)
                    self._job_mapping[job.id] = node
                    return job

        raise RelayRuntimeError(f"Processor {proc_id} not found/deployed.")

    def jobs_by_proc(self, proc_id: str) -> List[Job]:
        """
        Retrieves a list of jobs processed by a processor. Any job that is pending execution or actively executed will
        be included in the list. Past jobs, i.e., jobs that have completed execution (successfully or not) will not be
        included in this list.
        """
        all_results = []
        for node in self._find_all_rtis():
            rti = RTIProxy(node.rest_address)
            for proc in rti.get_deployed():
                if proc.proc_id == proc_id:
                    result = rti.get_jobs_by_proc(proc_id)
                    all_results.extend(result)

        return all_results

    def jobs_by_user(self, user: User = Depends(get_current_active_user)) -> List[Job]:
        """
        Retrieves a list of jobs owned by a user. Any job that is pending execution or actively executed will be
        included in the list. Past jobs, i.e., jobs that have completed execution (successfully or not) will not be
        included in this list.
        """
        all_results = []
        for node in self._find_all_rtis():
            rti = RTIProxy(node.rest_address)
            result = rti.get_jobs_by_user(authority=user.keystore)
            all_results.extend(result)

        return all_results

    def job_status(self, job_id: str, user: User = Depends(get_current_active_user)) -> JobStatus:
        """
        Retrieves detailed information about the status of a job. Authorisation is required by the owner of the job
        (i.e., the user that has created the job by submitting the task in the first place).
        """

        # do we know about this job?
        node = self._job_mapping.get(job_id)
        if node is None:
            raise RelayRuntimeError(f"Job {job_id} does not exist or not known to the Relay application.")

        # get the status
        rti = RTIProxy(node.rest_address)
        status = rti.get_job_status(job_id, with_authorisation_by=user.keystore)
        return status

    def job_logs(self, job_id: str, user: User = Depends(get_current_active_user)) -> Response:
        """
        Attempts to retrieve the execution logs of a job. This includes stdout and stderr output that has been
        generated during job execution. Depending on the status of the job (is the job already running or has it
        finished execution?) and on the underlying implementation of the processor (is stdout/stderr output generated?)
        logs may or may not be available. Logs will be archived using tar.gz and delivered as binary stream for the
        client to download.
        """

        # do we know about this job?
        node = self._job_mapping.get(job_id)
        if node is None:
            raise RelayRuntimeError(f"Job {job_id} does not exist or not known to the Relay application.")

        # store the contents temporarily
        download_path = os.path.join(self._wd_path, f"{get_timestamp_now()}_{generate_random_string(4)}")
        rti = RTIProxy(node.rest_address)
        rti.get_job_logs(job_id, with_authorisation_by=user.keystore, download_path=download_path)

        return _stream_contents(download_path)

    def job_cancel(self, job_id: str, user: User = Depends(get_current_active_user)) -> JobStatus:
        """
        Attempts to cancel a running job. Depending on the implementation of the processor, this may or may not be
        possible.
        """

        # do we know about this job?
        node = self._job_mapping.get(job_id)
        if node is None:
            raise RelayRuntimeError(f"Job {job_id} does not exist or not known to the Relay application.")

        # cancel the job
        rti = RTIProxy(node.rest_address)
        status = rti.cancel_job(job_id, with_authorisation_by=user.keystore)

        return status

    def put_permission(self, req_id: str, permission: Permission) -> None:
        """
        Uploads a permission for a specific request. This is normally only required in case of encrypted data objects.
        When a processor needs to process an encrypted data object, it requires the necessary permissions (and content
        key) to process the data object. For this purpose, the RTI will request the content key during the
        initialisation phase of a job. Data object Owners can then submit the required content key using this endpoint.
        The request itself is encrypted using the public key of the data object owner and provides the following
        information:
        `{
          'type': 'request_content_key',
          'req_id': 'H2dofbWhSZddTah9'
          'obj_id': '1e6e ... f6be',
          'ephemeral_public_key': 'MIIC ... Q==',
          'user_iid': 'fyll ... ev00',
          'node_id': '9mip ... x85y'
        }`
        """
        raise RelayRuntimeError("Permission submission not supported by Relay app.")
