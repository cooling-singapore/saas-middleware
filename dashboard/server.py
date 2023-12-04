import json
import os
from tempfile import NamedTemporaryFile
from typing import List, Union, Dict, Optional

from fastapi import Depends, Form, UploadFile, File
from fastapi.responses import Response, StreamingResponse, FileResponse
from pydantic import BaseModel

from saas.meta import __version__
from saas.core.exceptions import ExceptionContent
from saas.core.helpers import generate_random_string, validate_json
from saas.core.logging import Logging
from saas.dor.schemas import CDataObject, GPPDataObject, DataObject
from saas.rest.schemas import EndpointDefinition
from saas.rti.schemas import Processor, Job
from saas.sdk.app.auth import User
from saas.sdk.app.base import Application, get_current_active_user
from saas.sdk.base import SDKJob, SDKProductSpecification

from dashboard import schemas as app_schemas
from dashboard.proxy import endpoint_prefix_base

logger = Logging.get('dashboard.server')


class DashboardRuntimeError(Exception):
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


class JobSubmissionParameters(BaseModel):
    class InputItem(BaseModel):
        name: str
        content: Union[str, dict]

    class OutputItem(BaseModel):
        name: str
        restricted_access: bool
        content_encrypted: bool
        target_node_iid: Optional[str]

    name: str
    description: str
    proc_id: str
    input: List[InputItem]
    output: List[OutputItem]


class UploadContentParameters(BaseModel):
    data_type: str
    data_format: str
    restricted_access: bool
    content_encrypted: bool
    license_by: bool
    license_sa: bool
    license_nc: bool
    license_nd: bool
    preferred_dor_iid: Optional[str]
    tags: Optional[List[DataObject.Tag]]


class UploadGPPParameters(BaseModel):
    source: str
    commit_id: str
    proc_path: str
    proc_config: str
    preferred_dor_iid: Optional[str]
    tags: Optional[List[DataObject.Tag]]


def convert_job_content(job: SDKJob, include_status: bool) -> dict:
    # get the status?
    status = job.status if include_status else None

    # turn output dict into list
    output = []
    if status:
        for key, item in job.status.output.items():
            obj = item.dict()
            obj['output_name'] = key
            output.append(obj)

    return {
        'job': job.content,
        'proc_id': job.content.task.proc_id,
        'user_iid': job.content.task.user_iid,
        'input': job.content.task.input,
        'output': job.content.task.output,
        'state': status.state if status else 'unknown',
        'progress': status.progress if status else -1,
        'errors': status.errors if status else None,
        'output_objects': output
    }


class DashboardServer(Application):
    def __init__(self, server_address: (str, int), node_address: (str, int), wd_path: str) -> None:
        super().__init__(server_address, node_address, (endpoint_prefix_base, None), wd_path,
                         'Simulation-as-a-Service Dashboard', __version__,
                         'Web application to interact with processors deployed on SaaS Middleware nodes.')

        # create cached data object folder
        self._cache_path = os.path.join(wd_path, 'cache')
        os.makedirs(self._cache_path, exist_ok=True)

        self._jobs: Dict[str, SDKJob] = {}

    def endpoints(self) -> List[EndpointDefinition]:
        return [
            EndpointDefinition('GET', self.endpoint_prefix, 'processors',
                               self.get_processors, List[Processor], None),

            EndpointDefinition('POST', self.endpoint_prefix, 'job',
                               self.submit_job, Job, None),

            EndpointDefinition('GET', self.endpoint_prefix, 'job/{job_id}',
                               self.get_job, dict, None),

            EndpointDefinition('GET', self.endpoint_prefix, 'jobs',
                               self.get_all_jobs, List[dict], None),

            EndpointDefinition('DELETE', self.endpoint_prefix, 'job/{job_id}',
                               self.cancel_job, dict, None),

            EndpointDefinition('POST', self.endpoint_prefix, 'data/content',
                               self.upload_content, CDataObject, None),

            EndpointDefinition('POST', self.endpoint_prefix, 'data/gpp',
                               self.upload_gpp, GPPDataObject, None),

            EndpointDefinition('GET', self.endpoint_prefix, 'data',
                               self.search_data, List[Union[CDataObject, GPPDataObject]], None),

            EndpointDefinition('GET', self.endpoint_prefix, 'data/{obj_id}/meta',
                               self.get_meta, Union[CDataObject, GPPDataObject], None),

            EndpointDefinition('GET', self.endpoint_prefix, 'data/{obj_id}/content',
                               self.download_content, None, None),

            EndpointDefinition('GET', self.endpoint_prefix, 'data/{obj_id}/feature',
                               self.download_feature, None, None),

            EndpointDefinition('DELETE', self.endpoint_prefix, 'data/{obj_id}',
                               self.delete_data, Union[CDataObject, GPPDataObject], None),

            EndpointDefinition('GET', self.endpoint_prefix, 'provenance/{obj_id}',
                               self.provenance, app_schemas.DataObjectProvenance, None)
        ]

    def get_processors(self, user: User = Depends(get_current_active_user)) -> List[Processor]:
        """
        Retrieves a list of all processors that are known to be deployed across the network.
        """
        context = self._get_context(user)
        results = context.find_processors()
        return [result.descriptor for result in results]

    def submit_job(self, request: JobSubmissionParameters, user: User = Depends(get_current_active_user)) -> Job:
        """
        Submits a job.
        """
        context = self._get_context(user)

        # get the processor
        proc = context.find_processor_by_id(request.proc_id)
        if not proc:
            raise DashboardRuntimeError(f"Processor {request.proc_id} not deployed/found")

        # get by-value data object schemas (if any)
        schemas = {}
        for input_desc in proc.descriptor.gpp.proc_descriptor.input:
            if input_desc.data_schema is not None:
                schemas[input_desc.name] = input_desc.data_schema

        # create consume specification
        consume_specs = {}
        for item in request.input:
            if isinstance(item.content, dict):
                # if we have a by-value item, validate the content
                if item.name in schemas and not validate_json(item.content, schemas[item.name]):
                    raise DashboardRuntimeError(f"Invalid content for by-value input '{item.name}'")

                consume_specs[item.name] = item.content

            else:
                # search for the by-reference data object
                content = context.find_data_object(item.content)
                if content is None:
                    raise DashboardRuntimeError(f"No content data object found for by-reference input '{item.name}'")

                consume_specs[item.name] = content

        # create product specification
        product_specs = {}
        for item in request.output:
            # get the target DOR
            target = context.dor(item.target_node_iid)
            if target is None:
                raise DashboardRuntimeError(f"Target DOR {item.target_node_iid} for output '{item.name}' not found.")

            product_specs[item.name] = SDKProductSpecification(
                restricted_access=item.restricted_access,
                content_encrypted=item.content_encrypted,
                target_node=target,
                owner=user.keystore.identity
            )

        # submit the job
        job = proc.submit(consume_specs=consume_specs, product_specs=product_specs,
                          name=request.name, description=request.description)
        return job.content

    def get_job(self, job_id: str, user: User = Depends(get_current_active_user)) -> dict:
        """
        Retrieves the status of a job.
        """
        # do we have the job cached?
        if job_id in self._jobs:
            job: SDKJob = self._jobs[job_id]

        else:
            context = self._get_context(user)
            job = context.find_job(job_id)
            if not job:
                raise DashboardRuntimeError(f"Job {job_id} not found or not owned by the user")
            self._jobs[job_id] = job

        return convert_job_content(job, True)

    def get_all_jobs(self, user: User = Depends(get_current_active_user)) -> List[dict]:
        """
        Retrieves the status of all jobs by the user. It only includes jobs for which a job status could be found.
        There might be jobs without status that are not included in the result.
        """

        # do we have cached jobs?
        cached: Dict[str, SDKJob] = {}
        for job_id, job in self._jobs.items():
            if job.status:
                cached[job_id] = job

        # also check with the SDK
        context = self._get_context(user)
        jobs = context.find_all_jobs_with_status()
        for job in jobs:
            cached[job.content.id] = job

        # build result list
        result: List[dict] = [convert_job_content(job, False) for job in cached.values()]

        return result

    def cancel_job(self, job_id: str, user: User = Depends(get_current_active_user)) -> dict:
        """
        Cancels a job.
        """
        # do we have the job cached?
        if job_id in self._jobs:
            job: SDKJob = self._jobs[job_id]

        else:
            context = self._get_context(user)
            job = context.find_job(job_id)
            if not job:
                raise DashboardRuntimeError(f"Job {job_id} not found or not owned by the user")
            self._jobs[job_id] = job

        # remove the job
        self._jobs.pop(job_id)

        # cancel the job
        job.cancel()
        job.refresh_status()

        return convert_job_content(job, True)

    def upload_content(self, body: str = Form(...), attachment: UploadFile = File(...),
                       user: User = Depends(get_current_active_user)) -> CDataObject:
        """
        Uploads a new content data object returns the meta information for this data object. The content of the
        data object itself is uploaded as an attachment (binary). There is no restriction as to the nature or
        size of the content.
        """
        # create parameters object
        p = UploadContentParameters.parse_obj(json.loads(body))

        try:
            with NamedTemporaryFile() as f:
                f.write(attachment.file.read())
                f.flush()

                # upload the content
                context = self._get_context(user)
                obj = context.upload_content(f.name, data_type=p.data_type, data_format=p.data_format,
                                             access_restricted=p.restricted_access, content_encrypted=p.content_encrypted,
                                             license_by=p.license_by, license_sa=p.license_sa, license_nc=p.license_nc,
                                             license_nd=p.license_nd, preferred_dor_iid=p.preferred_dor_iid)

                # update the tags
                obj.update_tags(p.tags)

                return obj.meta

        except Exception as e:
            raise DashboardRuntimeError("upload failed while receiving data from client", details={'exception': e})

        finally:
            attachment.file.close()

    def upload_gpp(self, p: UploadGPPParameters, user: User = Depends(get_current_active_user)) -> GPPDataObject:
        """
        Uploads a new GPP data object.
        """
        context = self._get_context(user)
        gpp = context.upload_gpp(source=p.source, commit_id=p.commit_id, proc_path=p.proc_path,
                                 proc_config=p.proc_config, preferred_dor_iid=p.preferred_dor_iid)

        # update the tags
        gpp.update_tags(p.tags)

        return gpp.meta

    def search_data(self, patterns: str = None, owned_by_user: str = None, data_type: str = None,
                    data_format: str = None, c_hashes: str = None,
                    user: User = Depends(get_current_active_user)) -> List[Union[CDataObject, GPPDataObject]]:
        """
        Searches for data objects. Search is conducted in two steps. In the first step, the set of data objects is
        filtered by applying any of the constraints: owned_by_user, data_type, data_format, and c_hashes. All
        constraints must be matched exactly in order for a data object to be shortlisted. The shortlisted data objects
        are further filtered by applying the search patterns to the tags. As long as any pattern is found in any of the
        tags, a data object is returned as part of the result.

        Note that patterns and c_hashes can be comma separated list of values.
        """

        # unpack the comma separated lists
        patterns = patterns.split(',') if patterns else None
        c_hashes = c_hashes.split(',') if c_hashes else None

        # determine owner iid
        owner_iid = user.identity.id if owned_by_user and owned_by_user.lower() == 'true' else None

        # find data objects
        context = self._get_context(user)
        results = context.find_data_objects(patterns, owner_iid, data_type, data_format, c_hashes)
        results = [result.meta for result in results]
        return results

    def get_meta(self, obj_id: str, user: User = Depends(get_current_active_user)) -> Union[CDataObject, GPPDataObject]:
        """
        Retrieves the meta information about a data object.
        """
        context = self._get_context(user)

        # can we find this data object?
        obj = context.find_data_object(obj_id)
        if not obj:
            raise DashboardRuntimeError(f"Data object {obj_id} not found")

        return obj.meta

    def download_content(self, obj_id: str, user: User = Depends(get_current_active_user)) -> Response:
        """
        Downloads the content of a data object.
        """
        context = self._get_context(user)

        # can we find this data object?
        obj = context.find_data_object(obj_id)
        if not obj:
            raise DashboardRuntimeError(f"Data object {obj_id} not found")

        # download the data object content (unless we have it already)
        content_path = os.path.join(self._cache_path, obj.meta.obj_id)
        if not os.path.isfile(content_path):
            obj.download(content_path)

        return FileResponse(content_path, media_type='application/octet-stream')

    def download_feature(self, obj_id: str, parameters: dict,
                         user: User = Depends(get_current_active_user)) -> Response:
        """
        Downloads a data object type-specific feature for a data object.
        """
        context = self._get_context(user)

        # check if the server supports this data object type
        with self._mutex:
            dot = self._dots[parameters['data_type']] if 'data_type' in parameters else None
            if not dot:
                raise DashboardRuntimeError(f"Data object type {parameters['data_type']} not supported by server")

        # can we find this data object?
        obj = context.find_data_object(obj_id)
        if not obj:
            raise DashboardRuntimeError(f"Data object {obj_id} not found")

        # download the data object content (unless we have it already)
        content_path = os.path.join(self._cache_path, obj_id)
        if not os.path.isfile(content_path):
            obj.download(content_path)

        # extract the feature and stream it back
        feature = dot.extract_feature(content_path, parameters)

        async def streamer():
            yield json.dumps(feature).encode('utf-8')

        return StreamingResponse(
            content=streamer(),
            media_type='application/octet-stream'
        )

    def delete_data(self, obj_id: str, user: User = Depends(get_current_active_user)) -> Union[CDataObject,
                                                                                               GPPDataObject]:
        """
        Deletes a data object.
        """
        context = self._get_context(user)

        # can we find this data object?
        obj = context.find_data_object(obj_id)
        if not obj:
            raise DashboardRuntimeError(f"Data object {obj_id} not found")

        # delete the data object
        meta = obj.delete()
        return meta

    def provenance(self, obj_id: str, user: User = Depends(get_current_active_user)) -> app_schemas.DataObjectProvenance:
        """
        Retrieves the provenance information of a data object.
        """
        context = self._get_context(user)

        # can we find this data object?
        obj = context.find_data_object(obj_id)
        if not obj:
            raise DashboardRuntimeError(f"Data object {obj_id} not found")

        tmp = obj.get_provenance()

        # convert provenance
        provenance = app_schemas.DataObjectProvenance(
            data_nodes=[{'key': key, 'value': value} for key, value in tmp.data_nodes.items()],
            proc_nodes=[{'key': key, 'value': value} for key, value in tmp.proc_nodes.items()],
            steps=[{
                'processor': step.processor,
                'consumes': [{'name': s_name, 'id': s_id} for s_name, s_id in step.consumes.items()],
                'produces': [{'name': s_name, 'id': s_id} for s_name, s_id in step.produces.items()]
            } for step in tmp.steps],
            missing=tmp.missing
        )

        # check if we have data objects with the content hashes of the data nodes
        result = context.find_data_objects(c_hashes=[c_hash for c_hash in tmp.data_nodes.keys()])
        lookup = {}
        for obj in result:
            if obj.meta.c_hash not in lookup:
                lookup[obj.meta.c_hash] = [obj.meta]
            else:
                lookup[obj.meta.c_hash].append(obj.meta)

        # add the 'known_objects' information to the data nodes
        for item in provenance.data_nodes:
            c_hash = item['key']
            item['known_objects'] = lookup[c_hash] if c_hash in lookup else []

        return provenance
