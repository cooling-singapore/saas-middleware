from __future__ import annotations

import inspect
import json
import os
import pkgutil
import subprocess
from threading import Lock
from typing import Optional, Dict, List, Any, Union

from fastapi import Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy_json import NestedMutableJson

import saas
from saas.core.exceptions import SaaSRuntimeException, ExceptionContent
from saas.core.helpers import generate_random_string, get_timestamp_now
from saas.core.identity import Identity
from saas.core.logging import Logging
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.p2p.exceptions import PeerUnavailableError
import saas.rti.adapters.native as native_rti
import saas.rti.adapters.docker as docker_rti
from saas.rest.auth import VerifyAuthorisation, VerifyProcessorDeployed, VerifyUserIsNodeOwner, \
    VerifyUserIsJobOwnerOrNodeOwner
from saas.rti.adapters.base import RTIProcessorAdapter, ProcessorState, ProcessorStateWrapper, shorten_id, JobContext
from saas.rti.exceptions import JobStatusNotFoundError, GPPDataObjectNotFound, RTIException
from saas.rti.proxy import RTI_ENDPOINT_PREFIX
from saas.rti.schemas import ProcessorStatus, Processor, Job, Task, JobStatus, DeployParameters, Permission
from saas.dor.schemas import GitProcessorPointer, CDataObject
from saas.core.schemas import GithubCredentials, SSHCredentials
from saas.rest.schemas import EndpointDefinition

logger = Logging.get('rti.service')

Base = declarative_base()


class JobRuntimeInformation(BaseModel):
    pending_output: List[str]
    output: Dict[str, CDataObject]
    notes: Dict[str, Union[str, int, float, dict, list]]
    errors: List[JobStatus.Error]
    message: Optional[JobStatus.Message]


class DBContentKeys(Base):
    __tablename__ = 'content_keys'
    key = Column(String(64), primary_key=True)
    value = Column(String, nullable=False)


class DBJobContext(Base):
    __tablename__ = 'job_context'
    job_id = Column(String(8), primary_key=True)
    proc_id = Column(String(64), nullable=False)
    user_id = Column(String(64), nullable=False)
    wd_path = Column(String, nullable=False)
    job = Column(NestedMutableJson, nullable=False)
    state = Column(String, nullable=False)
    progress = Column(Integer, nullable=False)
    info = Column(NestedMutableJson, nullable=False)


class DBProcessorState(Base):
    __tablename__ = 'proc_state'
    proc_id = Column(String(64), primary_key=True)
    proc_adapter = Column(String, nullable=False)
    gpp = Column(NestedMutableJson, nullable=False)
    state = Column(String, nullable=False)
    ssh_credentials = Column(NestedMutableJson, nullable=True)
    github_credentials = Column(NestedMutableJson, nullable=True)


class DBProcessorStateWrapper(ProcessorStateWrapper):
    def __init__(self, session_maker: sessionmaker, proc_id: str):
        self._session_maker = session_maker
        self._proc_id = proc_id
        self._lookup = {member.value: member for member in ProcessorState}

    def state(self) -> ProcessorState:
        with self._session_maker() as session:
            record = session.query(DBProcessorState).filter_by(proc_id=self._proc_id).first()
            if record is not None:
                return self._lookup[record.state]
            else:
                raise RTIException(f"No state found for processor {self._proc_id}")

    def update_state(self, state: ProcessorState) -> ProcessorState:
        with self._session_maker() as session:
            record = session.query(DBProcessorState).filter_by(proc_id=self._proc_id).first()
            if record is not None:
                record.state = state.value
                session.commit()
                return state
            else:
                raise RTIException(f"No state found for processor {self._proc_id}")

    def delete(self) -> None:
        with self._session_maker() as session:
            record = session.query(DBProcessorState).get(self._proc_id)
            if record is not None:
                session.delete(record)
                session.commit()
            else:
                raise RTIException(f"No state found for processor {self._proc_id}")


class DBJobContextWrapper(JobContext):
    def __init__(self, owner: RTIService, session_maker: sessionmaker, job_id: str):
        self._mutex = Lock()
        self._session_maker = session_maker
        self._job_id = job_id
        self._descriptor_path = owner.job_descriptor_path(job_id)
        self._state_mapping = {
            'uninitialised': JobStatus.State.UNINITIALISED,
            'initialised': JobStatus.State.INITIALISED,
            'running': JobStatus.State.RUNNING,
            'postprocessing': JobStatus.State.POSTPROCESSING,
            'successful': JobStatus.State.SUCCESSFUL,
            'failed': JobStatus.State.FAILED,
            'cancelled': JobStatus.State.CANCELLED
        }

        # get the db record and cache some static information
        with session_maker() as session:
            # get the record
            record = session.query(DBJobContext).get(job_id)
            if record is None:
                raise RTIException(f"No job context record found for {job_id}")

            self._proc_id = record.proc_id
            self._wd_path = record.wd_path
            self._job = Job.parse_obj(record.job)

    def job_id(self) -> str:
        return self._job_id

    def job(self) -> Job:
        return self._job

    def wd_path(self) -> str:
        return self._wd_path

    def descriptor_path(self) -> str:
        return self._descriptor_path

    def state(self) -> JobStatus.State:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)
                state = self._state_mapping[record.state]
                return state

    def update_state(self, new_state: JobStatus.State) -> JobStatus.State:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                # only allow updating the state if it's not terminal already
                if record.state in [JobStatus.State.CANCELLED, JobStatus.State.FAILED, JobStatus.State.SUCCESSFUL]:
                    logger.warning(f"[job:{record.job_id}:{record.state}] ignoring state update to {new_state.value}")

                else:
                    record.state = new_state.value
                    session.commit()

                state = self._state_mapping[record.state]
                return state

    def status(self) -> JobStatus:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                jri = JobRuntimeInformation.parse_obj(record.info)

                status = JobStatus(state=record.state, progress=record.progress, output=jri.output,
                                   notes=jri.notes, job=self._job, errors=jri.errors)

                return status

    def add_pending_output(self, obj_name: str) -> None:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                jri = JobRuntimeInformation.parse_obj(record.info)
                jri.pending_output = [*jri.pending_output, obj_name]

                record.info = jri.dict()
                session.commit()

    def get_pending_outputs(self) -> List[str]:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                jri = JobRuntimeInformation.parse_obj(record.info)
                return list(jri.pending_output)

    def pop_pending_output(self, obj_name: str, obj: CDataObject) -> None:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                jri = JobRuntimeInformation.parse_obj(record.info)
                jri.pending_output.remove(obj_name)
                jri.output[obj_name] = obj

                record.info = jri.dict()
                session.commit()

    def progress(self) -> int:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)
                return record.progress

    def update_progress(self, new_progress: int) -> int:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                record.progress = new_progress
                session.commit()

                return record.progress

    def update_message(self, severity: str, content: str) -> None:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                jri = JobRuntimeInformation.parse_obj(record.info)
                jri.message = JobStatus.Message(severity=severity, content=content)

                record.info = jri.dict()
                session.commit()

    def put_note(self, key: str, note: Union[str, int, float, bool, list, dict]) -> None:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                jri = JobRuntimeInformation.parse_obj(record.info)
                jri.notes[key] = note

                record.info = jri.dict()
                session.commit()

    def get_note(self, key: str, default: Union[str, int, float, bool, dict, list] = None) -> Union[str, int, float,
                                                                                                    bool, dict, list]:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                jri = JobRuntimeInformation.parse_obj(record.info)
                return jri.notes[key] if key in jri.notes else default

    def remove_note(self, key: str) -> None:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                jri = JobRuntimeInformation.parse_obj(record.info)
                if key in jri.notes:
                    jri.notes.pop(key)

                record.info = jri.dict()
                session.commit()

    def add_error(self, message: str, exception: ExceptionContent) -> None:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                jri = JobRuntimeInformation.parse_obj(record.info)
                jri.errors.append(JobStatus.Error(message=message, exception=exception))

                record.info = jri.dict()
                session.commit()

    def errors(self) -> List[JobStatus.Error]:
        with self._mutex:
            with self._session_maker() as session:
                record = session.query(DBJobContext).get(self._job_id)

                jri = JobRuntimeInformation.parse_obj(record.info)
                return jri.errors


class RTIService:
    infix_path = 'rti'

    def __init__(self, node, db_path: str, retain_job_history: bool = False, strict_deployment: bool = True,
                 job_concurrency: bool = False):
        # initialise properties
        self._mutex = Lock()
        self._node = node
        self._retain_job_history = retain_job_history
        self._strict_deployment = strict_deployment
        self._job_concurrency = job_concurrency

        # initialise directories
        self._jobs_path = os.path.join(self._node.datastore, 'jobs')
        logger.info(f"[init] using jobs path at {self._jobs_path}")
        os.makedirs(self._jobs_path, exist_ok=True)
        os.makedirs(os.path.join(self._node.datastore, RTIService.infix_path), exist_ok=True)

        # initialise database things
        logger.info(f"[init] using DB file at {db_path}")
        self._engine = create_engine(db_path)
        Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

        # search for RTI adapter classes
        self._adapter_classes: Dict[str, Any] = {}
        base_path = os.path.abspath(os.path.dirname(saas.__path__[0]))
        for module_info in pkgutil.iter_modules([os.path.join(base_path, 'saas', 'rti', 'adapters')]):
            module = __import__(f"saas.rti.adapters.{module_info.name}", fromlist=[module_info.name])
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, RTIProcessorAdapter) and obj != RTIProcessorAdapter:
                    logger.info(f"[init] adding adapter class: {name}")
                    self._adapter_classes[name] = obj

        # check for deployed processors
        self._deployed: Dict[str, RTIProcessorAdapter] = {}
        with self._Session() as session:
            for record in session.query(DBProcessorState).all():
                if record.proc_adapter in self._adapter_classes:
                    # do we have SSH credentials for this processor?
                    ssh_credentials = \
                        SSHCredentials.parse_obj(record.ssh_credentials) if record.ssh_credentials else None

                    # do we have Github credentials for this processor?
                    github_credentials = \
                        GithubCredentials.parse_obj(record.github_credentials) if record.github_credentials else None

                    # get the adapter class
                    adapter_class = self._adapter_classes[record.proc_adapter]

                    logger.info(f"[init:{shorten_id(record.proc_id)}] [{adapter_class.__name__}:"
                                f"{'C' if self._job_concurrency else 'c'}{'S' if ssh_credentials else 's'}"
                                f"{'G' if github_credentials else 'g'}] starting adapter thread")

                    # start the adapter
                    adapter: RTIProcessorAdapter = adapter_class(
                        proc_id=record.proc_id, gpp=GitProcessorPointer.parse_obj(record.gpp),
                        state_wrapper=DBProcessorStateWrapper(session_maker=self._Session, proc_id=record.proc_id),
                        jobs_path=self._jobs_path, node=self._node, job_concurrency=self._job_concurrency,
                        ssh_credentials=ssh_credentials, github_credentials=github_credentials
                    )
                    adapter.start()
                    self._deployed[record.proc_id] = adapter

                    # search for existing jobs and add them
                    for job_state in session.query(DBJobContext).filter_by(proc_id=record.proc_id).all():
                        if job_state.state in [JobStatus.State.CANCELLED.value, JobStatus.State.FAILED.value,
                                               JobStatus.State.SUCCESSFUL.value]:
                            logger.info(f"[init] found job {shorten_id(record.proc_id)}/{job_state.job_id} with "
                                        f"terminal state {job_state.state} -> skipping.")

                        else:
                            logger.info(f"[init] found job {shorten_id(record.proc_id)}/{job_state.job_id} with "
                                        f"state {job_state.state} -> adding.")

                            context = DBJobContextWrapper(self, self._Session, job_state.job_id)
                            adapter.add(context)

                else:
                    logger.warning(f"[init] found processor {shorten_id(record.proc_id)}:{record.state} "
                                   f"using unavailable adapter {record.proc_adapter} -> skipping.")

    def _find_gpp_in_network(self, proc_id: str, gpp_custodian: str = None) -> Optional[GitProcessorPointer]:
        # get all nodes in the network (and filter by custodian if any)
        network = self._node.db.get_network()
        if gpp_custodian:
            network = [item for item in network if item.iid == gpp_custodian]

        # search the network for the GPP data object
        for node in network:
            # skip this node if doesn't have a DOR
            if node.dor_service is False:
                continue

            try:
                # lookup the GPP data object
                dor_protocol = DataObjectRepositoryP2PProtocol(self._node)
                gpp = dor_protocol.lookup_gpp(node.p2p_address, proc_id)
                if gpp:
                    return gpp

            # ignore peers that are not available
            except PeerUnavailableError:
                continue

    @property
    def retain_job_history(self) -> bool:
        return self._retain_job_history

    @property
    def strict_deployment(self) -> bool:
        return self._strict_deployment

    @property
    def job_concurrency(self) -> bool:
        return self._job_concurrency

    def job_descriptor_path(self, job_id: str) -> str:
        return os.path.join(self._jobs_path, job_id, 'job_descriptor.json')

    def job_status_path(self, job_id: str) -> str:
        return os.path.join(self._jobs_path, job_id, 'job_status.json')

    def endpoints(self) -> List[EndpointDefinition]:
        return [
            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, '',
                               self.deployed, List[Processor], None),

            EndpointDefinition('POST', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}',
                               self.deploy, Processor, [VerifyUserIsNodeOwner] if self._strict_deployment else None),

            EndpointDefinition('DELETE', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}',
                               self.undeploy, Processor, [VerifyProcessorDeployed, VerifyUserIsNodeOwner] if
                               self._strict_deployment else [VerifyProcessorDeployed]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/gpp',
                               self.gpp, GitProcessorPointer, [VerifyProcessorDeployed]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/status',
                               self.status, ProcessorStatus, [VerifyProcessorDeployed]),

            EndpointDefinition('POST', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/jobs',
                               self.submit, Job, [VerifyProcessorDeployed, VerifyAuthorisation]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/jobs',
                               self.jobs_by_proc, List[Job], [VerifyProcessorDeployed]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'job',
                               self.jobs_by_user, List[Job], [VerifyAuthorisation]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'job/{job_id}/status',
                               self.job_status, JobStatus, [VerifyUserIsJobOwnerOrNodeOwner]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'job/{job_id}/logs',
                               self.job_logs, None, [VerifyUserIsJobOwnerOrNodeOwner]),

            EndpointDefinition('DELETE', RTI_ENDPOINT_PREFIX, 'job/{job_id}',
                               self.job_cancel, JobStatus, [VerifyUserIsJobOwnerOrNodeOwner]),

            EndpointDefinition('POST', RTI_ENDPOINT_PREFIX, 'permission/{req_id}',
                               self.put_permission, None, None)
        ]

    def deployed(self) -> List[Processor]:
        """
        Retrieves a list of all processors that are deployed by the RTI.
        """
        with self._mutex:
            return [Processor(proc_id=proc_id, gpp=adapter.gpp) for proc_id, adapter in self._deployed.items()]

    def deploy(self, proc_id: str, p: DeployParameters) -> Processor:
        """
        Deploys a processor to the RTI. By default, the processor is deployed on the same machine that hosts the RTI.
        If the processor is supposed to be deployed on a remote machine, corresponding SSH credentials have to be
        provided which the RTI can use to access the remote machine. Note that SSH credentials will be stored and used
        by the RTI to be able to access the remotely deployed processor. Deployment requires the RTI to access the
        repository that contains the processor code. If the repository is not public, corresponding GitHub credentials
        need to be provided. Note that GitHub credentials are not stored. Note that all credentials information must
        not be sent in plaintext but instead encrypted using the corresponding public encryption key of the RTI node.
        """
        with self._mutex:
            # is the processor already deployed?
            if proc_id in self._deployed:
                logger.warning(f"[deploy:{shorten_id(proc_id)}] processor already deployed -> "
                               f"return descriptor only")
                return Processor(proc_id=proc_id, gpp=self._deployed[proc_id].gpp)

            # try to find the GPP data object for this processor
            gpp = self._find_gpp_in_network(proc_id)
            if gpp is None:
                raise GPPDataObjectNotFound(details={
                    'proc_id': proc_id
                })

            # decrypt SSH credentials (if any)
            if p.encrypted_ssh_credentials is not None:
                ssh_credentials = bytes.fromhex(p.encrypted_ssh_credentials)
                ssh_credentials = self._node.keystore.decrypt(ssh_credentials)
                ssh_credentials = ssh_credentials.decode('utf-8')
                ssh_credentials = json.loads(ssh_credentials)
                ssh_credentials = \
                    SSHCredentials(
                        host=ssh_credentials['host'],
                        login=ssh_credentials['login'],
                        key=ssh_credentials['key']
                    )
            else:
                ssh_credentials = None

            # decrypt Github credentials (if any)
            if p.encrypted_github_credentials is not None:
                github_credentials = bytes.fromhex(p.encrypted_github_credentials)
                github_credentials = self._node.keystore.decrypt(github_credentials)
                github_credentials = github_credentials.decode('utf-8')
                github_credentials = json.loads(github_credentials)
                github_credentials = \
                    GithubCredentials(
                        login=github_credentials['login'],
                        personal_access_token=github_credentials['personal_access_token']
                    )
            else:
                github_credentials = None

            # determine the adapter class
            if p.deployment == 'native':
                adapter_class = native_rti.RTINativeProcessorAdapter
            elif p.deployment == 'docker':
                adapter_class = docker_rti.RTIDockerProcessorAdapter
            else:
                raise RTIException(f"Invalid RTI deployment type: {p.deployment}")

            # initialise the processor state
            with self._Session() as session:
                session.add(
                    DBProcessorState(
                        proc_id=proc_id, proc_adapter=adapter_class.__name__,
                        gpp=gpp.dict(), state=str(ProcessorState.UNINITIALISED.value),
                        ssh_credentials=ssh_credentials.dict() if ssh_credentials else None,
                        github_credentials=github_credentials.dict() if github_credentials else None
                    )
                )
                session.commit()

            logger.info(f"[deploy:{shorten_id(proc_id)}] [{adapter_class.__name__}:"
                        f"{'C' if self._job_concurrency else 'c'}{'S' if ssh_credentials else 's'}"
                        f"{'G' if github_credentials else 'g'}] starting adapter thread")

            # start the adapter
            adapter: RTIProcessorAdapter = adapter_class(
                proc_id=proc_id, gpp=gpp,
                state_wrapper=DBProcessorStateWrapper(session_maker=self._Session, proc_id=proc_id),
                jobs_path=self._jobs_path, node=self._node, job_concurrency=self._job_concurrency,
                ssh_credentials=ssh_credentials, github_credentials=github_credentials
            )
            adapter.start()
            self._deployed[proc_id] = adapter

            return Processor(proc_id=proc_id, gpp=adapter.gpp)

    def undeploy(self, proc_id: str) -> Processor:
        """
        Shuts down a deployed processor and removes it from the list of deployed processor hosted by the RTI. If
        SSH credentials have been used by this processor for remote deployment, then the stored SSH credentials will
        be deleted as well.
        """
        with self._mutex:
            with self._Session() as session:
                logger.info(f"[undeploy:{shorten_id(proc_id)}] set state to STOPPING.")
                record = session.query(DBProcessorState).get(proc_id)
                record.state = str(ProcessorState.STOPPING.value)
                session.commit()

            # remove the adapter
            adapter = self._deployed.pop(proc_id)

            return Processor(proc_id=proc_id, gpp=adapter.gpp)

    def gpp(self, proc_id: str) -> GitProcessorPointer:
        """
        Retrieves the Git-Processor-Pointer (GPP) information of a deployed processor.
        """
        with self._mutex:
            return self._deployed[proc_id].gpp

    def status(self, proc_id: str) -> ProcessorStatus:
        """
        Retrieves status information for a deployed processor.
        """
        with self._mutex:
            return self._deployed[proc_id].status()

    def submit(self, proc_id: str, task: Task, request: Request) -> Job:
        """
        Submits a task to a deployed processor, thereby creating a new job. The job is queued and executed once the
        processor has the capacity to do so. Authorisation is required by the owner of the task/job.
        """
        with self._mutex:
            # get the user's identity and check if it's identical with that's indicated in the task
            iid = request.headers['saasauth-iid']
            if iid != task.user_iid:
                raise RTIException("Mismatching between user indicated in task and user making request", details={
                    'iid': iid,
                    'task': task
                })

            # get the processor
            proc = self._deployed.get(task.proc_id)
            if proc is None:
                raise RTIException(f"Processor {task.proc_id} not deployed", details={
                    'task': task
                })

            # create job descriptor with a generated job id
            job_id = generate_random_string(8)
            job = Job(id=job_id, task=task, retain=self._retain_job_history,
                      custodian=self._node.info, proc_name=proc.gpp.proc_descriptor.name,
                      t_submitted=get_timestamp_now())

            # create and add the job state to the processor
            info = JobRuntimeInformation(pending_output=[], output={}, notes={}, errors=[], message=None)

            # get the user identity
            user: Identity = self._node.db.get_identity(iid)

            job_state = DBJobContext(
                job_id=job_id, proc_id=proc_id, user_id=user.id, wd_path=os.path.join(self._jobs_path, job.id),
                job=job.dict(), state=str(JobStatus.State.UNINITIALISED.value), progress=0, info=info.dict()
            )

            # add the state to the db
            with self._Session() as session:
                session.add(job_state)
                session.commit()

            # add the job state to the processor
            logger.info(f"[submit:{shorten_id(proc_id)}] [job:{job_id}] adding job state to processor")
            context = DBJobContextWrapper(self, self._Session, job_id)
            proc.add(context)

            return job

    def jobs_by_proc(self, proc_id: str) -> List[Job]:
        """
        Retrieves a list of jobs processed by a processor. Any job that is pending execution or actively executed will
        be included in the list. Past jobs, i.e., jobs that have completed execution (successfully or not) will not be
        included in this list.
        """

        with self._mutex:
            # collect all jobs
            result = [*self._deployed[proc_id].pending_jobs()]
            active = [*self._deployed[proc_id].active_jobs()]
            result.extend(active)

            return result

    def jobs_by_user(self, request: Request) -> List[Job]:
        """
        Retrieves a list of jobs (past or current) owned by a user. If the user is the node owner, all jobs by all
        users will be returned.
        """

        with self._mutex:
            with self._Session() as session:
                # get the identity
                user: Identity = self._node.db.get_identity(request.headers['saasauth-iid'])

                # if the user is NOT the node owner, only return the jobs owned by the user
                if self._node.identity.id != user.id:
                    records = session.query(DBJobContext).filter_by(user_id=user.id).all()

                else:
                    records = session.query(DBJobContext).all()

                return [Job.parse_obj(record.job) for record in records]

    def job_status(self, job_id: str) -> JobStatus:
        """
        Retrieves detailed information about the status of a job. Authorisation is required by the owner of the job
        (i.e., the user that has created the job by submitting the task in the first place).
        """
        with self._mutex:
            with self._Session() as session:
                # get the context record for that job
                record = session.query(DBJobContext).get(job_id)
                if record is None:
                    raise JobStatusNotFoundError({
                        'job_id': job_id
                    })

                # determine job status
                job = Job.parse_obj(record.job)
                jri = JobRuntimeInformation.parse_obj(record.info)
                status = JobStatus(state=record.state, progress=record.progress, output=jri.output,
                                   notes=jri.notes, job=job, errors=jri.errors, message=jri.message)

                return status

    def job_logs(self, job_id: str) -> Response:
        """
        Attempts to retrieve the execution logs of a job. This includes stdout and stderr output that has been
        generated during job execution. Depending on the status of the job (is the job already running or has it
        finished execution?) and on the underlying implementation of the processor (is stdout/stderr output generated?)
        logs may or may not be available. Logs will be archived using tar.gz and delivered as binary stream for the
        client to download.
        """
        # collect log files (if they exist)
        existing = []
        for filename in ['execute_sh.stdout', 'execute_sh.stderr']:
            log_path = os.path.join(self._jobs_path, job_id, filename)
            if os.path.isfile(log_path):
                existing.append(os.path.basename(log_path))

        # do we have anything?
        if not existing:
            raise RTIException("No execute logs available.", details={
                'job_id': job_id
            })

        # build the command for archiving the logs
        wd_path = os.path.join(self._jobs_path, job_id)
        archive_path = os.path.join(self._jobs_path, job_id, 'execute_logs.tar.gz')
        command = ['tar', 'czf', archive_path, '-C', wd_path] + existing

        try:
            # archive the logs and return as stream
            subprocess.run(command, capture_output=True, check=True)
            return FileResponse(archive_path, media_type='application/octet-stream')

        except subprocess.CalledProcessError as e:
            raise SaaSRuntimeException('Archiving execute logs failed', details={
                'returncode': e.returncode,
                'command': command,
                'stdout': e.stdout.decode('utf-8'),
                'stderr': e.stderr.decode('utf-8')
            })

    def job_cancel(self, job_id: str) -> JobStatus:
        """
        Attempts to cancel a running job. Depending on the implementation of the processor, this may or may not be
        possible.
        """
        with self._mutex:
            with self._Session() as session:
                # get the context record for that job
                record = session.query(DBJobContext).get(job_id)
                if record is None:
                    raise JobStatusNotFoundError({
                        'job_id': job_id
                    })

                # is the processor deployed?
                if record.proc_id not in self._deployed:
                    raise RTIException(
                        f"Cannot cancel job: processor for {job_id} not deployed (has the node been restarted in "
                        f"the meantime?)"
                    )

                # do we have a job runner?
                proc = self._deployed[record.proc_id]
                runner = proc.pop_job_runner(job_id)
                if runner is None:
                    raise RTIException(
                        f"Cannot cancel job: no job runner found for {job_id} (either job was not found or the "
                        f"job is not running any longer)"
                    )

                # cancel the job and return the status
                runner.cancel()

                # determine job status
                job = Job.parse_obj(record.job)
                jri = JobRuntimeInformation.parse_obj(record.info)
                status = JobStatus(state=record.state, progress=record.progress, output=jri.output,
                                   notes=jri.notes, job=job, errors=jri.errors)

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
        with self._Session() as session:
            record = session.query(DBContentKeys).get(req_id)
            if record:
                record.value = permission.content_key
            else:
                session.add(DBContentKeys(key=req_id, value=permission.content_key))
            session.commit()

    def pop_permission(self, req_id: str) -> Optional[str]:
        with self._Session() as session:
            record = session.query(DBContentKeys).get(req_id)
            if record is not None:
                result = record.value
                session.delete(record)
                session.commit()
                return result
            return None
