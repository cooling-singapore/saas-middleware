import json
import logging
import os
import time
from threading import Thread
from typing import Union, List

import docker
import pytest
from docker.errors import DockerException

from saas.core.exceptions import SaaSRuntimeException
from saas.core.helpers import encrypt_file
from saas.core.rsakeypair import RSAKeyPair
from saas.dor.proxy import DORProxy
from saas.core.helpers import generate_random_string
from saas.core.keystore import Keystore
from saas.core.logging import Logging
from saas.nodedb.proxy import NodeDBProxy
from saas.rest.exceptions import UnsuccessfulRequestError
from saas.rti.adapters.base import ProcessorState
from saas.rti.adapters.docker import prune_image
from saas.rti.proxy import RTIProxy
from saas.rti.schemas import Task, JobStatus
from saas.core.schemas import GithubCredentials
from tests.base_testcase import update_keystore_from_credentials

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


def add_test_processor(dor: DORProxy, owner: Keystore, config: str) -> (str, GithubCredentials):
    source = 'https://github.com/cooling-singapore/saas-middleware'
    commit_id = 'e107901'
    proc_path = 'examples/adapters/proc_example'

    github_credentials = owner.github_credentials.get(source)

    meta = dor.add_gpp_data_object(source, commit_id, proc_path, config, owner.identity,
                                   github_credentials=github_credentials)
    return meta.obj_id, github_credentials


def deploy_and_wait(rti: RTIProxy, proc_id: str, authority: Keystore, github_credentials: GithubCredentials = None,
                    deployment: str = "native"):
    rti.deploy(proc_id, authority, deployment=deployment, github_credentials=github_credentials)
    while (state := rti.get_status(proc_id).state) in [ProcessorState.UNINITIALISED, ProcessorState.STARTING]:
        logger.info(f"Waiting for processor to deploy. {state}")
        time.sleep(1)
    assert(rti.get_status(proc_id).state == ProcessorState.OPERATIONAL)
    logger.info(f"Processor to deployed. {state}")


@pytest.fixture()
def non_strict_node(test_context, extra_keystores):
    keystore = extra_keystores[0]
    update_keystore_from_credentials(keystore)
    node = test_context.get_node(keystore, use_rti=True, enable_rest=True, strict_deployment=False)
    return node


@pytest.fixture()
def strict_node(test_context, extra_keystores):
    keystore = extra_keystores[1]
    update_keystore_from_credentials(keystore)
    node = test_context.get_node(keystore, use_rti=True, enable_rest=True, strict_deployment=True)
    return node


@pytest.fixture()
def known_user(extra_keystores, node_db_proxy):
    keystore = extra_keystores[2]
    node_db_proxy.update_identity(keystore.identity)
    return keystore


@pytest.fixture()
def test_processor_info(dor_proxy, node):
    test_proc_id, test_proc_gh_cred = add_test_processor(dor_proxy, node.keystore, 'default')
    return test_proc_id, test_proc_gh_cred


@pytest.fixture()
def deployed_test_processor(test_processor_info, rti_proxy, node):
    owner = node.keystore
    test_proc_id, test_proc_gh_cred = test_processor_info
    deploy_and_wait(rti_proxy, test_proc_id, owner, test_proc_gh_cred)
    return test_proc_id


@pytest.fixture()
def exec_only_node(test_context, extra_keystores):
    node = test_context.get_node(extra_keystores[1], use_dor=False, use_rti=True, enable_rest=True)
    return node


def test_rest_get_deployed(rti_proxy):
    result = rti_proxy.get_deployed()
    assert(result is not None)
    assert(len(result) == 0)


def test_rest_deploy_undeploy(non_strict_node, strict_node, known_user):
    node0 = non_strict_node
    db0 = NodeDBProxy(node0.rest.address())
    dor0 = DORProxy(node0.rest.address())
    rti0 = RTIProxy(node0.rest.address())

    node1 = strict_node
    db1 = NodeDBProxy(node1.rest.address())
    dor1 = DORProxy(node1.rest.address())
    rti1 = RTIProxy(node1.rest.address())

    # check flags
    info0 = db0.get_node()
    info1 = db1.get_node()
    assert(info0.strict_deployment is False)
    assert(info1.strict_deployment is True)

    # upload the test proc GCC
    proc_id0, gh_cred0 = add_test_processor(dor0, node0.keystore, 'default')
    proc_id1, gh_cred1 = add_test_processor(dor1, node1.keystore, 'default')

    # make the wrong user identity known to the nodes
    wrong_user = known_user
    db0.update_identity(wrong_user.identity)
    db1.update_identity(wrong_user.identity)

    # try to deploy the processor with the wrong user on node0
    rti0.deploy(proc_id0, wrong_user, github_credentials=gh_cred0)

    # try to deploy the processor with the wrong user on node1
    with pytest.raises(UnsuccessfulRequestError) as e:
        rti1.deploy(proc_id1, wrong_user, github_credentials=gh_cred1)
    assert ('User is not the node owner' in e.value.details['reason'])

    # try to deploy the processor with the correct user on node1
    rti1.deploy(proc_id1, node1.keystore, github_credentials=gh_cred1)

    # wait for deployment to be done
    while rti0.get_status(proc_id0).state != 'operational':
        time.sleep(0.5)

    # wait for deployment to be done
    while rti1.get_status(proc_id1).state != 'operational':
        time.sleep(0.5)

    # try to undeploy the processor with the wrong user on node0
    rti0.undeploy(proc_id0, wrong_user)

    # try to undeploy the processor with the wrong user on node1
    with pytest.raises(UnsuccessfulRequestError) as e:
        rti1.undeploy(proc_id1, wrong_user)
    assert ('User is not the node owner' in e.value.details['reason'])

    # try to undeploy the processor with the correct user on node1
    rti1.undeploy(proc_id1, node1.keystore)


def test_rest_deploy_descriptor_status_undeploy(node, test_processor_info, rti_proxy):
    # deploy the test processor with the correct user
    node_owner = node.keystore
    test_proc_id, test_proc_gh_cred = test_processor_info

    result = rti_proxy.deploy(test_proc_id, node_owner, github_credentials=test_proc_gh_cred)
    assert(result is not None)

    # get the descriptor
    result = rti_proxy.get_gpp(test_proc_id)
    assert(result is not None)

    # get the status
    while True:
        result = rti_proxy.get_status(test_proc_id)
        assert(result is not None)
        assert(result.state in ['starting', 'operational', 'uninitialised'])

        if result.state == 'operational':
            break

        time.sleep(1)

    # undeploy the test processor
    result = rti_proxy.undeploy(test_proc_id, node_owner)
    assert(result is not None)

    # try to get the status
    with pytest.raises(UnsuccessfulRequestError) as e:
        rti_proxy.get_status(test_proc_id)
    assert('Processor not deployed' in e.value.reason)


def test_rest_submit_list_get_job(test_context, node, dor_proxy, rti_proxy, deployed_test_processor, known_user):
    wrong_user = known_user
    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 1}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id,
                              'restricted_access': False, 'content_encrypted': False})
    ]

    # submit the job
    result = rti_proxy.submit_job(deployed_test_processor, task_input, task_output, owner)
    assert(result is not None)

    job_id = result.id

    # get list of all jobs by correct user
    result = rti_proxy.get_jobs_by_user(owner)
    assert(result is not None)
    result = {job.id: job for job in result}
    assert(job_id in result)

    # get list of all jobs by wrong user
    result = rti_proxy.get_jobs_by_user(wrong_user)
    assert(result is not None)
    assert(len(result) == 0)

    # get list of all jobs by proc
    result = rti_proxy.get_jobs_by_proc(deployed_test_processor)
    assert(result is not None)
    assert(len(result) == 1)

    # try to get the job info as the wrong user
    try:
        rti_proxy.get_job_status(job_id, wrong_user)
        assert False

    except UnsuccessfulRequestError as e:
        assert(e.details['reason'] == 'user is not the job owner or the node owner')

    while True:
        # get information about the running job
        status: JobStatus = rti_proxy.get_job_status(job_id, owner)
        from pprint import pprint
        pprint(status.dict())
        assert(status is not None)

        if status.state in [JobStatus.State.SUCCESSFUL, JobStatus.State.FAILED]:
            break

        time.sleep(1)

    # check if we have an object id for output object 'c'
    assert('c' in status.output)

    # get the contents of the output data object
    download_path = os.path.join(test_context.testing_dir, 'c.json')
    dor_proxy.get_content(status.output['c'].obj_id, owner, download_path)
    assert(os.path.isfile(download_path))

    with open(download_path, 'r') as f:
        content = json.load(f)
        print(content)
        assert(content['v'] == 2)

    download_path = os.path.join(test_context.testing_dir, 'log.tar.gz')

    # try to get the job logs as the wrong user
    with pytest.raises(UnsuccessfulRequestError) as e:
        rti_proxy.get_job_logs(job_id, wrong_user, download_path)
    assert(e.value.details['reason'] == 'user is not the job owner or the node owner')
    assert(not os.path.isfile(download_path))

    rti_proxy.get_job_logs(job_id, owner, download_path)
    assert(os.path.isfile(download_path))


def test_rest_submit_cancel_job(node, rti_proxy, deployed_test_processor, known_user):
    wrong_user = known_user
    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 3600}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 3600}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id,
                              'restricted_access': False, 'content_encrypted': False})
    ]

    # submit the job
    result = rti_proxy.submit_job(deployed_test_processor, task_input, task_output, owner)
    assert(result is not None)

    job_id = result.id

    # try to cancel the job (wrong user)
    with pytest.raises(UnsuccessfulRequestError) as e:
        rti_proxy.cancel_job(job_id, wrong_user)
    assert('user is not the job owner' in e.value.details['reason'])

    # wait until the job is running
    while True:
        status: JobStatus = rti_proxy.get_job_status(job_id, owner)
        if status.state == JobStatus.State.RUNNING:
            break
        else:
            time.sleep(0.5)

    # cancel the job (correct user)
    rti_proxy.cancel_job(job_id, owner)

    # get information about the job
    status: JobStatus = rti_proxy.get_job_status(job_id, owner)
    print(json.dumps(status.dict(), indent=4))
    assert(status.state == JobStatus.State.CANCELLED)


def test_rest_job_logs(test_context, node, deployed_test_processor, rti_proxy, dor_proxy):
    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id,
                              'restricted_access': False, 'content_encrypted': False})
    ]

    # submit the job
    result = rti_proxy.submit_job(deployed_test_processor, task_input, task_output, owner)
    assert(result is not None)

    job_id = result.id

    # get information about all jobs
    result = rti_proxy.get_jobs_by_proc(deployed_test_processor)
    assert(result is not None)

    while True:
        # get information about the running job
        status: JobStatus = rti_proxy.get_job_status(job_id, owner)
        if status.state in [JobStatus.State.SUCCESSFUL, JobStatus.State.FAILED]:
            break

        time.sleep(1)

    # check if we have an object id for output object 'c'
    assert('c' in status.output)

    # get the contents of the output data object
    download_path = os.path.join(test_context.testing_dir, 'c.json')
    dor_proxy.get_content(status.output['c'].obj_id, owner, download_path)
    assert(os.path.isfile(download_path))

    with open(download_path, 'r') as f:
        content = json.load(f)
        print(content)
        assert(content['v'] == 3)


def test_rest_put_permission():
    pass


class UnsuccessfulJob(SaaSRuntimeException):
    def __init__(self, reason: str, details: dict) -> None:
        super().__init__(f"Unsuccessful job: {reason}", details=details)


def submit_job(rti: RTIProxy, proc_id: str, task_input: List[Union[Task.InputValue, Task.InputReference]],
               task_output: List[Task.Output], owner: Keystore, name: str = None, description: str = None) -> str:
    result = rti.submit_job(proc_id, task_input, task_output, owner, name=name, description=description)
    job_id = result.id
    return job_id


def wait_for_job(rti: RTIProxy, job_id: str, owner: Keystore) -> dict:
    prev_message = None
    while True:
        status = rti.get_job_status(job_id, owner)
        print(status)

        if 'message' in status.notes and status.notes['message'] != prev_message:
            prev_message = status.notes['message']
            print(prev_message)

        if status.state == JobStatus.State.SUCCESSFUL:
            return status.output

        elif status.state == JobStatus.State.FAILED:
            raise UnsuccessfulJob(f"Job failed with {len(status.errors)} errors", details={
                'errors': [e.dict() for e in status.errors]
            })

        time.sleep(1)


def submit_and_wait(rti: RTIProxy, proc_id: str, task_input: List[Union[Task.InputValue, Task.InputReference]],
                    task_output: List[Task.Output], owner: Keystore, name: str = None, description: str = None
                    ) -> (str, dict):
    job_id = submit_job(rti, proc_id, task_input, task_output, owner, name=name, description=description)
    output = wait_for_job(rti, job_id, owner)
    return job_id, output


def handle_content_key_request(rti_proxy: RTIProxy, owner: Keystore, job_id: str, content_key: str):
    while True:
        time.sleep(1)

        status = rti_proxy.get_job_status(job_id, with_authorisation_by=owner)
        if 'requests' in status.notes:
            for r in status.notes['requests']:
                # we should be able to decrypt it
                request = owner.decrypt(r['request'].encode('utf-8')).decode('utf-8')
                request = json.loads(request)
                print(request)

                # get the ephemeral key and encrypt the content key with the ephemeral key
                key = RSAKeyPair.from_public_key_string(request['ephemeral_public_key'])
                c_key = owner.decrypt(content_key.encode('utf-8')).decode('utf-8')
                c_key = key.encrypt(c_key.encode('utf-8'), base64_encoded=True).decode('utf-8')

                # submit the content key
                rti_proxy.put_permission(r['req_id'], c_key)

                return


def test_processor_execution_value(node, rti_proxy, deployed_test_processor):
    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False})
    ]

    # submit and wait
    job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
    assert(output is not None)
    assert('c' in output)


def test_processor_execution_value_non_dor_target(node, exec_only_node, rti_proxy, deployed_test_processor):
    # join with the default node
    target_node = exec_only_node
    target_node.join_network(node.p2p.address())
    time.sleep(2)

    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False, 'target_node_iid': target_node.identity.id})
    ]

    # submit and wait
    try:
        submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
        assert False

    except UnsuccessfulJob as e:
        assert(e.details['errors'][0]['exception']['reason'] == 'Target node does not support DOR capabilities')


def test_processor_execution_value_with_name_and_description(node, rti_proxy, deployed_test_processor):
    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False})
    ]

    # submit and wait
    name = 'the job'
    description = 'here is some description about this job...'
    job_id = submit_job(rti_proxy, deployed_test_processor, task_input, task_output, owner,
                        name=name, description=description)

    # get the status
    status = rti_proxy.get_job_status(job_id, owner)
    print(status.job.task.name)
    print(status.job.task.description)
    assert(status.job.task.name == name)
    assert(status.job.task.description == description)

    # wait for the job to be done
    output = wait_for_job(rti_proxy, job_id, owner)
    assert(output is not None)
    assert('c' in output)


def test_processor_execution_specific_target_node(node, non_strict_node, deployed_test_processor, rti_proxy, dor_proxy):
    # create target node and join with the default node
    target_node = non_strict_node
    target_node.join_network(node.p2p.address())
    target_dor = DORProxy(target_node.rest.address())
    time.sleep(2)

    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False, 'target_node_iid': target_node.identity.id})
    ]

    # submit and wait
    job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
    assert(output is not None)
    assert('c' in output)

    # the output data object should be with the target node
    meta = dor_proxy.get_meta(output['c'].obj_id)
    assert(meta is None)

    meta = target_dor.get_meta(output['c'].obj_id)
    assert(meta is not None)
    assert(meta.custodian.identity.id == target_node.identity.id)

    target_node.shutdown()
    time.sleep(2)


def test_processor_execution_reference_unrestricted(test_context, node, dor_proxy, rti_proxy, deployed_test_processor):
    owner = node.keystore

    # add test data object
    meta = dor_proxy.add_data_object(test_context.create_file_with_content(f"{generate_random_string(4)}.json",
                                                                           json.dumps({'v': 1})),
                                     owner.identity, False, False, 'JSONObject', 'json')
    a_obj_id = meta.obj_id

    task_input = [
        Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': a_obj_id}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False})
    ]

    # submit and wait
    job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
    assert(output is not None)
    assert('c' in output)


def test_provenance(test_context, node, dor_proxy, rti_proxy, deployed_test_processor):
    owner = node.keystore

    # add test data object
    meta = dor_proxy.add_data_object(test_context.create_file_with_content(f"{generate_random_string(4)}.json",
                                                                           json.dumps({'v': 1})),
                                     owner.identity, False, False, 'JSONObject', 'json')
    obj_id, c_hash = meta.obj_id, meta.c_hash

    obj_id_a = obj_id
    obj_id_b = obj_id
    c_hash_a = c_hash
    c_hash_b = c_hash

    # run 3 iterations
    log = []
    for i in range(3):
        task_input = [
            Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': obj_id_a}),
            Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 5}})
        ]

        task_output = [
            Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                                  'content_encrypted': False})
        ]

        # submit and wait
        job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
        assert (output is not None)
        assert ('c' in output)
        obj_id = output['c'].obj_id

        # get the c_hash for output object 'c'
        meta = dor_proxy.get_meta(obj_id)
        c_hash = meta.c_hash

        log.append((c_hash_a, c_hash_b, c_hash))

        obj_id_a = obj_id_b
        obj_id_b = obj_id
        c_hash_a = c_hash_b
        c_hash_b = c_hash

    for item in log:
        print(f"{item[0]} + {item[1]} = {item[2]}")

    # get the provenance and print it
    provenance = dor_proxy.get_provenance(log[2][2])
    assert(provenance is not None)
    print(json.dumps(provenance.dict(), indent=2))


def test_job_concurrency(test_context, concurrent_node, dor_proxy, rti_proxy, deployed_test_processor):
    wd_path = test_context.testing_dir
    owner = concurrent_node.keystore

    # submit jobs
    n = 20
    jobs = []
    for i in range(n):
        task_input = [
            Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 5}}),
            Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 5}})
        ]

        task_output = [
            Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                                  'content_encrypted': False})
        ]

        job_id = submit_job(rti_proxy, deployed_test_processor, task_input, task_output, owner)
        print(f"[{time.time()}] job {job_id} submitted")
        jobs.append(job_id)

    # wait for all jobs
    results = []
    for i in range(n):
        status = rti_proxy.get_status(deployed_test_processor)
        print(f"proc status: {status}")

        job_id = jobs[i]
        output = wait_for_job(rti_proxy, job_id, owner)
        print(f"job {job_id} done -> output: {output}")

        obj_id = output['c'].obj_id
        download_path = os.path.join(wd_path, f"{obj_id}.json")
        dor_proxy.get_content(obj_id, owner, download_path)

        with open(download_path, 'r') as f:
            content = json.load(f)
            results.append(content['v'])


def test_processor_execution_same_reference(test_context, node, dor_proxy, rti_proxy, deployed_test_processor):
    # test for issue #110: https://github.com/cooling-singapore/saas-middleware/issues/110

    owner = node.keystore

    # add test data object
    meta = dor_proxy.add_data_object(test_context.create_file_with_content(f"{generate_random_string(4)}.json",
                                                                           json.dumps({'v': 1})),
                                     owner.identity, False, False, 'JSONObject', 'json')
    a_obj_id = meta.obj_id

    task_input = [
        Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': a_obj_id}),
        Task.InputReference.parse_obj({'name': 'b', 'type': 'reference', 'obj_id': a_obj_id}),
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False})
    ]

    # submit and wait
    job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
    assert(output is not None)
    assert('c' in output)

    input_path_a = os.path.join(test_context.testing_dir, node.datastore, 'jobs', str(job_id), 'a')
    input_path_b = os.path.join(test_context.testing_dir, node.datastore, 'jobs', str(job_id), 'b')
    output_path = os.path.join(test_context.testing_dir, node.datastore, 'jobs', str(job_id), 'c')
    assert(os.path.isfile(input_path_a))
    assert(os.path.isfile(input_path_b))
    assert(os.path.isfile(output_path))


def test_processor_execution_reference_restricted(test_context, node, node_db_proxy, dor_proxy, rti_proxy, known_user,
                                                  deployed_test_processor):
    owner = node.keystore
    rti_node_info = node_db_proxy.get_node()

    # add test data object
    meta = dor_proxy.add_data_object(test_context.create_file_with_content(f"{generate_random_string(4)}.json",
                                                                           json.dumps({'v': 1})),
                                     owner.identity, True, False, 'JSONObject', 'json')
    a_obj_id = meta.obj_id

    user = known_user

    invalid_signature = user.sign("invalid content".encode('utf-8'))
    task_input_invalid = [
        Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': a_obj_id,
                                      'user_signature': invalid_signature}),
        Task.InputReference.parse_obj({'name': 'b', 'type': 'reference', 'obj_id': a_obj_id,
                                      'user_signature': invalid_signature})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False})
    ]

    # no access rights and no valid signature
    with pytest.raises(UnsuccessfulJob) as e:
        submit_and_wait(rti_proxy, deployed_test_processor, task_input_invalid, task_output, user)
    assert('Identity does not have access to data object' in e.value.details['errors'][0]['exception']['reason'])

    # grant access
    dor_proxy.grant_access(a_obj_id, owner, user.identity)

    # access rights but invalid signature
    with pytest.raises(UnsuccessfulJob) as e:
        submit_and_wait(rti_proxy, deployed_test_processor, task_input_invalid, task_output, user)
    assert('authorisation failed' in e.value.details['errors'][0]['exception']['details']['reason'])

    # create valid and invalid task input
    valid_signature = user.sign(f"{rti_node_info.identity.id}:{a_obj_id}".encode('utf-8'))
    task_input_valid = [
        Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': a_obj_id,
                                      'user_signature': valid_signature}),
        Task.InputReference.parse_obj({'name': 'b', 'type': 'reference', 'obj_id': a_obj_id,
                                      'user_signature': valid_signature})
    ]

    # access rights and valid signature
    job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input_valid, task_output, user)
    assert('c' in output)


def test_processor_execution_reference_encrypted(test_context, node, dor_proxy, rti_proxy, deployed_test_processor):
    owner = node.keystore

    # add encrypted test data object
    obj_path = test_context.create_file_with_content(f"{generate_random_string(4)}.json", json.dumps({'v': 1}))
    content_key = encrypt_file(obj_path, encrypt_for=owner.identity, delete_source=True)

    meta = dor_proxy.add_data_object(obj_path, owner.identity, False, True, 'JSONObject', 'json')
    obj_id = meta.obj_id

    task_input = [
        Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': obj_id}),
        Task.InputReference.parse_obj({'name': 'b', 'type': 'reference', 'obj_id': obj_id})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False})
    ]

    # submit the job
    job_id = submit_job(rti_proxy, deployed_test_processor, task_input, task_output, owner)

    # run monitoring thread
    thread = Thread(target=handle_content_key_request, args=[rti_proxy, owner, job_id, content_key])
    thread.start()

    # wait for the job to finish
    output = wait_for_job(rti_proxy, job_id, owner)
    assert('c' in output)


def test_retain_job_history_false(test_context, keystore):
    # create target node and join with the default node
    target_node = test_context.get_node(keystore, enable_rest=True, retain_job_history=False)
    target_rti = RTIProxy(target_node.rest.address())
    target_dor = DORProxy(target_node.rest.address())
    time.sleep(2)

    owner = target_node.keystore

    # add test proc and deploy
    proc_id, gh_cred = add_test_processor(target_dor, owner, 'default')
    deploy_and_wait(target_rti, proc_id, owner, gh_cred)

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False})
    ]

    # submit and wait
    job_id, output = submit_and_wait(target_rti, proc_id, task_input, task_output, owner)
    assert(output is not None)
    assert('c' in output)

    # check if the output path exists
    output_path = os.path.join(test_context.testing_dir, target_node.datastore, 'jobs', str(job_id), 'c')
    assert not os.path.isfile(output_path)  # retain is False, so the path shouldn't exist!

    target_node.shutdown()
    time.sleep(2)


def test_retain_job_history_true(test_context, keystore):
    # create target node and join with the default node
    target_node = test_context.get_node(keystore, enable_rest=True, retain_job_history=True)
    target_rti = RTIProxy(target_node.rest.address())
    target_dor = DORProxy(target_node.rest.address())
    time.sleep(2)

    owner = target_node.keystore

    # add test proc and deploy
    proc_id, gh_cred = add_test_processor(target_dor, owner, 'default')
    deploy_and_wait(target_rti, proc_id, owner, gh_cred)

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False})
    ]

    # submit and wait
    job_id, output = submit_and_wait(target_rti, proc_id, task_input, task_output, owner)
    assert(output is not None)
    assert('c' in output)

    # check if the output path exists
    output_path = os.path.join(test_context.testing_dir, target_node.datastore, 'jobs', str(job_id), 'c')
    assert os.path.isfile(output_path)  # retain is False, so the path shouldn't exist!

    target_node.shutdown()
    time.sleep(2)


@pytest.fixture()
def deployed_test_processor_docker(test_processor_info, rti_proxy, node):
    owner = node.keystore
    test_proc_id, test_proc_gh_cred = test_processor_info
    deploy_and_wait(rti_proxy, test_proc_id, owner, test_proc_gh_cred, "docker")
    yield test_proc_id
    prune_image(test_proc_id)


@pytest.fixture(scope="session")
def remote_docker_credentials(keystore):
    cred = keystore.ssh_credentials.get('docker')
    if cred is None:
        pytest.skip("Docker ssh credentials not found")
    return cred


def check_docker():
    try:
        docker.from_env()
    except DockerException:
        return False
    else:
        return True


docker_required = pytest.mark.skipif(not check_docker(), reason="Docker daemon not found")


@docker_required
def test_docker_processor_execution_value(node, rti_proxy, deployed_test_processor_docker):
    # add test data object
    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False})
    ]

    # submit and wait
    job_id, output = submit_and_wait(rti_proxy, deployed_test_processor_docker, task_input, task_output, owner)
    assert (output is not None)
    assert ('c' in output)

    # Perform cleanup
    rti_proxy.undeploy(deployed_test_processor_docker, node.keystore)


@docker_required
def test_docker_remote_processor_execution_value(node, remote_docker_credentials, rti_proxy, test_processor_info):
    """
    Requires test credentials to have one ssh credential named `docker`
    """
    test_proc_id, test_proc_gh_cred = test_processor_info

    # instruct the RTI to deploy the processor remotely using the SSH credentials
    logger.info("Deploying processor using docker")
    rti_proxy.deploy(test_proc_id, node.keystore,
                     deployment="docker", github_credentials=test_proc_gh_cred,
                     ssh_credentials=remote_docker_credentials)

    # wait for processor to be deployed
    while (state := ProcessorState(
            rti_proxy.get_status(test_proc_id).state)) == ProcessorState.STARTING:
        logger.info(f"Waiting for processor to deploy. {state.name=}")
        time.sleep(5)
    logger.info(f"Processor to deployed. {state.name=}")

    # add test data object
    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
                              'content_encrypted': False})
    ]

    # submit and wait
    job_id, output = submit_and_wait(rti_proxy, test_proc_id, task_input, task_output, owner)
    assert (output is not None)
    assert ('c' in output)

    # Perform cleanup
    rti_proxy.undeploy(test_proc_id, node.keystore)


@docker_required
def test_docker_submit_cancel_job(node, rti_proxy, deployed_test_processor_docker):
    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 5}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 5}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id,
                              'restricted_access': False, 'content_encrypted': False})
    ]

    # submit the job
    result = rti_proxy.submit_job(deployed_test_processor_docker, task_input, task_output, owner)
    assert(result is not None)

    job_id = result.id

    # wait until the job is running
    while True:
        status: JobStatus = rti_proxy.get_job_status(job_id, owner)
        if status.state == JobStatus.State.RUNNING:
            break
        else:
            time.sleep(0.5)

    # cancel the job
    rti_proxy.cancel_job(job_id, owner)

    # get information about the job
    status: JobStatus = rti_proxy.get_job_status(job_id, owner)
    assert(status.state == JobStatus.State.CANCELLED)

    # Perform cleanup
    rti_proxy.undeploy(deployed_test_processor_docker, node.keystore)


# @pytest.fixture(scope="session")
# def nscc_ssh_cred(keystore):
#     cred = keystore.ssh_credentials.get('nscc')
#     if cred is None:
#         pytest.skip("NSCC ssh credentials not found")
#     return cred
#
#
# def test_deployment_undeployment(rti_proxy, test_processor_info, nscc_ssh_cred, keystore):
#     test_proc_id, test_proc_gh_cred = test_processor_info
#
#     # instruct the RTI to deploy the processor remotely using the SSH credentials
#     rti_proxy.deploy(test_proc_id, authority=keystore, github_credentials=test_proc_gh_cred,
#                      ssh_credentials=nscc_ssh_cred)
#
#     # wait for processor to be deployed
#     while (state := ProcessorState(
#             rti_proxy.get_status(test_proc_id).state)) == ProcessorState.STARTING:
#         logger.info(f"Waiting for processor to deploy. {state.name=}")
#         time.sleep(5)
#     logger.info(f"Processor to deployed. {state.name=}")
#
#     # get the deployed processors
#     result = rti_proxy.get_deployed()
#     assert(result is not None)
#     assert(len(result) == 1)
#     assert(result[0].proc_id == test_proc_id)
#
#     # undeploy the processor
#     result = rti_proxy.undeploy(test_proc_id, authority=keystore)
#     assert(result is not None)
#
#
# def test_processor_execution_mixed(test_context, node, rti_proxy, dor_proxy, test_processor_info, nscc_ssh_cred,
#                                    keystore):
#     test_proc_id, test_proc_gh_cred = test_processor_info
#
#     # instruct the RTI to deploy the processor remotely using the SSH credentials
#     rti_proxy.deploy(test_proc_id, authority=keystore, github_credentials=test_proc_gh_cred,
#                      ssh_credentials=nscc_ssh_cred)
#
#     # wait for processor to be deployed
#     while (state := ProcessorState(
#             rti_proxy.get_status(test_proc_id).state)) == ProcessorState.STARTING:
#         logger.info(f"Waiting for processor to deploy. {state.name=}")
#         time.sleep(5)
#     logger.info(f"Processor to deployed. {state.name=}")
#
#     # add test data object
#     owner = node.keystore
#     meta = dor_proxy.add_data_object(test_context.create_file_with_content(f"{generate_random_string(4)}.json",
#                                                                            json.dumps({'v': 1})),
#                                      owner.identity, False, False, 'JSONObject', 'json')
#     a_obj_id = meta.obj_id
#
#     task_input = [
#         Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': a_obj_id}),
#         Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
#     ]
#
#     task_output = [
#         Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                               'content_encrypted': False})
#     ]
#
#     # submit and wait
#     job_id, output = submit_and_wait(rti_proxy, test_proc_id, task_input, task_output, owner)
#     assert(output is not None)
#     assert('c' in output)
#
#
# def test_processor_resume_execution(test_context, node, rti_proxy, dor_proxy, test_processor_info, nscc_ssh_cred,
#                                     keystore):
#     test_proc_id, test_proc_gh_cred = test_processor_info
#
#     # instruct the RTI to deploy the processor remotely using the SSH credentials
#     rti_proxy.deploy(test_proc_id, authority=keystore, github_credentials=test_proc_gh_cred,
#                      ssh_credentials=nscc_ssh_cred)
#
#     # wait for processor to be deployed
#     while (state := ProcessorState(
#             rti_proxy.get_status(test_proc_id).state)) == ProcessorState.STARTING:
#         logger.info(f"Waiting for processor to deploy. {state.name=}")
#         time.sleep(5)
#     logger.info(f"Processor to deployed. {state.name=}")
#
#     # add test data object
#     owner = node.keystore
#     meta = dor_proxy.add_data_object(test_context.create_file_with_content(f"{generate_random_string(4)}.json",
#                                                                            json.dumps({'v': 1})),
#                                      owner.identity, False, False, 'JSONObject', 'json')
#     a_obj_id = meta.obj_id
#
#     task_input = [
#         Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': a_obj_id}),
#         Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
#     ]
#
#     task_output = [
#         Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                               'content_encrypted': False})
#     ]
#
#     # submit and wait
#     job_id, output = submit_and_wait(rti_proxy, test_proc_id, task_input, task_output, owner)
#     assert (output is not None)
#     assert ('c' in output)
#
#     # attempt to resume the job. note: this should work even though the job has already finished. we just
#     # need to provide valid reconnect info.
#     status: JobStatus = rti_proxy.get_job_status(job_id, owner)
#     assert(status.reconnect is not None)
#
#     # manually delete the remote exitcode file (we want to pretend the process hasn't finished yet)
#     exitcode_path = status.reconnect.pid_paths['exitcode']
#     run_command(f"mv {exitcode_path} {exitcode_path}.backup", ssh_credentials=nscc_ssh_cred)
#
#     job_descriptor = rti_proxy.resume_job(test_proc_id, status.job, status.reconnect,
#                                           with_authorisation_by=owner)
#     job_id = job_descriptor.id
#     logger.info(f"job_id={job_id}")
#     assert (job_id is not None)
#
#     def recreate_exitcode_file():
#         # wait 10 seconds until pretending for the process to have completed
#         time.sleep(10)
#         print('finishing now!!!')
#         run_command(f"mv {exitcode_path}.backup {exitcode_path}", ssh_credentials=nscc_ssh_cred)
#
#     # the following wait would never return because the process didn't really get timed-out. it actually finished
#     # and we just 'resumed' it after renaming the exitcode file. unless the exitcode file is renamed back to what
#     # it was, the wait will not return. so we start a thread which will wait for some time and then move the file
#     # back to where it was.
#     Thread(target=recreate_exitcode_file).start()
#     wait_for_job(rti_proxy, job_id, owner)
#
#     output_path = os.path.join(test_context.testing_dir, node.datastore, 'jobs', str(job_id), 'c')
#     assert os.path.isfile(output_path)
#
#
# def test_command_monitoring(test_context, nscc_ssh_cred):
#     wd_path = test_context.testing_dir
#     command_ok = "ls"
#     command_fail = "ls x"
#
#     # (1) Local + OK
#     try:
#         pid, paths = run_command_async(command_ok, wd_path, 'test1')
#         monitor_command(pid, paths)
#     except RunCommandError as e:
#         print(e)
#         assert False
#
#     # (2) Local + Fail
#     with pytest.raises(RunCommandError) as e:
#         pid, paths = run_command_async(command_fail, wd_path, 'test2')
#         monitor_command(pid, paths)
#     print(e.value)
#
#     # (3) Remote + OK
#     try:
#         pid, paths = run_command_async(command_ok, wd_path, 'test3', ssh_credentials=nscc_ssh_cred)
#         monitor_command(pid, paths, ssh_credentials=nscc_ssh_cred)
#     except RunCommandError as e:
#         print(e)
#         assert False
#
#     # (4) Remote + Fail
#     with pytest.raises(RunCommandError) as e:
#         pid, paths = run_command_async(command_fail, wd_path, 'test4', ssh_credentials=nscc_ssh_cred)
#         monitor_command(pid, paths, ssh_credentials=nscc_ssh_cred)
#     print(e)
#
#
# def test_simulate_vpn_disconnect(test_context, nscc_ssh_cred):
#     wd_path = test_context.testing_dir
#     command = "sleep 60"
#
#     try:
#         pid, paths = run_command_async(command, wd_path, 'test_sleep', ssh_credentials=nscc_ssh_cred)
#         monitor_command(pid, paths, ssh_credentials=nscc_ssh_cred)
#     except RunCommandError as e:
#         print(e)
#         assert False
