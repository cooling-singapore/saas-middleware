import json
import logging
import os
import time

import pytest

from saas.dor.proxy import DORProxy
from saas.core.logging import Logging
from saas.dor.schemas import DataObject
from saas.nodedb.proxy import NodeDBProxy
from saas.rest.exceptions import UnsuccessfulRequestError
from saas.rti.proxy import RTIProxy
from saas.rti.schemas import Task, JobStatus, Processor
from tests.base_testcase import update_keystore_from_credentials
from tests.conftest import add_test_processor

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


@pytest.fixture(scope='session')
def non_strict_node(test_context, extra_keystores):
    keystore = extra_keystores[0]
    update_keystore_from_credentials(keystore)
    node = test_context.get_node(keystore, use_rti=True, enable_rest=True, strict_deployment=False)
    return node


@pytest.fixture(scope='session')
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
def exec_only_node(test_context, extra_keystores):
    node = test_context.get_node(extra_keystores[1], use_dor=False, use_rti=True, enable_rest=True)
    return node


def test_rest_get_deployed(rti_proxy):
    result = rti_proxy.get_all_procs()
    assert (result is not None)
    assert (len(result) == 0)


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
    assert (info0.strict_deployment is False)
    assert (info1.strict_deployment is True)

    # upload the test proc GCC
    proc0: DataObject = add_test_processor(dor0, node0.keystore)
    proc_id0 = proc0.obj_id
    proc1: DataObject = add_test_processor(dor1, node1.keystore)
    proc_id1 = proc1.obj_id

    # make the wrong user identity known to the nodes
    wrong_user = known_user
    db0.update_identity(wrong_user.identity)
    db1.update_identity(wrong_user.identity)

    # try to deploy the processor with the wrong user on node0
    rti0.deploy(proc_id0, wrong_user)

    # wait for deployment to be done
    while True:
        proc = rti0.get_proc(proc_id0)
        if proc.state == Processor.State.READY:
            break
        time.sleep(0.5)

    # try to deploy the processor with the wrong user on node1
    with pytest.raises(UnsuccessfulRequestError) as e:
        rti1.deploy(proc_id1, wrong_user)
    assert ('User is not the node owner' in e.value.details['reason'])

    # try to deploy the processor with the correct user on node1
    rti1.deploy(proc_id1, node1.keystore)

    while True:
        proc = rti1.get_proc(proc_id1)
        if proc.state == Processor.State.READY:
            break
        time.sleep(0.5)

    # wait for deployment to be done
    while rti1.get_proc(proc_id1).state != Processor.State.READY:
        time.sleep(0.5)

    # try to undeploy the processor with the wrong user on node0
    rti0.undeploy(proc_id0, wrong_user)

    try:
        while True:
            rti1.get_proc(proc_id0)
            time.sleep(0.5)
    except UnsuccessfulRequestError as e:
        assert ('Processor not deployed' in e.reason)

    # try to undeploy the processor with the wrong user on node1
    with pytest.raises(UnsuccessfulRequestError) as e:
        rti1.undeploy(proc_id1, wrong_user)
    assert ('User is not the node owner' in e.value.details['reason'])

    # try to undeploy the processor with the correct user on node1
    rti1.undeploy(proc_id1, node1.keystore)

    try:
        while True:
            rti1.get_proc(proc_id1)
            time.sleep(0.5)
    except UnsuccessfulRequestError as e:
        assert ('Processor not deployed' in e.reason)


def test_rest_submit_list_get_job(test_context, node, dor_proxy, rti_proxy, deployed_test_processor, known_user):
    proc_id = deployed_test_processor.obj_id
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
    result = rti_proxy.submit_job(proc_id, task_input, task_output, owner)
    assert (result is not None)

    job_id = result.id

    # get list of all jobs by correct user
    result = rti_proxy.get_jobs_by_user(owner)
    assert (result is not None)
    result = {job.id: job for job in result}
    assert (job_id in result)

    # get list of all jobs by wrong user
    result = rti_proxy.get_jobs_by_user(wrong_user)
    assert (result is not None)
    assert (len(result) == 0)

    # get list of all jobs by proc
    result = rti_proxy.get_jobs_by_proc(proc_id)
    assert (result is not None)
    assert (len(result) == 1)

    # try to get the job info as the wrong user
    try:
        rti_proxy.get_job_status(job_id, wrong_user)
        assert False

    except UnsuccessfulRequestError as e:
        assert (e.details['reason'] == 'user is not the job owner or the node owner')

    while True:
        # get information about the running job
        try:
            status: JobStatus = rti_proxy.get_job_status(job_id, owner)

            from pprint import pprint
            pprint(status.dict())
            assert (status is not None)

            if status.state in [JobStatus.State.SUCCESSFUL, JobStatus.State.CANCELLED, JobStatus.State.FAILED]:
                break

        except Exception:
            pass

        time.sleep(1)

    # check if we have an object id for output object 'c'
    assert ('c' in status.output)

    # get the contents of the output data object
    download_path = os.path.join(test_context.testing_dir, 'c.json')
    dor_proxy.get_content(status.output['c'].obj_id, owner, download_path)
    assert (os.path.isfile(download_path))

    with open(download_path, 'r') as f:
        content = json.load(f)
        print(content)
        assert (content['v'] == 2)


def test_rest_submit_cancel_job(node, rti_proxy, deployed_test_processor, known_user):
    proc_id = deployed_test_processor.obj_id
    wrong_user = known_user
    owner = node.keystore

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 100}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 100}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id,
                               'restricted_access': False, 'content_encrypted': False})
    ]

    # submit the job
    result = rti_proxy.submit_job(proc_id, task_input, task_output, owner)
    assert (result is not None)

    job_id = result.id

    # try to cancel the job (wrong user)
    with pytest.raises(UnsuccessfulRequestError) as e:
        rti_proxy.cancel_job(job_id, wrong_user)
    assert ('user is not the job owner' in e.value.details['reason'])

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
    assert (status.state == JobStatus.State.CANCELLED)


# def test_processor_execution_value_non_dor_target(node, exec_only_node, rti_proxy, deployed_test_processor):
#     # join with the default node
#     target_node = exec_only_node
#     target_node.join_network(node.p2p.address())
#     time.sleep(2)
#
#     owner = node.keystore
#
#     task_input = [
#         Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
#         Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
#     ]
#
#     task_output = [
#         Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                                'content_encrypted': False, 'target_node_iid': target_node.identity.id})
#     ]
#
#     # submit and wait
#     try:
#         submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
#         assert False
#
#     except UnsuccessfulJob as e:
#         assert (e.details['errors'][0]['exception']['reason'] == 'Target node does not support DOR capabilities')
#
#
# def test_processor_execution_value_with_name_and_description(node, rti_proxy, deployed_test_processor):
#     owner = node.keystore
#
#     task_input = [
#         Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
#         Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
#     ]
#
#     task_output = [
#         Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                                'content_encrypted': False})
#     ]
#
#     # submit and wait
#     name = 'the job'
#     description = 'here is some description about this job...'
#     job_id = submit_job(rti_proxy, deployed_test_processor, task_input, task_output, owner,
#                         name=name, description=description)
#
#     # get the status
#     status = rti_proxy.get_job_status(job_id, owner)
#     print(status.job.task.name)
#     print(status.job.task.description)
#     assert (status.job.task.name == name)
#     assert (status.job.task.description == description)
#
#     # wait for the job to be done
#     output = wait_for_job(rti_proxy, job_id, owner)
#     assert (output is not None)
#     assert ('c' in output)
#
#
# def test_processor_execution_specific_target_node(node, non_strict_node, deployed_test_processor, rti_proxy, dor_proxy):
#     # create target node and join with the default node
#     target_node = non_strict_node
#     target_node.join_network(node.p2p.address())
#     target_dor = DORProxy(target_node.rest.address())
#     time.sleep(2)
#
#     owner = node.keystore
#
#     task_input = [
#         Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
#         Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
#     ]
#
#     task_output = [
#         Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                                'content_encrypted': False, 'target_node_iid': target_node.identity.id})
#     ]
#
#     # submit and wait
#     job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
#     assert (output is not None)
#     assert ('c' in output)
#
#     # the output data object should be with the target node
#     meta = dor_proxy.get_meta(output['c'].obj_id)
#     assert (meta is None)
#
#     meta = target_dor.get_meta(output['c'].obj_id)
#     assert (meta is not None)
#     assert (meta.custodian.identity.id == target_node.identity.id)
#
#     target_node.shutdown()
#     time.sleep(2)
#
#
# def test_processor_execution_reference_unrestricted(test_context, node, dor_proxy, rti_proxy, deployed_test_processor):
#     owner = node.keystore
#
#     # add test data object
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
#                                'content_encrypted': False})
#     ]
#
#     # submit and wait
#     job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
#     assert (output is not None)
#     assert ('c' in output)
#
#
# def test_provenance(test_context, node, dor_proxy, rti_proxy, deployed_test_processor):
#     owner = node.keystore
#
#     # add test data object
#     meta = dor_proxy.add_data_object(test_context.create_file_with_content(f"{generate_random_string(4)}.json",
#                                                                            json.dumps({'v': 1})),
#                                      owner.identity, False, False, 'JSONObject', 'json')
#     obj_id, c_hash = meta.obj_id, meta.c_hash
#
#     obj_id_a = obj_id
#     obj_id_b = obj_id
#     c_hash_a = c_hash
#     c_hash_b = c_hash
#
#     # run 3 iterations
#     log = []
#     for i in range(3):
#         task_input = [
#             Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': obj_id_a}),
#             Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 5}})
#         ]
#
#         task_output = [
#             Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                                    'content_encrypted': False})
#         ]
#
#         # submit and wait
#         job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
#         assert (output is not None)
#         assert ('c' in output)
#         obj_id = output['c'].obj_id
#
#         # get the c_hash for output object 'c'
#         meta = dor_proxy.get_meta(obj_id)
#         c_hash = meta.c_hash
#
#         log.append((c_hash_a, c_hash_b, c_hash))
#
#         obj_id_a = obj_id_b
#         obj_id_b = obj_id
#         c_hash_a = c_hash_b
#         c_hash_b = c_hash
#
#     for item in log:
#         print(f"{item[0]} + {item[1]} = {item[2]}")
#
#     # get the provenance and print it
#     provenance = dor_proxy.get_provenance(log[2][2])
#     assert (provenance is not None)
#     print(json.dumps(provenance.dict(), indent=2))
#
#
# def test_job_concurrency(test_context, node, dor_proxy, rti_proxy, deployed_test_processor):
#     wd_path = test_context.testing_dir
#     owner = node.keystore
#     results = {}
#     failed = {}
#     rnd = random.Random()
#
#     def do_a_job(idx: int) -> None:
#         try:
#             dt = rnd.randint(0, 1000) / 1000.0
#             v0 = rnd.randint(2, 6)
#             v1 = rnd.randint(2, 6)
#
#             time.sleep(dt)
#
#             task_input = [
#                 Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': v0}}),
#                 Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': v1}})
#             ]
#
#             task_output = [
#                 Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                                        'content_encrypted': False})
#             ]
#
#             job_id = submit_job(rti_proxy, deployed_test_processor, task_input, task_output, owner)
#             print(f"[{idx}] [{time.time()}] job {job_id} submitted")
#
#             status = rti_proxy.get_status(deployed_test_processor)
#             print(f"[{idx}] proc status: {status}")
#
#             output = wait_for_job(rti_proxy, job_id, owner)
#             print(f"[{idx}] job {job_id} done -> output: {output}")
#
#             obj_id = output['c'].obj_id
#             download_path = os.path.join(wd_path, f"{obj_id}.json")
#             while True:
#                 try:
#                     dor_proxy.get_content(obj_id, owner, download_path)
#                     break
#                 except UnsuccessfulRequestError as e:
#                     print(e)
#                     time.sleep(0.5)
#
#             with open(download_path, 'r') as f:
#                 content = json.load(f)
#                 results[idx] = content['v']
#
#         except Exception as e:
#             failed[idx] = e
#
#     # submit jobs
#     n = 10
#     threads = []
#     for i in range(n):
#         thread = threading.Thread(target=do_a_job, kwargs={'idx': i})
#         thread.start()
#         threads.append(thread)
#
#     # wait for all the threads
#     for thread in threads:
#         thread.join()
#
#     for idx, e in failed.items():
#         trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
#         logger.error(f"[{idx}] failed: {trace}")
#
#     # print(results)
#     logger.info(failed)
#     assert (len(failed) == 0)
#     assert (len(results) == n)
#
#
# def test_processor_execution_same_reference(test_context, node, dor_proxy, rti_proxy, deployed_test_processor):
#     # test for issue #110: https://github.com/cooling-singapore/saas-middleware/issues/110
#
#     owner = node.keystore
#
#     # add test data object
#     meta = dor_proxy.add_data_object(test_context.create_file_with_content(f"{generate_random_string(4)}.json",
#                                                                            json.dumps({'v': 1})),
#                                      owner.identity, False, False, 'JSONObject', 'json')
#     a_obj_id = meta.obj_id
#
#     task_input = [
#         Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': a_obj_id}),
#         Task.InputReference.parse_obj({'name': 'b', 'type': 'reference', 'obj_id': a_obj_id}),
#     ]
#
#     task_output = [
#         Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                                'content_encrypted': False})
#     ]
#
#     # submit and wait
#     job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input, task_output, owner)
#     assert (output is not None)
#     assert ('c' in output)
#
#     input_path_a = os.path.join(test_context.testing_dir, node.datastore, 'jobs', str(job_id), 'a')
#     input_path_b = os.path.join(test_context.testing_dir, node.datastore, 'jobs', str(job_id), 'b')
#     output_path = os.path.join(test_context.testing_dir, node.datastore, 'jobs', str(job_id), 'c')
#     assert (os.path.isfile(input_path_a))
#     assert (os.path.isfile(input_path_b))
#     assert (os.path.isfile(output_path))
#
#
# def test_processor_execution_reference_restricted(test_context, node, node_db_proxy, dor_proxy, rti_proxy, known_user,
#                                                   deployed_test_processor):
#     owner = node.keystore
#     rti_node_info = node_db_proxy.get_node()
#
#     # add test data object
#     meta = dor_proxy.add_data_object(test_context.create_file_with_content(f"{generate_random_string(4)}.json",
#                                                                            json.dumps({'v': 1})),
#                                      owner.identity, True, False, 'JSONObject', 'json')
#     a_obj_id = meta.obj_id
#
#     user = known_user
#
#     invalid_signature = user.sign("invalid content".encode('utf-8'))
#     task_input_invalid = [
#         Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': a_obj_id,
#                                        'user_signature': invalid_signature}),
#         Task.InputReference.parse_obj({'name': 'b', 'type': 'reference', 'obj_id': a_obj_id,
#                                        'user_signature': invalid_signature})
#     ]
#
#     task_output = [
#         Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                                'content_encrypted': False})
#     ]
#
#     # no access rights and no valid signature
#     with pytest.raises(UnsuccessfulJob) as e:
#         submit_and_wait(rti_proxy, deployed_test_processor, task_input_invalid, task_output, user)
#     assert ('Identity does not have access to data object' in e.value.details['errors'][0]['exception']['reason'])
#
#     # grant access
#     dor_proxy.grant_access(a_obj_id, owner, user.identity)
#
#     # access rights but invalid signature
#     with pytest.raises(UnsuccessfulJob) as e:
#         submit_and_wait(rti_proxy, deployed_test_processor, task_input_invalid, task_output, user)
#     assert ('authorisation failed' in e.value.details['errors'][0]['exception']['details']['reason'])
#
#     # create valid and invalid task input
#     valid_signature = user.sign(f"{rti_node_info.identity.id}:{a_obj_id}".encode('utf-8'))
#     task_input_valid = [
#         Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': a_obj_id,
#                                        'user_signature': valid_signature}),
#         Task.InputReference.parse_obj({'name': 'b', 'type': 'reference', 'obj_id': a_obj_id,
#                                        'user_signature': valid_signature})
#     ]
#
#     # access rights and valid signature
#     job_id, output = submit_and_wait(rti_proxy, deployed_test_processor, task_input_valid, task_output, user)
#     assert ('c' in output)
#
#
# def test_processor_execution_reference_encrypted(test_context, node, dor_proxy, rti_proxy, deployed_test_processor):
#     owner = node.keystore
#
#     # add encrypted test data object
#     obj_path = test_context.create_file_with_content(f"{generate_random_string(4)}.json", json.dumps({'v': 1}))
#     content_key = encrypt_file(obj_path, encrypt_for=owner.identity, delete_source=True)
#
#     meta = dor_proxy.add_data_object(obj_path, owner.identity, False, True, 'JSONObject', 'json')
#     obj_id = meta.obj_id
#
#     task_input = [
#         Task.InputReference.parse_obj({'name': 'a', 'type': 'reference', 'obj_id': obj_id}),
#         Task.InputReference.parse_obj({'name': 'b', 'type': 'reference', 'obj_id': obj_id})
#     ]
#
#     task_output = [
#         Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                                'content_encrypted': False})
#     ]
#
#     # submit the job
#     job_id = submit_job(rti_proxy, deployed_test_processor, task_input, task_output, owner)
#
#     # run monitoring thread
#     thread = Thread(target=handle_content_key_request, args=[rti_proxy, owner, job_id, content_key])
#     thread.start()
#
#     # wait for the job to finish
#     output = wait_for_job(rti_proxy, job_id, owner)
#     assert ('c' in output)
#
#
# def test_retain_job_history_false(test_context, keystore):
#     # create target node and join with the default node
#     target_node = test_context.get_node(keystore, enable_rest=True, retain_job_history=False)
#     target_rti = RTIProxy(target_node.rest.address())
#     target_dor = DORProxy(target_node.rest.address())
#     time.sleep(2)
#
#     owner = target_node.keystore
#
#     # add test proc and deploy
#     proc_id, gh_cred = add_test_processor(target_dor, owner, 'default')
#     deploy_and_wait(target_rti, proc_id, owner, gh_cred)
#
#     task_input = [
#         Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
#         Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
#     ]
#
#     task_output = [
#         Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                                'content_encrypted': False})
#     ]
#
#     # submit and wait
#     job_id, output = submit_and_wait(target_rti, proc_id, task_input, task_output, owner)
#     assert (output is not None)
#     assert ('c' in output)
#
#     # check if the output path exists
#     output_path = os.path.join(test_context.testing_dir, target_node.datastore, 'jobs', str(job_id), 'c')
#     assert not os.path.isfile(output_path)  # retain is False, so the path shouldn't exist!
#
#     target_node.shutdown()
#     time.sleep(2)
#
#
# def test_retain_job_history_true(test_context, keystore):
#     # create target node and join with the default node
#     target_node = test_context.get_node(keystore, enable_rest=True, retain_job_history=True)
#     target_rti = RTIProxy(target_node.rest.address())
#     target_dor = DORProxy(target_node.rest.address())
#     time.sleep(2)
#
#     owner = target_node.keystore
#
#     # add test proc and deploy
#     proc_id, gh_cred = add_test_processor(target_dor, owner, 'default')
#     deploy_and_wait(target_rti, proc_id, owner, gh_cred)
#
#     task_input = [
#         Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
#         Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 2}})
#     ]
#
#     task_output = [
#         Task.Output.parse_obj({'name': 'c', 'owner_iid': owner.identity.id, 'restricted_access': False,
#                                'content_encrypted': False})
#     ]
#
#     # submit and wait
#     job_id, output = submit_and_wait(target_rti, proc_id, task_input, task_output, owner)
#     assert (output is not None)
#     assert ('c' in output)
#
#     # check if the output path exists
#     output_path = os.path.join(test_context.testing_dir, target_node.datastore, 'jobs', str(job_id), 'c')
#     assert os.path.isfile(output_path)  # retain is False, so the path shouldn't exist!
#
#     target_node.shutdown()
#     time.sleep(2)
