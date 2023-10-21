import json
import logging
import os
import shutil
import tempfile
import time
import pytest

from saas.core.logging import Logging
from saas.dor.schemas import DataObject, GPP_DATA_TYPE
from saas.node import Node
from saas.rti.schemas import Task, JobStatus
from saas.sdk.app.auth import UserDB, UserAuth
from saas.sdk.base import SDKProcessor, connect, SDKContext, SDKCDataObject, SDKGPPDataObject

from dashboard.proxy import DashboardProxy
from dashboard.server import DashboardServer, DashboardRuntimeError
from tests.base_testcase import create_rnd_hex_string, PortMaster

Logging.initialise(logging.DEBUG)
logger = Logging.get(__name__)

server_address = PortMaster.generate_rest_address()
user_password = 'password'


@pytest.fixture(scope="module")
def node_wo_concurrency(keystore):
    with tempfile.TemporaryDirectory() as tempdir:
        rest_address = PortMaster.generate_rest_address()
        p2p_address = PortMaster.generate_p2p_address()

        _node = Node.create(keystore=keystore, storage_path=tempdir,
                            p2p_address=p2p_address, boot_node_address=p2p_address, rest_address=rest_address,
                            enable_dor=True, enable_rti=True, strict_deployment=False, job_concurrency=False)

        yield _node

        _node.shutdown()


@pytest.fixture(scope="module")
def init_auth_and_db(temp_directory):
    keystore_path = os.path.join(temp_directory, 'keystore')
    if os.path.isdir(keystore_path):
        shutil.rmtree(keystore_path)
    os.makedirs(keystore_path)

    # initialise user Auth and DB
    UserAuth.initialise(create_rnd_hex_string(32))
    UserDB.initialise(temp_directory)

    yield

    UserDB.delete(temp_directory)


@pytest.fixture(scope="module")
def owner():
    login = 'foo.bar@email.com'
    user = UserDB.add_user(login, 'Foo Bar', user_password)
    credentials = ('foo.bar@email.com', user_password)

    yield user, credentials

    UserDB.delete_user(login)


@pytest.fixture(scope="module")
def user():
    login = 'john.doe@email.com'
    user = UserDB.add_user(login, 'John Doe', user_password)
    credentials = ('john.doe@email.com', user_password)

    yield user, credentials

    UserDB.delete_user(login)


@pytest.fixture(autouse=True, scope="module")
def dashboard_context(init_auth_and_db, temp_directory, owner, user, node_wo_concurrency) -> SDKContext:
    _owner, _ = owner
    _user, _ = user
    node_address = node_wo_concurrency.rest.address()

    # create Relay server and proxy
    server = DashboardServer(server_address, node_address, temp_directory)
    server.startup()

    context: SDKContext = connect(node_address, _user.keystore)

    # make identities known
    context.publish_identity(_owner.identity)
    context.publish_identity(_user.identity)

    yield context

    server.shutdown()


@pytest.fixture(scope='module')
def proc_example(dashboard_context) -> SDKProcessor:
    # upload test processor
    source = 'https://github.com/cooling-singapore/saas-middleware'
    commit_id = 'e107901'
    proc_path = 'examples/adapters/proc_example'
    proc_config = 'default'
    gpp = dashboard_context.upload_gpp(source, commit_id, proc_path, proc_config)

    # deploy processor
    proc = gpp.deploy(dashboard_context.rti())

    yield proc

    proc.undeploy()
    gpp.delete()


@pytest.fixture(scope='module')
def test_obj_a(temp_directory, dashboard_context) -> SDKCDataObject:
    # add test data
    content_path = os.path.join(temp_directory, 'a.json')
    with open(content_path, 'w') as f:
        f.write(json.dumps({"v": 1}))

    # upload object a
    obj = dashboard_context.upload_content(content_path, 'JSONObject', 'json', False, False)

    # delete content file
    os.remove(content_path)

    yield obj

    obj.delete()


@pytest.fixture()
def test_obj_b(temp_directory, dashboard_context) -> SDKCDataObject:
    # add test data
    content_path = os.path.join(temp_directory, 'b.json')
    with open(content_path, 'w') as f:
        f.write(json.dumps({"v": 2}))

    # upload object a
    obj = dashboard_context.upload_content(content_path, 'JSONObject', 'json', False, False)

    # delete content file
    os.remove(content_path)

    yield obj

    obj.delete()


@pytest.fixture()
def test_gpp(temp_directory, dashboard_context) -> SDKGPPDataObject:
    gpp = dashboard_context.upload_gpp(
        source='https://github.com/cooling-singapore/saas-middleware',
        commit_id='e107901',
        proc_path='examples/adapters/proc_example',
        proc_config='default'
    )

    yield gpp

    gpp.delete()


@pytest.fixture()
def proxy(user) -> DashboardProxy:
    _user, _ = user
    return DashboardProxy(server_address, _user, user_password)


def test_get_processors(proxy, proc_example):
    results = proxy.get_processors()
    assert results is not None and len(results) > 0

    results = {result.proc_id: result for result in results}
    assert proc_example.descriptor.proc_id in results


def test_submit_job_wait_provenance(proxy, proc_example, test_obj_a, user, dashboard_context):
    _user, _ = user

    # submit job
    job = proxy.submit_job('job0', 'this is a test job', proc_example.descriptor.proc_id, [
        Task.InputReference(name='a', type='reference', obj_id=test_obj_a.meta.obj_id),
        Task.InputValue(name='b', type='value', value={"v": 1})
    ], [
        Task.Output(name='c', owner_iid=_user.identity.id,
                    restricted_access=False, content_encrypted=False)
    ])

    # wait for job to be done
    while True:
        time.sleep(1)
        status = proxy.get_job(job.id)
        if status['state'] in [JobStatus.State.SUCCESSFUL]:
            break
        elif status['state'] in [JobStatus.State.FAILED, JobStatus.State.CANCELLED]:
            raise DashboardRuntimeError(f"Unexpected state: {status['state']}")

    # test getting all jobs with status
    jobs = proxy.get_all_jobs()
    print(jobs)
    assert(len(jobs) == 1)
    assert(jobs[0]['job']['id'] == job.id)

    # check if we have the output data object
    assert (status['output_objects'][0]['output_name'] == 'c')

    # get the provenance information
    obj_c_id = status['output_objects'][0]['obj_id']
    result = proxy.provenance(obj_c_id)
    assert(result is not None)
    print(result)

    obj_c = dashboard_context.find_data_object(obj_c_id)
    assert obj_c is not None

    obj_c.delete()


def test_submit_job_and_cancel(proxy, proc_example, test_obj_a, user):
    _user, _ = user

    # submit job
    job = proxy.submit_job('job0', 'this is a test job', proc_example.descriptor.proc_id, [
        Task.InputReference(name='a', type='reference', obj_id=test_obj_a.meta.obj_id),
        Task.InputValue(name='b', type='value', value={"v": 1})
    ], [
        Task.Output(name='c', owner_iid=_user.identity.id, restricted_access=False, content_encrypted=False)
    ])

    # wait for job to be running
    while True:
        time.sleep(0.25)
        status = proxy.get_job(job.id)
        print(status['state'])
        if status['state'] == JobStatus.State.RUNNING:
            break

    proxy.cancel_job(job.id)

    # wait for job to be done
    while True:
        time.sleep(1)
        status = proxy.get_job(job.id)
        if status['state'] in [JobStatus.State.CANCELLED]:
            break
        elif status['state'] in [JobStatus.State.SUCCESSFUL, JobStatus.State.CANCELLED]:
            assert False


def test_upload_data_search_delete(proxy, proc_example, test_obj_b, test_gpp, user):
    # tag the object
    test_obj_b.update_tags([
        DataObject.Tag(key='project', value='hello-world'),
        DataObject.Tag(key='department', value='planning')
    ])

    # tag the gpp
    test_gpp.update_tags([
        DataObject.Tag(key='project', value='hello-world'),
        DataObject.Tag(key='department', value='IT')
    ])

    # search by patterns
    result = proxy.search_data()
    assert(len(result) >= 3)

    result = proxy.search_data(patterns=['planning'], owned_by_user=True)
    assert(len(result) == 1)

    result = proxy.search_data(patterns=['IT'], owned_by_user=True)
    assert(len(result) == 1)

    result = proxy.search_data(patterns=['hello-world'], owned_by_user=True)
    assert(len(result) == 2)

    result = proxy.search_data(patterns=['planning', 'IT'], owned_by_user=True)
    assert(len(result) == 2)

    result = proxy.search_data(c_hashes=[test_obj_b.meta.c_hash], owned_by_user=True)
    assert(len(result) == 1)

    result = proxy.search_data(c_hashes=[test_gpp.meta.c_hash], owned_by_user=True)
    assert(len(result) == 2)

    result = proxy.search_data(c_hashes=[test_obj_b.meta.c_hash, test_gpp.meta.c_hash], owned_by_user=True)
    assert(len(result) == 3)

    result = proxy.search_data(data_type=GPP_DATA_TYPE, owned_by_user=True)
    assert(len(result) == 2)

    result = proxy.search_data(data_format='json', owned_by_user=True)
    assert(len(result) >= 3)
