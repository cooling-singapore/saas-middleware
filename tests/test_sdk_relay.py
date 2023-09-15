import json
import logging
import os
import time

import pytest
import shapely
from shapely import Polygon

from saas.core.exceptions import SaaSRuntimeException
from saas.core.helpers import read_json_from_file
from saas.core.logging import Logging
from saas.dor.proxy import DORProxy
from saas.dor.schemas import DataObject
from saas.nodedb.proxy import NodeDBProxy
from saas.rest.exceptions import UnexpectedHTTPError
from saas.rti.proxy import RTIProxy
from saas.rti.schemas import Task, JobStatus
from saas.sdk.app.auth import UserDB, UserAuth
from saas.sdk.base import SDKProcessor, connect, connect_to_relay, SDKRelayContext, SDKCDataObject
from saas.sdk.helper import create_rnd_hex_string, generate_random_file

from relay.server import RelayServer, RELAY_ENDPOINT_PREFIX_BASE

Logging.initialise(logging.DEBUG)
logger = Logging.get(__name__)

nextcloud_path = os.path.join(os.environ['HOME'], 'Nextcloud', 'CS', 'CS2.0', 'Pillar DUCT R&D', 'Testing')

db_endpoint_prefix = (RELAY_ENDPOINT_PREFIX_BASE, 'db')
dor_endpoint_prefix = (RELAY_ENDPOINT_PREFIX_BASE, 'dor')
rti_endpoint_prefix = (RELAY_ENDPOINT_PREFIX_BASE, 'rti')

server_address = ('127.0.0.1', 5011)
node_address = ('127.0.0.1', 5001)
user_password = 'password'


def run_iem(proc_prep: SDKProcessor, proc_sim: SDKProcessor, bf_obj: SDKCDataObject,
            wd: float, ws: float, area: dict, output_path: str) -> None:

    # submit the job for pre-processing -> creates everything that's needed to run IEM sim,
    # most importantly it meshes the geometries.
    job0 = proc_prep.submit({
        'building-footprints': bf_obj,
        'parameters': {
            'settings': {
                'wind_direction': wd,
                'wind_speed': ws
            },
            # don't change the scaling parameters
            'scaling': {
                'lon': 111000,
                'lat': 111000,
                'height': 1
            },
            'area': area
        }
    })

    # wait for the job to be done
    output = job0.wait()

    # obtain the run package handle
    run_package = output['iem-run-package']
    print(run_package.meta)
    print(f"run package object id: {run_package.meta.obj_id}")

    # submit the job for the IEMSim run.
    job1 = proc_sim.submit({
        'iem-run-package': run_package,
        # don't change the following parameters. they are needed for the Aspire1 environment.
        'parameters': {
            'pbs_project_id': '21120261',
            'pbs_queue': 'normal',
            'pbs_nnodes': '1',
            'pbs_ncpus': '24',
            'pbs_mem': '96GB',
            'pbs_mpiprocs': '24',
            'walltime': '06:00:00',
        }
    })
    print(f"job id: {job1.content.id}")

    # wait for the job to be done
    output = job1.wait()

    at_map = output['air-temperature']
    ws_map = output['wind-speed']
    wd_map = output['wind-direction']

    at_map.download(os.path.join(output_path, f'at_{ws}_{wd}.tiff'))
    ws_map.download(os.path.join(output_path, f'ws_{ws}_{wd}.tiff'))
    wd_map.download(os.path.join(output_path, f'wd_{ws}_{wd}.tiff'))

    # clean up
    run_package.delete()


def extract_buildings(bf_input_path: str, bbox: dict,
                      bf_output_path: str) -> None:
    # create shape of bbox
    west = bbox['west']
    north = bbox['north']
    east = bbox['east']
    south = bbox['south']
    area = Polygon([[west, north], [east, north], [east, south], [west, south]])

    with open(bf_input_path, 'r') as f_in:
        content = f_in.read()
        content = json.loads(content)

        # check all features, if the feature overlaps with the area of interest
        result = []
        for feature in content['features']:
            geometry = feature['geometry']
            shape = shapely.geometry.shape(geometry)

            if area.intersection(shape).area > 0:
                result.append(feature)

    with open(bf_output_path, 'w') as f_out:
        content = json.dumps({
            'type': 'FeatureCollection',
            # 'crs': {'type': 'name', 'properties': {'name': 'urn:ogc:def:crs:OGC:1.3:CRS84'}},
            'features': result
        })
        f_out.write(content)


@pytest.fixture()
def init_auth_and_db(temp_directory):
    keystore_path = os.path.join(temp_directory, 'keystore')
    os.makedirs(keystore_path)

    # initialise user Auth and DB
    UserAuth.initialise(create_rnd_hex_string(32))
    UserDB.initialise(temp_directory)


@pytest.fixture(autouse=True)
def context(init_auth_and_db, temp_directory, owner, user):
    _owner, _ = owner
    _user, _ = user

    print("created")

    # create Dashboard server and proxy
    server = RelayServer(server_address, node_address, temp_directory)
    server.startup()

    context = connect(node_address, _user.keystore)

    # make identities known
    context.publish_identity(_owner.identity)
    context.publish_identity(_user.identity)

    yield context

    server.shutdown()


@pytest.fixture()
def owner():
    user = UserDB.add_user('foo.bar@email.com', 'Foo Bar', user_password)
    credentials = ('foo.bar@email.com', user_password)
    return user, credentials


@pytest.fixture()
def user():
    user = UserDB.add_user('john.doe@email.com', 'John Doe', user_password)
    credentials = ('john.doe@email.com', user_password)
    return user, credentials


@pytest.fixture()
def gpp(context):
    # upload test processor
    source = 'https://github.com/cooling-singapore/saas-middleware-sdk'
    commit_id = '5efcd1e'
    proc_path = 'examples/adapters/proc_example'
    proc_config = 'default'
    gpp = context.upload_gpp(source, commit_id, proc_path, proc_config)

    return gpp


@pytest.fixture()
def processor(context, gpp):
    # deploy the test processor
    rti = context.rti()
    proc = gpp.deploy(rti)

    yield proc

    proc.undeploy()


def test_get_node(owner) -> None:
    with pytest.raises(UnexpectedHTTPError) as e:
        db = NodeDBProxy(server_address, credentials=None, endpoint_prefix=db_endpoint_prefix)
        db.get_node()
    assert e.value.details['response'].status_code == 401

    try:
        _, owner_credentials = owner
        db = NodeDBProxy(server_address, credentials=owner_credentials, endpoint_prefix=db_endpoint_prefix)
        node = db.get_node()
    except Exception as e:
        print(e)
        assert False
    else:
        print(node)
        assert (node is not None)


def test_get_network(owner) -> None:
    with pytest.raises(UnexpectedHTTPError) as e:
        db = NodeDBProxy(server_address, credentials=None, endpoint_prefix=db_endpoint_prefix)
        db.get_network()
    assert e.value.details['response'].status_code == 401

    try:
        _, owner_credentials = owner
        db = NodeDBProxy(server_address, credentials=owner_credentials, endpoint_prefix=db_endpoint_prefix)
        network = db.get_network()
    except Exception as e:
        print(e)
        assert False
    else:
        print(network)
        assert (network is not None)


def test_get_identity(owner) -> None:
    _owner, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        db = NodeDBProxy(server_address, credentials=None, endpoint_prefix=db_endpoint_prefix)
        db.get_identity(_owner.identity.id)
    assert e.value.details['response'].status_code == 401

    try:
        db = NodeDBProxy(server_address, credentials=owner_credentials, endpoint_prefix=db_endpoint_prefix)
        identity = db.get_identity(_owner.identity.id)
    except Exception as e:
        print(e)
        assert False
    else:
        print(identity)
        assert (identity is not None)
        assert (identity.id == _owner.identity.id)


def test_get_identities(owner) -> None:
    _, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        db = NodeDBProxy(server_address, credentials=None, endpoint_prefix=db_endpoint_prefix)
        db.get_identities()
    assert e.value.details['response'].status_code == 401

    try:
        db = NodeDBProxy(server_address, credentials=owner_credentials, endpoint_prefix=db_endpoint_prefix)
        result = db.get_identities()
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)


def test_update_identity(owner) -> None:
    _owner, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        db = NodeDBProxy(server_address, credentials=None, endpoint_prefix=db_endpoint_prefix)
        db.update_identity(_owner.identity)
    assert e.value.details['response'].status_code == 401

    try:
        db = NodeDBProxy(server_address, credentials=owner_credentials, endpoint_prefix=db_endpoint_prefix)
        result = db.update_identity(_owner.identity)
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)


def test_search(owner) -> None:
    _owner, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.search()
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        result = dor.search()
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)


def test_statistics(owner) -> None:
    _owner, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.statistics()
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        result = dor.statistics()
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)


def test_add_get_remove_c(temp_directory, owner) -> None:
    _owner, owner_credentials = owner

    # create random temp file
    content_path = os.path.join(temp_directory, 'content')
    generate_random_file(content_path, 1024*1024)

    # ADD
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.add_data_object(content_path, _owner.identity, False, False, 'data_type', 'data_format')
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        meta = dor.add_data_object(content_path, _owner.identity, False, False, 'data_type', 'data_format')
    except Exception as e:
        print(e)
        assert False
    else:
        print(meta)
        assert (meta is not None)

    # GET META
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.get_meta(meta.obj_id)
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        meta = dor.get_meta(meta.obj_id)
    except Exception as e:
        print(e)
        assert False
    else:
        print(meta)
        assert (meta is not None)

    # GET CONTENT
    download_path = os.path.join(temp_directory, 'downloaded')
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.get_content(meta.obj_id, with_authorisation_by=_owner.keystore, download_path=download_path)
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        dor.get_content(meta.obj_id, with_authorisation_by=_owner.keystore, download_path=download_path)
    except Exception as e:
        print(e)
        assert False
    else:
        assert (os.path.isfile(download_path))

    # DELETE
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.delete_data_object(meta.obj_id, with_authorisation_by=_owner.keystore)
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        meta = dor.delete_data_object(meta.obj_id, with_authorisation_by=_owner.keystore)
    except Exception as e:
        print(e)
        assert False
    else:
        print(meta)
        assert (meta is not None)


def test_add_gpp(owner) -> None:
    _owner, owner_credentials = owner

    source = 'https://github.com/cooling-singapore/saas-middleware-sdk'
    commit_id = '310354f'
    proc_path = 'examples/adapters/proc_example'
    proc_config = 'default'

    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.add_gpp_data_object(source, commit_id, proc_path, proc_config, _owner.identity)
    assert e.value.details['response'].status_code == 401

    with pytest.raises(SaaSRuntimeException) as e:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        dor.add_gpp_data_object(source, commit_id, proc_path, proc_config, _owner.identity)
    assert e.value.details['status_code'] == 500


def test_tag_untag_grant_transfer_revoke_access(temp_directory, owner, user) -> None:
    _owner, owner_credentials = owner
    _user, user_credentials = user

    # create random temp file
    content_path = os.path.join(temp_directory, 'content')
    generate_random_file(content_path, 1024*1024)

    # ADD
    dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
    meta = dor.add_data_object(content_path, _owner.identity, False, False, 'data_type', 'data_format')

    # TAG
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.update_tags(meta.obj_id, authority=_owner.keystore, tags=[
            DataObject.Tag(key='hello', value='world')
        ])
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        meta = dor.update_tags(meta.obj_id, authority=_owner.keystore, tags=[
            DataObject.Tag(key='hello', value='world')
        ])
    except Exception as e:
        print(e)
        assert False
    else:
        print(meta)
        assert (meta is not None)

    # UNTAG
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.remove_tags(meta.obj_id, authority=_owner.keystore, keys=['hello'])
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        meta = dor.remove_tags(meta.obj_id, authority=_owner.keystore, keys=['hello'])
    except Exception as e:
        print(e)
        assert False
    else:
        print(meta)
        assert (meta is not None)

    # GRANT
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.grant_access(meta.obj_id, authority=_owner.keystore, identity=_user.identity)
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        meta = dor.grant_access(meta.obj_id, authority=_owner.keystore, identity=_user.identity)
    except Exception as e:
        print(e)
        assert False
    else:
        print(meta)
        assert (meta is not None)
        assert (_user.identity.id in meta.access)

    # REVOKE
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.revoke_access(meta.obj_id, authority=_owner.keystore, identity=_user.identity)
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        meta = dor.revoke_access(meta.obj_id, authority=_owner.keystore, identity=_user.identity)
    except Exception as e:
        print(e)
        assert False
    else:
        assert (meta is not None)

    # TRANSFER
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.transfer_ownership(meta.obj_id, authority=_owner.keystore, new_owner=_user.identity)
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        meta = dor.transfer_ownership(meta.obj_id, authority=_owner.keystore, new_owner=_user.identity)
    except Exception as e:
        print(e)
        assert False
    else:
        print(meta)
        assert (meta is not None)
        assert (_user.identity.id == meta.owner_iid)

    dor = DORProxy(server_address, credentials=user_credentials, endpoint_prefix=dor_endpoint_prefix)
    dor.delete_data_object(meta.obj_id, with_authorisation_by=_user.keystore)


def test_deployed(owner, processor) -> None:
    _, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        rti = RTIProxy(server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
        rti.get_deployed()
    assert e.value.details['response'].status_code == 401

    try:
        rti = RTIProxy(server_address, credentials=owner_credentials, endpoint_prefix=rti_endpoint_prefix)
        result = rti.get_deployed()
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)


def test_deploy(owner, gpp, processor) -> None:
    _owner, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        rti = RTIProxy(server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
        rti.deploy(gpp.meta.obj_id, authority=_owner.keystore)
    assert e.value.details['response'].status_code == 401

    with pytest.raises(SaaSRuntimeException) as e:
        rti = RTIProxy(server_address, credentials=owner_credentials, endpoint_prefix=rti_endpoint_prefix)
        rti.deploy(gpp.meta.obj_id, authority=_owner.keystore)
    assert e.value.details['status_code'] == 500


def test_undeploy(owner, gpp, processor) -> None:
    _owner, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        rti = RTIProxy(server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
        rti.undeploy(gpp.meta.obj_id, authority=_owner.keystore)
    assert e.value.details['response'].status_code == 401

    with pytest.raises(SaaSRuntimeException) as e:
        rti = RTIProxy(server_address, credentials=owner_credentials, endpoint_prefix=rti_endpoint_prefix)
        rti.undeploy(gpp.meta.obj_id, authority=_owner.keystore)
    assert e.value.details['status_code'] == 500


def test_gpp(owner, gpp) -> None:
    _owner, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        rti = RTIProxy(server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
        rti.get_gpp(gpp.meta.obj_id)
    assert e.value.details['response'].status_code == 401

    try:
        rti = RTIProxy(server_address, credentials=owner_credentials, endpoint_prefix=rti_endpoint_prefix)
        result = rti.get_gpp(gpp.meta.obj_id)
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)


def test_status(owner, gpp, processor) -> None:
    _owner, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        rti = RTIProxy(server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
        rti.get_status(gpp.meta.obj_id)
    assert e.value.details['response'].status_code == 401

    try:
        rti = RTIProxy(server_address, credentials=owner_credentials, endpoint_prefix=rti_endpoint_prefix)
        result = rti.get_status(gpp.meta.obj_id)
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)


def test_submit_status_logs_provenance(temp_directory, owner, processor) -> None:
    _owner, owner_credentials = owner

    # connect to Relay -> this publishes a 'proxy identity' for the user (i.e., _owner) which we are
    # going to use in this test case
    connect_to_relay(temp_directory, server_address, (_owner.login, user_password))

    task_input = [
        Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
        Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 1}})
    ]

    task_output = [
        Task.Output.parse_obj({'name': 'c', 'owner_iid': _owner.identity.id,
                               'restricted_access': False, 'content_encrypted': False})
    ]

    # SUBMIT
    with pytest.raises(UnexpectedHTTPError) as e:
        rti = RTIProxy(server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
        rti.submit_job(processor.descriptor.proc_id, task_input, task_output, _owner.keystore)
    assert e.value.details['response'].status_code == 401

    try:
        rti = RTIProxy(server_address, credentials=owner_credentials, endpoint_prefix=rti_endpoint_prefix)
        result = rti.submit_job(processor.descriptor.proc_id, task_input, task_output, _owner.keystore)
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)
        job_id = result.id

    # STATUS
    with pytest.raises(UnexpectedHTTPError) as e:
        rti = RTIProxy(server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
        rti.get_job_status(job_id, with_authorisation_by=_owner.keystore)
    assert e.value.details['response'].status_code == 401

    try:
        rti = RTIProxy(server_address, credentials=owner_credentials, endpoint_prefix=rti_endpoint_prefix)
        result = rti.get_job_status(job_id, with_authorisation_by=_owner.keystore)
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)

    while True:
        # get information about the running job
        status: JobStatus = rti.get_job_status(job_id, with_authorisation_by=_owner.keystore)
        from pprint import pprint
        pprint(status.dict())
        assert (status is not None)

        if status.state in [JobStatus.State.SUCCESSFUL, JobStatus.State.FAILED]:
            break

        time.sleep(1)

    obj = status.output['c']

    # LOGS
    logs_path = os.path.join(temp_directory, 'logs')
    with pytest.raises(UnexpectedHTTPError) as e:
        rti = RTIProxy(server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
        rti.get_job_logs(job_id, with_authorisation_by=_owner.keystore, download_path=logs_path)
    assert e.value.details['response'].status_code == 401

    try:
        rti = RTIProxy(server_address, credentials=owner_credentials, endpoint_prefix=rti_endpoint_prefix)
        rti.get_job_logs(job_id, with_authorisation_by=_owner.keystore, download_path=logs_path)
    except Exception as e:
        print(e)
        assert False
    else:
        assert (os.path.isfile(logs_path))

    # PROVENANCE
    with pytest.raises(UnexpectedHTTPError) as e:
        dor = DORProxy(server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
        dor.get_provenance(obj.c_hash)
    assert e.value.details['response'].status_code == 401

    try:
        dor = DORProxy(server_address, credentials=owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        result = dor.get_provenance(obj.c_hash)
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert(result is not None)


def test_resume() -> None:
    pass


def test_jobs_by_proc(owner, gpp) -> None:
    _owner, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        rti = RTIProxy(server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
        rti.get_jobs_by_proc(gpp.meta.obj_id)
    assert e.value.details['response'].status_code == 401

    try:
        rti = RTIProxy(server_address, credentials=owner_credentials, endpoint_prefix=rti_endpoint_prefix)
        result = rti.get_jobs_by_proc(gpp.meta.obj_id)
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)


def test_jobs_by_user(owner) -> None:
    _owner, owner_credentials = owner
    with pytest.raises(UnexpectedHTTPError) as e:
        rti = RTIProxy(server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
        rti.get_jobs_by_user(authority=_owner.keystore)
    assert e.value.details['response'].status_code == 401

    try:
        rti = RTIProxy(server_address, credentials=owner_credentials, endpoint_prefix=rti_endpoint_prefix)
        result = rti.get_jobs_by_user(authority=_owner.keystore)
    except Exception as e:
        print(e)
        assert False
    else:
        print(result)
        assert (result is not None)


def test_job_cancel() -> None:
    pass


def test_put_permission() -> None:
    pass


def test_sdk(temp_directory, user, processor) -> None:
    _, user_credentials = user
    context: SDKRelayContext = connect_to_relay(temp_directory, server_address, user_credentials)

    proc: SDKProcessor = context.find_processor_by_name(processor.name)
    assert(proc is not None)

    for a in range(0, 2):
        for b in range(0, 2):
            output = proc.submit_and_wait({
                'a': {"v": a},
                'b': {"v": b}
            })

            obj_c = output['c']
            download_path = os.path.join(temp_directory, f"c_for_a{a}_b{b}.json")
            obj_c.download(download_path)

            # load the result
            c = read_json_from_file(download_path)
            c = c['v']
            print(f"{a} + {b} = {c}")

    context.close()


def test_sdk_remote(temp_directory, processor) -> None:
    context: SDKRelayContext = connect_to_relay(temp_directory,
                                                relay_address=('https', 'api-dev.duct.sg', 443),
                                                credentials=('foo.bar@somewhere.com', '105PFvIg'))

    result = context.find_processors()
    for proc in result:
        print(proc.name)
        print(proc.descriptor)

    context.close()


@pytest.mark.skipif(not os.path.exists(nextcloud_path), reason="Test directory not found")
def test_sdk_remote_iemsim(temp_directory, processor) -> None:
    # path to the building footprints file with ALL the building footprints
    bf_path = os.path.join(nextcloud_path, 'bdpimport_geo', 'output', 'building-footprints')

    # bounding box of the area of interest
    area = {
        "west": 103.9058553468161392,
        "south": 1.3270255520350709,
        "east": 103.9090271198505349,
        "north": 1.3290574984153798
    }

    # path to the building footprints file with only those buildings that are inside the area of interest
    extracted_bf_path = os.path.join(temp_directory, 'bf_extracted.geojson')

    # extract the buildings in the area of interest
    extract_buildings(bf_path, area, extracted_bf_path)

    # connect to the Relay
    context: SDKRelayContext = connect_to_relay(temp_directory,
                                                relay_address=('https', 'api-dev.duct.sg', 443),
                                                credentials=('foo.bar@somewhere.com', '105PFvIg'))

    # upload the extracted buildings so the processors can use it
    bf_obj = context.upload_content(extracted_bf_path, 'DUCT.GeoVectorData', 'geojson',
                                    access_restricted=False)
    print(bf_obj.meta)

    # find the two processors that we need: ucm-iem-prep and ucm-iem-sim
    proc_prep = context.find_processor_by_name('ucm-iem-prep')
    proc_sim = context.find_processor_by_name('ucm-iem-sim')
    if proc_prep is None or proc_sim is None:
        raise RuntimeError("Processors not found.")

    # define the output path, i.e., the folder where to store all the simulation output
    # output_path = self._wd_path
    output_path = os.path.join(os.environ['HOME'], 'Desktop')

    # running an IEM simulation requires two steps: (1) pre-processing (using ucm-iem-prep) and
    # (2) solving (using ucm-iem-sim).
    # for ws in range(1, 5, 1):
    #     for wd in range(0, 360, 45):
    #         print(f"ws={ws} wd={wd}")
    #         run_iem(proc_prep, proc_sim, bf_obj, wd, wd, area, output_path)

    run_iem(proc_prep, proc_sim, bf_obj, 45, 2.5, area, output_path)

    # close the Relay session
    context.close()
