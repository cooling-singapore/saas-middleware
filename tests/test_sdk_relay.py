import json
import logging
import os
import shutil
import time
import unittest
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
from saas.sdk.helper import create_wd, create_rnd_hex_string, generate_random_file

from relay.server import RelayServer, RELAY_ENDPOINT_PREFIX_BASE

Logging.initialise(logging.DEBUG)
logger = Logging.get(__name__)

nextcloud_path = os.path.join(os.environ['HOME'], 'Nextcloud', 'CS', 'CS2.0', 'Pillar DUCT R&D', 'Testing')

db_endpoint_prefix = (RELAY_ENDPOINT_PREFIX_BASE, 'db')
dor_endpoint_prefix = (RELAY_ENDPOINT_PREFIX_BASE, 'dor')
rti_endpoint_prefix = (RELAY_ENDPOINT_PREFIX_BASE, 'rti')


class RelayServerTestCase(unittest.TestCase):
    _server_address = ('127.0.0.1', 5011)
    _node_address = ('127.0.0.1', 5001)
    _wd_path = None
    _server = None
    _proxy = None

    _keystore_path = None
    _datastore_path = None
    _owner = None
    _user = None
    _context = None
    _proc: SDKProcessor = None

    def setUp(self):
        if not self._server:
            # create folders
            self._wd_path = create_wd()
            self._keystore_path = os.path.join(self._wd_path, 'keystore')
            os.makedirs(self._keystore_path, exist_ok=True)

            # initialise user Auth and DB
            UserAuth.initialise(create_rnd_hex_string(32))
            UserDB.initialise(self._wd_path)

            # create users: owner and user
            self._password = 'password'
            self._owner = UserDB.add_user('foo.bar@email.com', 'Foo Bar', self._password)
            self._user = UserDB.add_user('john.doe@email.com', 'John Doe', self._password)

            self._owner_credentials = ('foo.bar@email.com', self._password)
            self._user_credentials = ('john.doe@email.com', self._password)

            # create Dashboard server and proxy
            self._server = RelayServer(self._server_address, self._node_address, self._wd_path)
            self._server.startup()

            # get SaaS context
            self._context = connect(self._node_address, self._user.keystore)

            # make identities known
            self._context.publish_identity(self._owner.identity)
            self._context.publish_identity(self._user.identity)

            # upload test processor
            source = 'https://github.com/cooling-singapore/saas-middleware-sdk'
            commit_id = '5efcd1e'
            proc_path = 'examples/adapters/proc_example'
            proc_config = 'default'
            self._gpp = self._context.upload_gpp(source, commit_id, proc_path, proc_config)

            # deploy the test processor
            rti = self._context.rti()
            self._proc = self._gpp.deploy(rti)

    @classmethod
    def tearDownClass(cls):
        if cls._server is not None:
            # undeploy processor
            cls._proc.undeploy()

            # shutdown server
            cls._server.shutdown()

            # delete working directory
            shutil.rmtree(cls._wd_path, ignore_errors=True)

    def test_get_node(self) -> None:
        try:
            db = NodeDBProxy(self._server_address, credentials=None,
                             endpoint_prefix=db_endpoint_prefix)
            db.get_node()
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            db = NodeDBProxy(self._server_address, credentials=self._owner_credentials,
                             endpoint_prefix=db_endpoint_prefix)
            node = db.get_node()
            print(node)
            assert (node is not None)
        except Exception as e:
            print(e)
            assert False

    def test_get_network(self) -> None:
        try:
            db = NodeDBProxy(self._server_address, credentials=None,
                             endpoint_prefix=db_endpoint_prefix)
            db.get_network()
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            db = NodeDBProxy(self._server_address, credentials=self._owner_credentials,
                             endpoint_prefix=db_endpoint_prefix)
            network = db.get_network()
            print(network)
            assert (network is not None)
        except Exception as e:
            print(e)
            assert False

    def test_get_identity(self) -> None:
        try:
            db = NodeDBProxy(self._server_address, credentials=None, endpoint_prefix=db_endpoint_prefix)
            db.get_identity(self._owner.identity.id)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            db = NodeDBProxy(self._server_address, credentials=self._owner_credentials,
                             endpoint_prefix=db_endpoint_prefix)
            identity = db.get_identity(self._owner.identity.id)
            print(identity)
            assert (identity is not None)
            assert (identity.id == self._owner.identity.id)
        except Exception as e:
            print(e)
            assert False

    def test_get_identities(self) -> None:
        try:
            db = NodeDBProxy(self._server_address, credentials=None, endpoint_prefix=db_endpoint_prefix)
            db.get_identities()
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            db = NodeDBProxy(self._server_address, credentials=self._owner_credentials,
                             endpoint_prefix=db_endpoint_prefix)
            result = db.get_identities()
            print(result)
            assert (result is not None)
        except Exception as e:
            print(e)
            assert False

    def test_update_identity(self) -> None:
        try:
            db = NodeDBProxy(self._server_address, credentials=None, endpoint_prefix=db_endpoint_prefix)
            db.update_identity(self._owner.identity)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            db = NodeDBProxy(self._server_address, credentials=self._owner_credentials,
                             endpoint_prefix=db_endpoint_prefix)
            result = db.update_identity(self._owner.identity)
            print(result)
            assert (result is not None)
        except Exception as e:
            print(e)
            assert False

    def test_search(self) -> None:
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.search()
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            result = dor.search()
            print(result)
            assert (result is not None)
        except Exception as e:
            print(e)
            assert False

    def test_statistics(self) -> None:
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.statistics()
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            result = dor.statistics()
            print(result)
            assert (result is not None)
        except Exception as e:
            print(e)
            assert False

    def test_add_get_remove_c(self) -> None:
        # create random temp file
        content_path = os.path.join(self._wd_path, 'content')
        generate_random_file(content_path, 1024*1024)

        # ADD
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.add_data_object(content_path, self._owner.identity, False, False, 'data_type', 'data_format')
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            meta = dor.add_data_object(content_path, self._owner.identity, False, False, 'data_type', 'data_format')
            print(meta)
            assert (meta is not None)
        except Exception as e:
            print(e)
            assert False

        # GET META
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.get_meta(meta.obj_id)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            meta = dor.get_meta(meta.obj_id)
            print(meta)
            assert (meta is not None)
        except Exception as e:
            print(e)
            assert False

        # GET CONTENT
        download_path = os.path.join(self._wd_path, 'downloaded')
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.get_content(meta.obj_id, with_authorisation_by=self._owner.keystore, download_path=download_path)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            dor.get_content(meta.obj_id, with_authorisation_by=self._owner.keystore, download_path=download_path)
            assert (os.path.isfile(download_path))
        except Exception as e:
            print(e)
            assert False

        # DELETE
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.delete_data_object(meta.obj_id, with_authorisation_by=self._owner.keystore)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            meta = dor.delete_data_object(meta.obj_id, with_authorisation_by=self._owner.keystore)
            print(meta)
            assert (meta is not None)
        except Exception as e:
            print(e)
            assert False

    def test_add_gpp(self) -> None:
        source = 'https://github.com/cooling-singapore/saas-middleware-sdk'
        commit_id = '310354f'
        proc_path = 'examples/adapters/proc_example'
        proc_config = 'default'

        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.add_gpp_data_object(source, commit_id, proc_path, proc_config, self._owner.identity)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            dor.add_gpp_data_object(source, commit_id, proc_path, proc_config, self._owner.identity)
            assert False
        except SaaSRuntimeException as e:
            assert e.details['status_code'] == 500

    def test_tag_untag_grant_transfer_revoke_access(self) -> None:
        # create random temp file
        content_path = os.path.join(self._wd_path, 'content')
        generate_random_file(content_path, 1024*1024)

        # ADD
        dor = DORProxy(self._server_address, credentials=self._owner_credentials, endpoint_prefix=dor_endpoint_prefix)
        meta = dor.add_data_object(content_path, self._owner.identity, False, False, 'data_type', 'data_format')

        # TAG
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.update_tags(meta.obj_id, authority=self._owner.keystore, tags=[
                DataObject.Tag(key='hello', value='world')
            ])
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            meta = dor.update_tags(meta.obj_id, authority=self._owner.keystore, tags=[
                DataObject.Tag(key='hello', value='world')
            ])
            print(meta)
            assert (meta is not None)
        except Exception as e:
            print(e)
            assert False

        # UNTAG
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.remove_tags(meta.obj_id, authority=self._owner.keystore, keys=['hello'])
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            meta = dor.remove_tags(meta.obj_id, authority=self._owner.keystore, keys=['hello'])
            print(meta)
            assert (meta is not None)
        except Exception as e:
            print(e)
            assert False

        # GRANT
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.grant_access(meta.obj_id, authority=self._owner.keystore, identity=self._user.identity)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            meta = dor.grant_access(meta.obj_id, authority=self._owner.keystore, identity=self._user.identity)
            print(meta)
            assert (meta is not None)
            assert (self._user.identity.id in meta.access)
        except Exception as e:
            print(e)
            assert False

        # REVOKE
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.revoke_access(meta.obj_id, authority=self._owner.keystore, identity=self._user.identity)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            meta = dor.revoke_access(meta.obj_id, authority=self._owner.keystore, identity=self._user.identity)
            assert (meta is not None)
        except Exception as e:
            print(e)
            assert False

        # TRANSFER
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.transfer_ownership(meta.obj_id, authority=self._owner.keystore, new_owner=self._user.identity)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            meta = dor.transfer_ownership(meta.obj_id, authority=self._owner.keystore, new_owner=self._user.identity)
            print(meta)
            assert (meta is not None)
            assert (self._user.identity.id == meta.owner_iid)
        except Exception as e:
            print(e)
            assert False

        dor = DORProxy(self._server_address, credentials=self._user_credentials, endpoint_prefix=dor_endpoint_prefix)
        dor.delete_data_object(meta.obj_id, with_authorisation_by=self._user.keystore)

    def test_deployed(self) -> None:
        try:
            rti = RTIProxy(self._server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
            rti.get_deployed()
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            rti = RTIProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=rti_endpoint_prefix)
            result = rti.get_deployed()
            print(result)
            assert (result is not None)
        except Exception as e:
            print(e)
            assert False

    def test_deploy(self) -> None:
        try:
            rti = RTIProxy(self._server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
            rti.deploy(self._gpp.meta.obj_id, authority=self._owner.keystore)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            rti = RTIProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=rti_endpoint_prefix)
            rti.deploy(self._gpp.meta.obj_id, authority=self._owner.keystore)
            assert False
        except SaaSRuntimeException as e:
            assert e.details['status_code'] == 500

    def test_undeploy(self) -> None:
        try:
            rti = RTIProxy(self._server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
            rti.undeploy(self._gpp.meta.obj_id, authority=self._owner.keystore)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            rti = RTIProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=rti_endpoint_prefix)
            rti.undeploy(self._gpp.meta.obj_id, authority=self._owner.keystore)
            assert False
        except SaaSRuntimeException as e:
            assert e.details['status_code'] == 500

    def test_gpp(self) -> None:
        try:
            rti = RTIProxy(self._server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
            rti.get_gpp(self._gpp.meta.obj_id)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            rti = RTIProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=rti_endpoint_prefix)
            result = rti.get_gpp(self._gpp.meta.obj_id)
            print(result)
            assert (result is not None)
        except Exception as e:
            print(e)
            assert False

    def test_status(self) -> None:
        try:
            rti = RTIProxy(self._server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
            rti.get_status(self._gpp.meta.obj_id)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            rti = RTIProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=rti_endpoint_prefix)
            result = rti.get_status(self._gpp.meta.obj_id)
            print(result)
            assert (result is not None)
        except Exception as e:
            print(e)
            assert False

    def test_submit_status_logs_provenance(self) -> None:
        # connect to Relay -> this publishes a 'proxy identity' for the user (i.e., _owner) which we are
        # going to use in this test case
        connect_to_relay(self._wd_path, self._server_address, (self._owner.login, self._password))

        task_input = [
            Task.InputValue.parse_obj({'name': 'a', 'type': 'value', 'value': {'v': 1}}),
            Task.InputValue.parse_obj({'name': 'b', 'type': 'value', 'value': {'v': 1}})
        ]

        task_output = [
            Task.Output.parse_obj({'name': 'c', 'owner_iid': self._owner.identity.id,
                                   'restricted_access': False, 'content_encrypted': False})
        ]

        # SUBMIT
        try:
            rti = RTIProxy(self._server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
            rti.submit_job(self._proc.descriptor.proc_id, task_input, task_output, self._owner.keystore)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            rti = RTIProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=rti_endpoint_prefix)
            result = rti.submit_job(self._proc.descriptor.proc_id, task_input, task_output, self._owner.keystore)
            print(result)
            assert (result is not None)
            job_id = result.id
        except Exception as e:
            print(e)
            assert False

        # STATUS
        try:
            rti = RTIProxy(self._server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
            rti.get_job_status(job_id, with_authorisation_by=self._owner.keystore)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            rti = RTIProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=rti_endpoint_prefix)
            result = rti.get_job_status(job_id, with_authorisation_by=self._owner.keystore)
            print(result)
            assert (result is not None)
        except Exception as e:
            print(e)
            assert False

        while True:
            # get information about the running job
            status: JobStatus = rti.get_job_status(job_id, with_authorisation_by=self._owner.keystore)
            from pprint import pprint
            pprint(status.dict())
            assert (status is not None)

            if status.state in [JobStatus.State.SUCCESSFUL, JobStatus.State.FAILED]:
                break

            time.sleep(1)

        obj = status.output['c']

        # LOGS
        logs_path = os.path.join(self._wd_path, 'logs')
        try:
            rti = RTIProxy(self._server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
            rti.get_job_logs(job_id, with_authorisation_by=self._owner.keystore, download_path=logs_path)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            rti = RTIProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=rti_endpoint_prefix)
            rti.get_job_logs(job_id, with_authorisation_by=self._owner.keystore, download_path=logs_path)
            assert (os.path.isfile(logs_path))
        except Exception as e:
            print(e)
            assert False

        # PROVENANCE
        try:
            dor = DORProxy(self._server_address, credentials=None, endpoint_prefix=dor_endpoint_prefix)
            dor.get_provenance(obj.c_hash)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            dor = DORProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=dor_endpoint_prefix)
            result = dor.get_provenance(obj.c_hash)
            print(result)
            assert(result is not None)

        except Exception as e:
            print(e)
            assert False

    def test_resume(self) -> None:
        pass

    def test_jobs_by_proc(self) -> None:
        try:
            rti = RTIProxy(self._server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
            rti.get_jobs_by_proc(self._gpp.meta.obj_id)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            rti = RTIProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=rti_endpoint_prefix)
            result = rti.get_jobs_by_proc(self._gpp.meta.obj_id)
            print(result)
            assert (result is not None)
        except Exception as e:
            print(e)
            assert False

    def test_jobs_by_user(self) -> None:
        try:
            rti = RTIProxy(self._server_address, credentials=None, endpoint_prefix=rti_endpoint_prefix)
            rti.get_jobs_by_user(authority=self._owner.keystore)
            assert False
        except UnexpectedHTTPError as e:
            assert e.details['response'].status_code == 401

        try:
            rti = RTIProxy(self._server_address, credentials=self._owner_credentials,
                           endpoint_prefix=rti_endpoint_prefix)
            result = rti.get_jobs_by_user(authority=self._owner.keystore)
            print(result)
            assert (result is not None)
        except Exception as e:
            print(e)
            assert False

    def test_job_cancel(self) -> None:
        pass

    def test_put_permission(self) -> None:
        pass

    def test_sdk(self) -> None:
        context: SDKRelayContext = connect_to_relay(self._wd_path, self._server_address, self._user_credentials)

        proc: SDKProcessor = context.find_processor_by_name(self._proc.name)
        assert(proc is not None)

        for a in range(0, 2):
            for b in range(0, 2):
                output = proc.submit_and_wait({
                    'a': {"v": a},
                    'b': {"v": b}
                })

                obj_c = output['c']
                download_path = os.path.join(self._wd_path, f"c_for_a{a}_b{b}.json")
                obj_c.download(download_path)

                # load the result
                c = read_json_from_file(download_path)
                c = c['v']
                print(f"{a} + {b} = {c}")

        context.close()

    def test_sdk_remote(self) -> None:
        context: SDKRelayContext = connect_to_relay(self._wd_path,
                                                    relay_address=('https', 'api-dev.duct.sg', 443),
                                                    credentials=('foo.bar@somewhere.com', '105PFvIg'))

        result = context.find_processors()
        for proc in result:
            print(proc.name)
            print(proc.descriptor)

        context.close()

    def test_sdk_remote_iemsim(self) -> None:
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
        extracted_bf_path = os.path.join(self._wd_path, 'bf_extracted.geojson')

        # extract the buildings in the area of interest
        extract_buildings(bf_path, area, extracted_bf_path)

        # connect to the Relay
        context: SDKRelayContext = connect_to_relay(self._wd_path,
                                                    relay_address=('https', 'api-dev.duct.sg', 443),
                                                    credentials=('foo.bar@somewhere.com', '105PFvIg'))

        # upload the extracted buildings so the processors can use it
        bf_obj = context.upload_content(extracted_bf_path, 'DUCT.GeoVectorData', 'geojson', access_restricted=False)
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


if __name__ == '__main__':
    unittest.main()
