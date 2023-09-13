import json
import os
import shutil
import unittest

from saas.core.exceptions import SaaSRuntimeException
from saas.core.keystore import Keystore
from saas.dor.schemas import DataObject
from saas.sdk.base import connect, SDKGPPDataObject
from saas.sdk.helper import create_wd, generate_random_file


class SDKBaseTestCase(unittest.TestCase):
    _node_address = ('127.0.0.1', 5001)
    _wd_path: str = None
    _keystore = None
    _known_user = None

    @classmethod
    def setUpClass(cls):
        cls._wd_path = create_wd()
        cls._keystore = Keystore.create(cls._wd_path, 'Foo Bar', 'foo.bar@somewhere.com', 'password')
        cls._known_user = Keystore.create(cls._wd_path, 'John Doe', 'john.doe@somewhere.com', 'password')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._wd_path)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_context(self):
        # try wrong address
        try:
            connect(('127.0.0.1', 9999), self._keystore)
            assert False

        except SaaSRuntimeException as e:
            assert("Cannot establish connection" in e.reason)

        context = connect(self._node_address, self._keystore)
        assert(context is not None)

    def test_upload_gpp_delete(self):
        context = connect(self._node_address, self._keystore)

        # upload test processor
        source = 'https://github.com/cooling-singapore/saas-processor-template'
        commit_id = '7a87928'
        proc_path = 'processor_test'
        proc_config = 'default'
        obj = context.upload_gpp(source, commit_id, proc_path, proc_config)

        # search for it (wrong id)
        result = context.find_data_object('lpjsjlkdfgjli')
        assert(result is None)

        # search for it (correct id)
        result = context.find_data_object(obj.meta.obj_id)
        assert(result is not None)
        assert(isinstance(result, SDKGPPDataObject))

        # delete the object
        obj.delete()

        # search for it (correct id)
        result = context.find_data_object(obj.meta.obj_id)
        assert(result is None)

    def test_upload_content_access_tags_ownership_delete(self):
        context = connect(self._node_address, self._keystore)

        # generate file with random content
        content_path = os.path.join(self._wd_path, 'content.dat')
        generate_random_file(content_path, 1024*1024)

        # upload
        obj = context.upload_content(content_path, 'Bytes', 'dat', True)
        assert('k' not in obj.meta.tags)

        # tag
        obj.update_tags([DataObject.Tag(key='k', value='value')])
        assert('k' in obj.meta.tags)
        assert(obj.meta.tags['k'] == 'value')

        # untag
        obj.remove_tags(['k'])
        assert('k' not in obj.meta.tags)

        # download content (should not work)
        context2 = connect(self._node_address, self._known_user)
        obj2 = context2.find_data_object(obj.meta.obj_id)
        try:
            obj2.download(self._wd_path)
            assert False

        except SaaSRuntimeException:
            assert True

        # grant access
        assert(self._known_user.identity.id not in obj.meta.access)
        obj.grant_access(self._known_user.identity)
        assert(self._known_user.identity.id in obj.meta.access)

        # download content (should work)
        context2 = connect(self._node_address, self._known_user)
        obj2 = context2.find_data_object(obj.meta.obj_id)
        try:
            obj2.download(self._wd_path)

        except SaaSRuntimeException:
            assert False

        # revoke access
        obj.revoke_access(self._known_user.identity)
        assert(self._known_user.identity.id not in obj.meta.access)

        # transfer ownership
        obj.transfer_ownership(self._known_user.identity)

        # delete the object (shouldn't work)
        try:
            obj.delete()
            assert False

        except SaaSRuntimeException:
            assert True

        # delete the object (should work)
        try:
            obj2.delete()

        except SaaSRuntimeException:
            assert False

    def test_deploy_execute_provenance(self):
        context = connect(self._node_address, self._keystore)

        # upload test GPP
        source = 'https://github.com/cooling-singapore/saas-middleware-sdk'
        commit_id = '310354f'
        proc_path = 'examples/adapters/proc_example'
        proc_config = 'default'
        obj = context.upload_gpp(source, commit_id, proc_path, proc_config)

        # get an RTI
        rti = context.rti()
        assert(rti is not None)

        # deploy the processor
        proc = obj.deploy(rti)

        # find the processor
        proc = context.find_processor_by_id(proc.descriptor.proc_id)
        assert(proc is not None)

        # find all processors
        procs = context.find_processors()
        for p in procs:
            print(p.descriptor)
        assert(procs is not None)
        assert(len(procs) > 0)

        # get proc status
        status = proc.status()
        print(status)

        # execute a job
        output = proc.submit_and_wait({
            'a': {'v': 1},
            'b': {'v': 2}
        })
        assert('c' in output)

        # download 'c'
        c = output['c']
        download_path = os.path.join(self._wd_path, 'c')
        c.download(download_path)
        assert(os.path.isfile(download_path))

        # analyse file content
        with open(download_path, 'r') as f:
            content = json.load(f)
            assert('v' in content)

        # clean up
        proc.undeploy()
        c.delete()
        obj.delete()


if __name__ == '__main__':
    unittest.main()
