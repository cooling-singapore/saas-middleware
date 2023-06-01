import tempfile

import pytest

from saas.core.keystore import Keystore
from saas.dor.proxy import DORProxy
from saas.nodedb.proxy import NodeDBProxy
from saas.rti.proxy import RTIProxy
from tests.base_testcase import TestContext, update_keystore_from_credentials


@pytest.fixture()
def test_context():
    context = TestContext()
    context.initialise()
    yield context
    context.cleanup()


@pytest.fixture(scope="session")
def keystore():
    with tempfile.TemporaryDirectory() as tempdir:
        _keystore = Keystore.create(tempdir, "node", "no-email-provided", "password")
        update_keystore_from_credentials(_keystore)
        yield _keystore


@pytest.fixture()
def node(test_context, keystore):
    _node = test_context.get_node(keystore, enable_rest=True, strict_deployment=False)
    return _node


@pytest.fixture()
def dor_proxy(node):
    proxy = DORProxy(node.rest.address())
    return proxy


@pytest.fixture()
def node_db_proxy(node):
    proxy = NodeDBProxy(node.rest.address())
    return proxy


@pytest.fixture()
def rti_proxy(node):
    proxy = RTIProxy(node.rest.address())
    return proxy


@pytest.fixture()
def temp_directory():
    with tempfile.TemporaryDirectory() as tempdir:
        yield tempdir


@pytest.fixture(scope="module")
def extra_keystores():
    keystores = []
    with tempfile.TemporaryDirectory() as tempdir:
        for i in range(3):
            keystore = Keystore.create(tempdir, f"keystore-{i}", "no-email-provided", "password")
            keystores.append(keystore)
        yield keystores
