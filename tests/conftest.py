import tempfile

import pytest

from saas.core.keystore import Keystore
from saas.dor.proxy import DORProxy
from saas.node import Node
from saas.nodedb.proxy import NodeDBProxy
from saas.rti.proxy import RTIProxy
from tests.base_testcase import TestContext, update_keystore_from_credentials, PortMaster


COMMIT_ID = "ccd0a3281c9590b760c0800bfa999bd693c7345c"

@pytest.fixture()
def test_context():
    context = TestContext()
    context.initialise()
    yield context
    context.cleanup()


@pytest.fixture(scope="module")
def keystore():
    with tempfile.TemporaryDirectory() as tempdir:
        _keystore = Keystore.create(tempdir, "keystore1", "no-email-provided", "password")
        update_keystore_from_credentials(_keystore)
        yield _keystore


@pytest.fixture(scope="module")
def another_keystore():
    with tempfile.TemporaryDirectory() as tempdir:
        _keystore = Keystore.create(tempdir, "keystore2", "no-email-provided", "password")
        update_keystore_from_credentials(_keystore)
        yield _keystore


@pytest.fixture(scope="module")
def temp_directory():
    with tempfile.TemporaryDirectory() as tempdir:
        yield tempdir


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


@pytest.fixture(scope="module")
def extra_keystores():
    keystores = []
    with tempfile.TemporaryDirectory() as tempdir:
        for i in range(3):
            keystore = Keystore.create(tempdir, f"keystore-{i}", "no-email-provided", "password")
            keystores.append(keystore)
        yield keystores


@pytest.fixture(scope="module")
def node(keystore):
    with tempfile.TemporaryDirectory() as tempdir:
        rest_address = PortMaster.generate_rest_address()
        p2p_address = PortMaster.generate_p2p_address()

        _node = Node.create(keystore=keystore, storage_path=tempdir,
                            p2p_address=p2p_address, boot_node_address=p2p_address, rest_address=rest_address,
                            enable_dor=True, enable_rti=True, strict_deployment=False, job_concurrency=True,
                            retain_job_history=True)

        yield _node

        _node.shutdown()
