import time
import unittest

from apps.escrow_demo.server.agent_proxy import AgentProxy
from apps.escrow_demo.server.agent_app import app_rest_address
from tests.base_testcase import TestCaseBase

from apps.escrow_demo.server.agent_app import EscrowAgent


class AgentAppCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        self.create_keystores(1, password='password')
        self._agent = EscrowAgent(self.wd_path, password='password')
        self._agent.start_service(app_rest_address)

    def tearDown(self):
        self._agent.stop_service()

        self.cleanup()

    def test_identity(self):
        sender = self.get_node("sender")
        proxy = AgentProxy(app_rest_address, sender)

        identity = proxy.get_identity()
        assert(identity is not None)

    def test_add_get_transaction(self):
        sender = self.get_node("sender")
        proxy = AgentProxy(app_rest_address, sender)

        # update node with identities
        keystores = self.create_keystores(2)
        provider = keystores[0]
        consumer = keystores[1]

        self._agent.node.db.update_identity(provider.identity.public_as_string(), provider.name(), provider.email(),
                                            provider.nonce(), propagate=False)

        self._agent.node.db.update_identity(consumer.identity.public_as_string(), consumer.name(), consumer.email(),
                                            consumer.nonce(), propagate=False)

        transaction = proxy.add_transaction('name', 'description', provider.identity, consumer.identity, False, False)
        print(transaction)
        assert(transaction['consumer_iid'] == consumer.id())
        assert(transaction['provider_iid'] == provider.id())

        tx_id = transaction['id']
        assert(tx_id == '0')

        details = proxy.get_transaction(tx_id)
        transaction2 = details['transaction']
        print(transaction2)
        assert(transaction2['consumer_iid'] == consumer.id())
        assert(transaction2['provider_iid'] == provider.id())
        assert(transaction2['id'] == tx_id)

        transactions = proxy.get_transactions()
        print(transactions)
        assert(len(transactions) == 1)
        assert(tx_id in transactions)

    def test_deploy_processor(self):
        sender = self.get_node("sender")
        proxy = AgentProxy(app_rest_address, sender)
        identity = sender.identity()

        self._agent.node.db.update_identity(identity.public_as_string(), sender.name(), sender.email(),
                                            sender.nonce(), propagate=False)

        transaction = proxy.add_transaction('name', 'description', identity, identity, False, False)
        print(transaction)
        assert(transaction['consumer_iid'] == identity.iid)
        assert(transaction['provider_iid'] == identity.iid)

        tx_id = transaction['id']
        assert(tx_id == '0')

        source = 'https://github.com/cooling-singapore/saas-processor-template'
        commit_id = '09d00d6'
        path = 'processor_dummy'

        result = proxy.confirm_processor(tx_id, source, commit_id, path)
        print(result)
        assert(result is not None)
        assert('proc_id' in result)
        assert('descriptor' in result)



if __name__ == '__main__':
    unittest.main()
