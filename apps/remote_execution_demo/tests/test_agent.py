import traceback
import unittest
import os

from apps.remote_execution_demo.server.agent_proxy import ExecutionAgentProxy
from tests.base_testcase import TestCaseBase

from apps.remote_execution_demo.server.agent import ExecutionAgent

app_rest_address = ('127.0.0.1', 5000)
node_rest_address = ('127.0.0.1', 5001)
node_p2p_address = ('127.0.0.1', 4001)


class AgentAppCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        keystores = self.create_keystores(1, password='password')
        self._agent = ExecutionAgent(self.wd_path, keystores[0], app_rest_address, node_rest_address, node_p2p_address)
        self._agent.start_service()

    def tearDown(self):
        self._agent.stop_service()

        self.cleanup()

    def test_identity(self):
        sender = self.get_node("sender")
        proxy = ExecutionAgentProxy(app_rest_address, sender)

        identity = proxy.get_identity()
        assert(identity is not None)

    def test_add_get_transaction(self):
        sender = self.get_node("sender")
        proxy = ExecutionAgentProxy(app_rest_address, sender)

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
        proxy = ExecutionAgentProxy(app_rest_address, sender)
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
        # commit_id = '09d00d6'
        # path = 'processor_dummy'
        commit_id = '0d40f2b'
        path = 'processor_20210602-demo'

        result = proxy.confirm_processor(tx_id, source, commit_id, path)
        print(result)
        assert(result is not None)
        assert('proc_id' in result)
        assert('descriptor' in result)


    def test_function(self):
        wd = os.path.join(os.environ['HOME'], 'Desktop')
        function(wd)

        out_path = os.path.join(wd, 'aggregated')
        assert(os.path.isfile(out_path))


def function(working_directory):
    status_path = os.path.join(working_directory, 'status.log')
    with open(status_path, 'w') as status:
        try:
            in_path = os.path.join(working_directory, 'confidential')
            with open(in_path, 'r') as f:
                # read the header
                header = f.readline()
                status.write(f"{header}\n")

                result = []
                for t in range(24):
                    line = f.readline()
                    print(line)

                    line = line.split(',')
                    s = 0
                    for i in range(1, len(line)):
                        s += float(line[i])

                    result.append(s)

            status.write(f"{result}\n")

            out_path = os.path.join(working_directory, 'aggregated')
            status.write(f"out_path={out_path}\n")
            with open(out_path, 'w') as f:
                f.write("Time,Aggregated\n")

                for t in range(24):
                    f.write(f"{t},{result[t]}\n")

            status.write(f"done\n")

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            status.write(trace)


if __name__ == '__main__':
    unittest.main()
