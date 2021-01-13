import unittest
import logging
import os
import time

from tests.testing_environment import TestingEnvironment
from saas.node import Node
from saas.nodedb.nodedb import DBTable

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)
env = TestingEnvironment.get_instance('/Users/heikoaydt/Desktop/saas_env/testing-config.json')
n_nodes = 5


class NodeDBTestCase(unittest.TestCase):
    def setUp(self):
        env.prepare_working_directory()

        self.nodes = []
        for i in range(0, n_nodes):
            name = f"node_{i}"
            datastore_path = os.path.join(env.wd_path, name)

            logger.info(f"creating node '{name}'")
            node = Node(name, datastore_path, env.rest_api_address)
            node.initialise_identity(env.password)
            node.start_server((env.p2p_server_address[0], env.p2p_server_address[1] + i))
            node.initialise_registry(env.p2p_server_address)
            self.nodes.append(node)

        # give it some time to settle
        time.sleep(5)

    def tearDown(self):
        for node in self.nodes:
            logger.info(f"stopping node '{node.name}'")
            node.stop_server()

    def test_registry(self):
        # nodes have already been created in the setup... here we just see if all nodes know of each other
        for node in self.nodes:
            content = node.registry.get()
            logger.info(f"{node.name} registry content: {content}")
            assert len(content) == len(self.nodes)

            for node2 in self.nodes:
                assert node2.key.iid in content

    def test_node_db(self):
        # create a test table (each node has the same)
        tables = []
        for node in self.nodes:
            table = node.db.create_table('test_table', {
                'row_id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
                'col_a': 'VARCHAR(64) NOT NULL',
                'col_b': 'VARCHAR(64) NOT NULL'
            }, auto_sync=True)
            tables.append(table)

        for table in tables:
            records = table.select()
            logger.info(f"{table.name} records: {records}")
            assert len(records) == 0

        table: DBTable = tables[0]
        table.insert({
            'col_a': 'abc',
            'col_b': 'def'
        })

        for table in tables:
            records = table.select()
            logger.info(f"{table.name} records: {records}")
            assert len(records) == 1
            assert records[0]['col_a'] == 'abc'
            assert records[0]['col_b'] == 'def'

        table: DBTable = tables[1]
        table.update({
            'col_a': 'def'
        }, {
            'col_a': 'abc'
        })

        for table in tables:
            records = table.select()
            logger.info(f"{table.name} records: {records}")
            assert len(records) == 1
            assert records[0]['col_a'] == 'def'
            assert records[0]['col_b'] == 'def'

        table: DBTable = tables[2]
        table.delete({
            'col_a': 'def'
        })

        for table in tables:
            records = table.select()
            logger.info(f"{table.name} records: {records}")
            assert len(records) == 0


if __name__ == '__main__':
    unittest.main()
