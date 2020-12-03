import unittest
import logging

from saas.registry.registry import Registry

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class RegistryTestCases(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_update(self):
        registry = Registry()

        # empty registry: adding a new records should be successful
        assert registry.update('123', 'name1', ('127.0.0.1', 5000), ['a', 'b'], 100)
        assert registry.update('234', 'name2', ('127.0.0.1', 5000), ['a', 'b'], 100)

        # there should be two records in the registry now
        assert registry.size() == 2

        # records already exists and timestamps are NOT more recent: updates should fail
        assert not registry.update('123', 'name1', ('127.0.0.1', 5000), ['a', 'b'], 100)
        assert not registry.update('123', 'name1', ('127.0.0.1', 5000), ['a', 'b'], 99)

        # records already exists and timestamps are more recent: update should succeed
        assert registry.update('123', 'name1', ('127.0.0.1', 5000), ['a', 'b', 'c'], 101)

        # the information of record '123' should be updated now
        record = registry.get('123')
        assert record
        assert all(item in record['processors'] for item in ['a', 'b', 'c'])

    def test_update_all(self):
        registry = Registry()

        records_a = {
            '123': {
                'name': 'node1',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 100
            },
            '234': {
                'name': 'node2',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 99
            }
        }

        records_b = {
            '123': {
                'name': 'node1',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 99
            },
            '234': {
                'name': 'node2',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 98
            }
        }

        # empty registry: adding a new records should be successful for al items
        assert len(registry.update_all(records_a)) == 2

        # adding records that are LESS RECENT should fail
        assert len(registry.update_all(records_b)) == 0

    def test_touch(self):
        registry = Registry()

        # empty registry: adding a new records should be successful
        assert registry.update('123', ('127.0.0.1', 5000), ['a', 'b'], 100)

        # touching an existing record should yield a timestamp
        t0 = registry.touch('123')
        assert t0 is not None

        # the last_seen timestamp on record should match t0
        record = registry.get('123')
        assert t0 == record['last_seen']

        # touching a non-existing record should yield None
        t1 = registry.touch('234')
        assert t1 is None

    def test_remove(self):
        registry = Registry()

        records_a = {
            '123': {
                'name': 'node1',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 100
            },
            '234': {
                'name': 'node2',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 99
            }
        }

        # empty registry: adding a new records should be successful for al items
        assert len(registry.update_all(records_a)) == 2

        # size of registry should be 2
        assert registry.size() == 2

        # remove a record that doesn't exist: the size should be 2
        removed = registry.remove(['222'])
        assert len(removed) == 0
        assert registry.size() == 2

        # remove a record that does exist: the size should be 1
        removed = registry.remove(['123'])
        assert len(removed) == 1
        assert '123' in removed
        assert registry.size() == 1


if __name__ == '__main__':
    unittest.main()
