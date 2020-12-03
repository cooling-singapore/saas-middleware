import unittest
import logging

from saas.utilities.database_helpers import DBTable

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)
datastore_path = '/Users/heikoaydt/Desktop/saas_env/testing/test_table.db'


class TestTable(DBTable):
    def __init__(self, db_path):
        super().__init__(db_path, "test_table")

        self.create({
            'row_id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
            's': 'VARCHAR(64) NOT NULL',
            'i0': 'UNSIGNED BIG INT NOT NULL',
            'i1': 'UNSIGNED BIG INT'
        })


class DBTableTestCases(unittest.TestCase):
    def setUp(self):
        self.table = TestTable(datastore_path)

    def tearDown(self):
        self.table.drop()

    def test_insert_update_delete(self):
        # delete everything in case there is something in the table
        self.table.delete()
        records = self.table.select(['s', 'i0', 'i1'])
        logger.debug("select:\n{}".format(records))
        assert(len(records) == 0)

        # insert something
        self.table.insert({
            's': 'string0',
            'i0': 0,
            'i1': 1
        })
        records = self.table.select(['s', 'i0', 'i1'])
        logger.debug("select:\n{}".format(records))
        assert(len(records) == 1)
        assert(records[0]['s'] == 'string0')
        assert(records[0]['i0'] == 0)
        assert(records[0]['i1'] == 1)

        # make an update
        self.table.update({
            'i1': 10,
            's': 'string1'
        }, {
            'i0': 0,
            'i1': 1
        })
        records = self.table.select(['s', 'i0', 'i1'])
        logger.debug("select:\n{}".format(records))
        assert(len(records) == 1)
        assert(records[0]['s'] == 'string1')
        assert(records[0]['i0'] == 0)
        assert(records[0]['i1'] == 10)

        # delete everything
        self.table.delete()
        records = self.table.select(['s', 'i0', 'i1'])
        logger.debug("select:\n{}".format(records))
        assert(len(records) == 0)


if __name__ == '__main__':
    unittest.main()
