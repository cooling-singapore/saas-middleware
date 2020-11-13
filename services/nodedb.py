"""
NodeDB is a convenience wrapper for the data object records db.
"""

import os
import sqlite3
import logging
import utilities

from eckeypair import ECKeyPair

logger = logging.getLogger('NodeDB')


class NodeDB:
    def __init__(self, datastore_path):
        # initialise properties
        self.db_path = os.path.join(datastore_path, 'records.db')
        logger.info("using database path '{}'.".format(self.db_path))

        # initialise records database (if needed)
        db = sqlite3.connect(self.db_path)

        db.execute(
            "CREATE TABLE IF NOT EXISTS dor_records ("
            "   id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "   h_hash VARCHAR(64) NOT NULL,"
            "   c_hash VARCHAR(64) NOT NULL,"
            "   obj_id VARCHAR(64) NOT NULL,"
            "   owner_iid VARCHAR(64) NOT NULL,"
            "   custodian_iid VARCHAR(64) NOT NULL,"
            "   last_access UNSIGNED BIG INT NOT NULL,"
            "   expiration UNSIGNED BIG INT"
            ")"
        )

        db.execute(
            "CREATE TABLE IF NOT EXISTS dor_permissions ("
            "   id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "   record_id INTEGER NOT NULL,"
            "   user_iid VARCHAR(64) NOT NULL,"
            "   FOREIGN KEY (record_id) REFERENCES records (id)"
            ")"
        )

        db.execute(
            "CREATE TABLE IF NOT EXISTS dor_tags ("
            "   id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "   record_id INTEGER NOT NULL,"
            "   key TEXT NOT NULL,"
            "   value TEXT,"
            "   FOREIGN KEY (record_id) REFERENCES records (id)"
            ")"
        )

        db.execute(
            "CREATE TABLE IF NOT EXISTS public_keys ("
            "   iid VARCHAR(64) PRIMARY KEY,"
            "   public_key TEXT NOT NULL,"
            "   UNIQUE(iid, public_key)"
            ")"
        )

        sql_result = db.execute("SELECT COUNT(*) FROM dor_records").fetchone()
        logger.info("number of data object records in database: {}".format(sql_result[0]))

        db.close()

    def get_number_of_records(self):
        db = sqlite3.connect(self.db_path)

        sql_result = db.execute("SELECT COUNT(*) FROM dor_records").fetchone()
        result = int(sql_result[0])

        db.close()
        return result

    def get_distinct_tag_keys(self):
        db = sqlite3.connect(self.db_path)

        result = []
        for key in db.execute("SELECT DISTINCT key FROM dor_tags ORDER BY key ASC"):
            result.append(key)

        db.close()
        return result

    def get_all_objects_with_tag_keys(self, keys):
        db = sqlite3.connect(self.db_path)

        sql_result = db.execute(
            "SELECT DISTINCT r.data_object_id, r.id "
            "FROM dor_records AS r "
            "   INNER JOIN dor_tags AS t ON r.id = t.record_id "
            "   WHERE t.key IN ({})".format(keys)
        )

        result = []
        for record in sql_result:
            result.append((record[0], record[1]))

        db.close()
        return result

    def get_data_objects(self, condition):
        result = []
        db = sqlite3.connect(self.db_path)

        for record in db.execute(
            "SELECT id, h_hash, c_hash, obj_id, owner_iid, custodian_iid, last_access, expiration "
            "FROM dor_records WHERE ({})".format(condition)
        ):
            result.append({
                'record_id': int(record[0]),
                'h_hash': str(record[1]),
                'c_hash': str(record[2]),
                'obj_id': str(record[3]),
                'owner_iid': str(record[4]),
                'custodian_iid': str(record[5]),
                'last_access': int(record[6]),
                'expiration': None if record[7] is None else int(record[7])
            })

        db.close()
        return result

    def get_data_object_by_id(self, obj_id):
        # get the data objects that match the object id (there should be at most one)
        result = self.get_data_objects("obj_id = '{}'".format(obj_id))
        return None if not result else result[0]

    def get_data_objects_by_content_hash(self, c_hash):
        # get the data objects that match the content hash
        return self.get_data_objects("c_hash == '{}'".format(c_hash))

    def get_public_key(self, iid):
        db = sqlite3.connect(self.db_path)
        record = db.execute("SELECT public_key WHERE iid = '{}".format(iid)).fetchone()
        db.close()
        return ECKeyPair.from_public_key_string(record[0]) if record else None

    def insert_data_object_record(self, h_hash, c_hash, obj_id, owner, custodian, expiration=None):
        # determine timestamp and prepare expiration
        last_access = utilities.get_timestamp_now()
        expiration = 'NULL' if expiration is None else expiration

        db = sqlite3.connect(self.db_path)
        db.execute(
            "INSERT OR IGNORE INTO public_keys (iid, public_key) "
            "VALUES ('{}', '{}')".format(owner.iid, owner.public_as_string(truncate=True))
        )
        db.execute(
            "INSERT INTO dor_records (h_hash, c_hash, obj_id, owner_iid, custodian_iid, last_access, expiration) "
            "VALUES ('{}', '{}', '{}', '{}', '{}', {}, {})".format(h_hash, c_hash, obj_id, owner.iid, custodian.iid, last_access, expiration)
        )
        db.commit()
        db.close()

    def delete_data_object_record(self, obj_id):
        record = self.get_data_object_by_id(obj_id)
        if record:
            db = sqlite3.connect(self.db_path)

            # delete permissions and tags for this records first, then the record itself
            db.execute("DELETE FROM dor_permissions WHERE record_id = {}".format(record['record_id']))
            db.execute("DELETE FROM dor_tags WHERE record_id = {}".format(record['record_id']))
            db.execute("DELETE FROM dor_records WHERE id = {}".format(record['record_id']))

            db.commit()
            db.close()

        return record

    def get_access_permissions(self, obj_id):
        db = sqlite3.connect(self.db_path)

        result = []
        for record in db.execute(
            "SELECT p.user_iid "
            "   FROM dor_permissions AS p "
            "   INNER JOIN dor_records AS r ON r.id = p.record_id "
            "   WHERE r.obj_id = '{}'".format(obj_id)
        ):
            result.append(record[0])

        db.close()
        return result


    def show_all_records(self):
        # TODO: remove if not needed anymore

        db = sqlite3.connect(self.db_path)
        for record in db.execute("SELECT * FROM dor_records"):
            logger.info("record: {}".format(record))
        db.close()

