"""
This module contains the code for the Data Object Repository component needed by a SaaS node.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import sqlite3
import logging

from saas.eckeypair import ECKeyPair
from saas.utilities.database_helpers import DBTable
from saas.utilities.general_helpers import get_timestamp_now

logger = logging.getLogger('DOR.Records')


class DORRecordsTable(DBTable):
    """
    Convenient wrapper class for the 'dor_records' database table.
    """
    def __init__(self, db_path):
        super().__init__(db_path, "dor_records")

        self.create({
            'row_id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
            'h_hash': 'VARCHAR(64) NOT NULL',
            'c_hash': 'VARCHAR(64) NOT NULL',
            'obj_id': 'VARCHAR(64) NOT NULL',
            'owner_iid': 'VARCHAR(64) NOT NULL',
            'custodian_iid': 'VARCHAR(64) NOT NULL',
            'last_access': 'UNSIGNED BIG INT NOT NULL',
            'expiration': 'UNSIGNED BIG INT'
        })

    def add_data_object(self, h_hash, c_hash, obj_id, owner, custodian, expiration=None):
        """
        Adds a data object record to the table.
        :param h_hash: header hash
        :param c_hash: content hash
        :param obj_id: object id
        :param owner: the identity (ECKeyPair) of the data object owner
        :param custodian: the identity (ECKeyPair) of the data object custodian
        :param expiration: (optional) the timestamp after which the data object is expired
        :return: None
        """
        # determine timestamp and prepare expiration
        last_access = get_timestamp_now()
        expiration = 'NULL' if expiration is None else expiration

        self.insert({
            'h_hash': h_hash,
            'c_hash': c_hash,
            'obj_id': obj_id,
            'owner_iid': owner.iid,
            'custodian_iid': custodian.iid,
            'last_access': last_access,
            'expiration': expiration
        })
        # db.execute(
        #     "INSERT OR IGNORE INTO public_keys (iid, public_key) "
        #     "VALUES ('{}', '{}')".format(owner.iid, owner.public_as_string(truncate=True))
        # )

    def get_owner(self, obj_id):
        """
        Returns the owner identity associated with a given object id.
        :param obj_id: the object id
        :return: ECKeyPair or None in case no object with the given id can be found
        """
        records = self.select([
            "owner_iid"
        ], {
            'obj_id': obj_id
        })

        return str(records[0]['owner_iid']) if records else None

    def update_ownership(self, obj_id, new_owner):
        """
        Update the ownership information of a given data object to a new owner.
        :param obj_id: the object id
        :param new_owner: the identity of the new owner
        :return: None
        """
        self.update({
            'owner_iid': new_owner.iid
        }, {
            'obj_id': obj_id
        })


class DORTagsTable(DBTable):
    """
    Convenient wrapper class for the 'dor_tags' database table.
    """
    def __init__(self, db_path):
        super().__init__(db_path, "dor_tags")

        self.create({
            'row_id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
            'record_id': 'INTEGER NOT NULL',
            'key': 'TEXT NOT NULL',
            'value': 'TEXT'
        })

    def get_distinct_tag_keys(self):
        """
        Returns the distinct tags found in the table.
        :return: list of distinct tags
        """
        return self.select([
            'key'
        ], use_distinct=True)


class DORPermissionsTable(DBTable):
    """
    Convenient wrapper class for the 'dor_permissions' database table.
    """
    def __init__(self, db_path):
        super().__init__(db_path, "dor_permissions")

        self.create({
            'row_id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
            'obj_id': 'VARCHAR(64) NOT NULL',
            'user_iid': 'VARCHAR(64) NOT NULL'
        }, unique=['obj_id', 'user_iid'])

    def grant_access(self, obj_id, user):
        """
        Grant a user access to a data object.
        :param obj_id: the id of the data object
        :param user: the identity of the user
        :return: None
        """
        self.insert({
            'obj_id': obj_id,
            'user_iid': user.iid
        }, or_ignore=True)

    def revoke_access(self, obj_id, user):
        """
        Revoke the access of a user to a data object.
        :param obj_id: the id of the data object
        :param user: the identity of the user
        :return: None
        """
        self.delete({
            'obj_id': obj_id,
            'user_iid': user.iid
        })

    def get_access_permissions(self, obj_id):
        """
        Returns a list of user iids that have access to a data object.
        :param obj_id: the id of the data object
        :return: a list of user iids
        """
        return self.select(
            [
                'user_iid'
            ],
            {
                'obj_id': obj_id
            }
        )

    def has_access(self, obj_id, user):
        """
        Returns True or False depending on whether or not a user has access to a data object
        :param obj_id: the id of the data object
        :param user: the identity of the user
        :return: True or False
        """
        records = self.select(
            [
                'row_id'
            ],
            {
                'obj_id': obj_id,
                'user_iid': user.iid
            }
        )
        return True if records else False


class DORPublicKeysTable(DBTable):
    """
    Convenient wrapper class for the 'dor_public_keys' database table.
    """
    def __init__(self, db_path):
        super().__init__(db_path, "dor_public_keys")

        self.create({
            'row_id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
            'iid': 'VARCHAR(64) NOT NULL',
            'public_key': 'TEXT NOT NULL',
        }, unique=['iid', 'public_key'])

    def put(self, key: ECKeyPair):
        """
        Puts a public key and its iid into the table.
        :param key: the identity from which to take the public key and corresponding iid
        :return: None
        """
        self.insert({
            'iid': key.iid,
            'public_key': key.public_as_string()
        }, or_ignore=True)

    def pop(self, iid):
        """
        Removes a public key and its iid from the table.
        :param iid: the iid of the entry that is to be removed.
        :return: None
        """
        self.delete({
            "iid": iid
        })

    def get_public_key(self, iid):
        """
        Returns the public key for a given iid.
        :param iid: the iid of interest
        :return: public key that matches the iid or None in case it cannot be found in the database
        """
        result = self.select(['public_key'], {
            'iid': iid
        })
        return ECKeyPair.from_public_key_string(result[0]['public_key']) if result else None


class DataObjectRepository:
    """
    DataObjectRepository is a facade that provides methods required for the Data Object Repository. Each of these
    methods typically performs operations on one or more database tables.
    """
    def __init__(self, db_path):
        # initialise properties
        self.db_path = db_path
        logger.info("using database path '{}'.".format(self.db_path))

        # initialise the database table wrappers
        self.records = DORRecordsTable(self.db_path)
        self.tags = DORTagsTable(self.db_path)
        self.permissions = DORPermissionsTable(self.db_path)
        self.public_keys = DORPublicKeysTable(self.db_path)

        # fyi: how many records do we have?
        n = self.records.get_number_of_rows()
        logger.info("number of data object records in database: {}".format(n))

    def get_number_of_records(self):
        return self.records.get_number_of_rows()

    def get_distinct_tag_keys(self):
        return self.tags.get_distinct_tag_keys()

    def get_objects_with_tag_keys(self, keys):
        db = sqlite3.connect(self.db_path)

        sql_result = db.execute(
            "SELECT DISTINCT r.data_object_id, r.id "
            "FROM {} AS r "
            "   INNER JOIN {} AS t ON r.id = t.record_id "
            "   WHERE t.key IN ({})".format(self.records.name, self.tags.name, keys)
        )

        result = []
        for record in sql_result:
            result.append((record[0], record[1]))

        db.close()
        return result

    def get_data_object_by_id(self, obj_id):
        result = self.records.select(where_parameters={
            'obj_id': obj_id
        })
        return result[0] if result else None

    def get_data_objects_by_content_hash(self, c_hash):
        return self.records.select(where_parameters={
            'c_hash': c_hash
        })

    def add_data_object(self, h_hash, c_hash, obj_id, owner, custodian, expiration=None):
        self.public_keys.put(owner)
        self.records.add_data_object(h_hash, c_hash, obj_id, owner, custodian, expiration)
        self.grant_access(obj_id, owner)

    def delete_data_object(self, obj_id):
        records = self.records.select(where_parameters={
            'obj_id': obj_id
        })
        logger.info("records={}".format(records))

        if records:
            record = records[0]
            record_id = str(record['row_id'])

            # delete permissions and tags for this records first, then the record itself
            self.permissions.delete({'obj_id': obj_id})
            self.tags.delete({'record_id': record_id})
            self.records.delete({'row_id': record_id})

            return record

        else:
            return None

    def get_owner_for_object(self, obj_id):
        owner_iid = self.records.get_owner(obj_id)
        return self.public_keys.get_public_key(owner_iid) if owner_iid else None

    def update_ownership(self, obj_id, new_owner):
        self.public_keys.put(new_owner)
        self.records.update_ownership(obj_id, new_owner)

    def grant_access(self, obj_id, user):
        self.public_keys.put(user)
        self.permissions.grant_access(obj_id, user)

    def revoke_access(self, obj_id, user):
        self.permissions.revoke_access(obj_id, user)

    def get_access_permissions(self, obj_id):
        return self.permissions.get_access_permissions(obj_id)

    def has_access(self, obj_id, user):
        return self.permissions.has_access(obj_id, user)
