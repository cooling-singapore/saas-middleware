"""
This module contains the code for the Data Object Repository component needed by a SaaS node.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import os
import logging
import subprocess
import json

from cryptography.hazmat.primitives import hashes

from saas.eckeypair import ECKeyPair, hash_json_object, hash_file_content
from saas.utilities.general_helpers import get_timestamp_now, dump_json_to_file, create_symbolic_link
from saas.dor.protocol import DataObjectRepositoryP2PProtocol

logger = logging.getLogger('DOR.Records')


class DORRecordsTable:
    """
    Convenient wrapper class for the 'dor_records' database table.
    """

    def __init__(self, node_db):
        self.table = node_db.create_table('dor_records', {
            'row_id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
            'd_hash': 'VARCHAR(64) NOT NULL',
            'c_hash': 'VARCHAR(64) NOT NULL',
            'obj_id': 'VARCHAR(64) NOT NULL',
            'owner_iid': 'VARCHAR(64) NOT NULL',
            'custodian_iid': 'VARCHAR(64) NOT NULL',
            'last_access': 'UNSIGNED BIG INT NOT NULL',
            'expiration': 'UNSIGNED BIG INT'
        })

    def add(self, d_hash, c_hash, obj_id, owner, custodian, expiration=None):
        """
        Adds a data object record to the table.
        :param d_hash: descriptor hash
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

        self.table.insert({
            'd_hash': d_hash,
            'c_hash': c_hash,
            'obj_id': obj_id,
            'owner_iid': owner.iid,
            'custodian_iid': custodian.iid,
            'last_access': last_access,
            'expiration': expiration
        })

    def get_by_object_id(self, obj_id):
        """
        Returns the data object record with a given object id.
        :param obj_id: the object id
        :return:
        """
        result = self.table.select(where_parameters={
            'obj_id': obj_id
        })
        return result[0] if result else None

    def get_by_content_hash(self, c_hash):
        return self.table.select(where_parameters={
            'c_hash': c_hash
        })

    def delete(self, obj_id):
        self.table.delete({
            'obj_id': obj_id
        })

    def update_ownership(self, obj_id, new_owner):
        """
        Update the ownership information of a given data object to a new owner.
        :param obj_id: the object id
        :param new_owner: the identity of the new owner
        :return: None
        """
        self.table.update({
            'owner_iid': new_owner.iid
        }, {
            'obj_id': obj_id
        })

    def get_number_of_rows(self):
        return self.table.get_number_of_rows()


class DORTagsTable:
    """
    Convenient wrapper class for the 'dor_tags' database table.
    """

    def __init__(self, node_db):
        self.table = node_db.create_table('dor_tags', {
            'row_id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
            'obj_id': 'INTEGER NOT NULL',
            'key': 'TEXT NOT NULL',
            'value': 'TEXT'
        })

    def search(self, key_vriterion, value_criterion):
        where_parameters = {
            'key': key_vriterion
        }
        if value_criterion:
            where_parameters['value'] = value_criterion

        sql_result = self.table.select(['obj_id'], where_parameters)

        result = []
        for kv in sql_result:
            result.append(kv['obj_id'])

        return result

    def get_by_object_id(self, obj_id):
        """
        Returns the tags for a data object with a given object id.
        :param obj_id: the object id
        :return:
        """
        tags = self.table.select(
            ['key', 'value'],
            where_parameters={
                'obj_id': obj_id
            }
        )

        result = {}
        for tag in tags:
            result[tag['key']] = tag['value']

        return result

    def update(self, obj_id, tags):
        for tag in tags:
            key = tag['key']
            value = tag['value']

            # is the key already in the table? then update
            where_parameters = {'obj_id': obj_id, 'key': key}
            if self.table.has(where_parameters):
                self.table.update({
                    'value': value
                }, where_parameters)

            # otherwise insert
            else:
                self.table.insert({
                    'obj_id': obj_id,
                    'key': key,
                    'value': value
                })

    def remove(self, obj_id, tags):
        for tag in tags:
            self.table.delete({
                'obj_id': obj_id,
                'key': tag
            })

    def remove_all(self, obj_id):
        self.table.delete({
            'obj_id': obj_id
        })

    def get_distinct_tag_keys(self):
        """
        Returns the distinct tags found in the table.
        :return: list of distinct tags
        """
        return self.table.select([
            'key'
        ], use_distinct=True)


class DORPermissionsTable:
    """
    Convenient wrapper class for the 'dor_permissions' database table.
    """

    def __init__(self, node_db):
        self.table = node_db.create_table('dor_permissions', {
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
        self.table.insert({
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
        self.table.delete({
            'obj_id': obj_id,
            'user_iid': user.iid
        })

    def revoke_all(self, obj_id):
        """
        Revoke the access for all users to a data object.
        :param obj_id: the id of the data object
        :return: None
        """
        self.table.delete({
            'obj_id': obj_id
        })

    def get_access_permissions(self, obj_id):
        """
        Returns a list of user iids that have access to a data object.
        :param obj_id: the id of the data object
        :return: a list of user iids
        """
        result = []
        for item in self.table.select(
                [
                    'user_iid'
                ],
                {
                    'obj_id': obj_id
                }
        ):
            result.append(item['user_iid'])

        return result

    def has_access(self, obj_id, user):
        """
        Returns True or False depending on whether or not a user has access to a data object
        :param obj_id: the id of the data object
        :param user: the identity of the user
        :return: True or False
        """
        records = self.table.select(
            [
                'row_id'
            ],
            {
                'obj_id': obj_id,
                'user_iid': user.iid
            }
        )
        return True if records else False


class DORPublicKeysTable:
    """
    Convenient wrapper class for the 'dor_public_keys' database table.
    """

    def __init__(self, node_db):
        self.table = node_db.create_table('dor_public_keys', {
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
        self.table.insert({
            'iid': key.iid,
            'public_key': key.public_as_string()
        }, or_ignore=True)

    def pop(self, iid):
        """
        Removes a public key and its iid from the table.
        :param iid: the iid of the entry that is to be removed.
        :return: None
        """
        self.table.delete({
            "iid": iid
        })

    def get_public_key(self, iid):
        """
        Returns the public key for a given iid.
        :param iid: the iid of interest
        :return: public key that matches the iid or None in case it cannot be found in the database
        """
        result = self.table.select(['public_key'], {
            'iid': iid
        })
        return ECKeyPair.from_public_key_string(result[0]['public_key']) if result else None


class DataObjectRepository:
    infix_master_path = 'dor-master'
    infix_cache_path = 'dor-cache'

    def obj_content_path(self, c_hash, cache=False):
        if cache:
            return os.path.join(self.node.datastore_path, DataObjectRepository.infix_cache_path, f"{c_hash}.content")
        else:
            return os.path.join(self.node.datastore_path, DataObjectRepository.infix_master_path, f"{c_hash}.content")

    def obj_descriptor_path(self, obj_id, cache=False):
        if cache:
            return os.path.join(self.node.datastore_path, DataObjectRepository.infix_cache_path, f"{obj_id}.descriptor")
        else:
            return os.path.join(self.node.datastore_path, DataObjectRepository.infix_master_path, f"{obj_id}.descriptor")

    """
    DataObjectRepository is a facade that provides methods required for the Data Object Repository. Each of these
    methods typically performs operations on one or more database tables.
    """

    def __init__(self, node):
        # initialise properties
        self.node = node

        # initialise directories
        subprocess.check_output(['mkdir', '-p', os.path.join(self.node.datastore_path,
                                                             DataObjectRepository.infix_master_path)])
        subprocess.check_output(['mkdir', '-p', os.path.join(self.node.datastore_path,
                                                             DataObjectRepository.infix_cache_path)])

        # initialise the database table wrappers
        self.records = DORRecordsTable(node.db)
        self.tags = DORTagsTable(node.db)
        self.permissions = DORPermissionsTable(node.db)
        self.public_keys = DORPublicKeysTable(node.db)

        # fyi: how many records do we have?
        n = self.records.get_number_of_rows()
        logger.info(f"number of data object records in database: {n}")

    def add(self, owner_public_key, descriptor, content_path, expiration=None):
        # recreate ECKeyPair (public key only) of the data object owner
        owner = ECKeyPair.from_public_key_string(owner_public_key)

        # calculate hashes for the data object descriptor and content
        d_hash = hash_json_object(descriptor)
        c_hash = hash_file_content(content_path)

        # calculate the data object id as a hash of the hashed data object header and content
        digest = hashes.Hash(hashes.SHA256())
        digest.update(d_hash)
        digest.update(c_hash)
        obj_id = digest.finalize()

        # convert into strings
        d_hash = d_hash.hex()
        c_hash = c_hash.hex()
        obj_id = obj_id.hex()

        # check if there is already a data object with the same id
        if self.records.get_by_object_id(obj_id) is not None:
            # the data object already exists, nothing to do here.
            # TODO: decide if this is correct behaviour - in the meantime, just return the object id
            # current behaviour makes it impossible for the caller to know if a data object already existed
            # or not. question is whether this matters or not. the important point is that after calling
            # 'add' the data object is in the DOR.
            logger.warning(f"data object '{obj_id}' already exists. not adding to DOR.")
            return 200, {'data_object_id': obj_id}

        # check if there are already data objects with the same content
        if self.records.get_by_content_hash(c_hash):
            # it is possible for cases like this to happen. despite the exact same content, this may well be
            # a legitimate different data object. for example, different provenance has led to the exact same
            # outcome. we thus create a new data object
            logger.info(f"data object content '{c_hash}' already exists. not adding to DOR.")

        else:
            logger.info(f"data object content '{c_hash}' does not exist yet. adding to DOR.")

            # move the content to its destination and make read-only
            destination_path = self.obj_content_path(c_hash)
            subprocess.check_output(['mv', content_path, destination_path])
            subprocess.check_output(['chmod', 'ugo-w', destination_path])

        # create descriptor file
        descriptor_path = self.obj_descriptor_path(obj_id)
        dump_json_to_file(descriptor, descriptor_path)
        logger.info(f"data object '{obj_id}' descriptor stored at '{descriptor_path}'.")

        # update DOR db: add public key of owner, add the data object record and grant access to the owner by default
        self.public_keys.put(owner)
        self.records.add(d_hash, c_hash, obj_id, owner, self.node.key, expiration)
        self.grant_access(obj_id, owner)

        return 201, {'data_object_id': obj_id}

    def delete(self, obj_id):
        # do we have a record for this data object?
        record = self.records.get_by_object_id(obj_id)
        if not record:
            return 404, f"Database record for data object '{obj_id}' not found."

        # if we are not the custodian, we are not allowed to delete it
        if not record['custodian_iid'] == self.node.key.iid:
            return 403, f"Node is not custodian for data object '{obj_id}'"

        # do we have a descriptor for this data object?
        descriptor_path = self.obj_descriptor_path(obj_id)
        if not os.path.isfile(descriptor_path):
            return 500, f"Descriptor for data object '{obj_id}' not found."

        # read the descriptor content before deleting it
        with open(descriptor_path, 'r') as f:
            descriptor = json.loads(f.read())
            os.remove(descriptor_path)
            logger.info(f"descriptor for data object '{obj_id}' deleted.")

        # we delete the database entries associated with this data object
        self.permissions.revoke_all(obj_id)
        self.tags.remove_all(obj_id)
        self.records.delete(obj_id)
        logger.info(f"database records for data object '{obj_id}' deleted.")

        # next we need to check if there are other data objects that point to the same content (very unlikely but
        # not impossible). if not, then we can also safely delete the data object content.
        if not self.records.get_by_content_hash(record['c_hash']):
            content_path = self.obj_content_path(record['c_hash'])
            os.remove(content_path)
            logger.info(f"data object content '{record['c_hash']}' for data object '{obj_id}' deleted.")

        return 200, {'descriptor': descriptor}

    def get_content_hash(self, obj_id):
        record = self.records.get_by_object_id(obj_id)
        return record['c_hash'] if record else None

    def get(self, obj_id):
        return self.records.get_by_object_id(obj_id)

    def has_access(self, obj_id, user):
        return self.permissions.has_access(obj_id, user)

    def get_owner(self, obj_id):
        record = self.records.get_by_object_id(obj_id)
        return self.public_keys.get_public_key(record['owner_iid']) if record else None

    def get_descriptor(self, obj_id):
        # do we have a descriptor for this data object?
        descriptor_path = self.obj_descriptor_path(obj_id)
        if not os.path.isfile(descriptor_path):
            return 404, f"Data object '{obj_id}' not found."

        with open(descriptor_path, 'r') as f:
            descriptor = json.loads(f.read())
            return 200, {'descriptor': descriptor}

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

    def fetch(self, obj_id, job_input_obj_content_path=None):
        """
        Attempts to fetch the descriptor and the content of the data object with the given object id. If successful,
        the descriptor and content is stored in the DOR cache directory.
        :param obj_id: the data object id
        :return: content hash (c_hash) of the data object
        """
        # are we the custodian? in other words: do we have a record for this object?
        record = self.records.get_by_object_id(obj_id)
        if record:
            source_descriptor_path = self.obj_descriptor_path(obj_id)
            destination_descriptor_path = self.obj_descriptor_path(obj_id, cache=True)
            create_symbolic_link(source_descriptor_path, destination_descriptor_path)

            source_content_path = self.obj_content_path(record['c_hash'])
            destination_content_path = self.obj_content_path(record['c_hash'], cache=True)
            create_symbolic_link(source_content_path, destination_content_path)

            if job_input_obj_content_path:
                create_symbolic_link(source_descriptor_path, f"{job_input_obj_content_path}.descriptor")
                create_symbolic_link(source_content_path, job_input_obj_content_path)

            return record['c_hash']

        else:
            # use P2P protocol to attempt fetching from all other nodes
            protocol = DataObjectRepositoryP2PProtocol(self.node)
            for item in self.node.registry.get(exclude_self=True).items():
                c_hash = protocol.send_fetch(item[1]['address'], obj_id)
                if c_hash:
                    if job_input_obj_content_path:
                        source_descriptor_path = self.obj_descriptor_path(obj_id, cache=True)
                        source_content_path = self.obj_content_path(record['c_hash'], cache=True)
                        create_symbolic_link(source_content_path, job_input_obj_content_path)
                        create_symbolic_link(source_descriptor_path, f"{job_input_obj_content_path}.descriptor")

                    return c_hash

            return None

    def search_by_tags(self, key_criterion, value_criterion):
        return self.tags.search(key_criterion, value_criterion)

    def get_tags(self, obj_id):
        return self.tags.get_by_object_id(obj_id)

    def update_tags(self, obj_id, tags):
        self.tags.update(obj_id, tags)

    def remove_tags(self, obj_id, tags):
        self.tags.remove(obj_id, tags)
