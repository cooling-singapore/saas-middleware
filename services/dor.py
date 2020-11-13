"""
The Data Object Repository (DOM) - manages data objects.
"""

import os
import logging
import subprocess
import json
import ssl
import canonicaljson
import threading
import socket
import base64

from utilities import serialize_public_key
from utilities import deserialize_public_key
from utilities import serialize_private_key
from utilities import deserialize_private_key
from utilities import create_private_key
from utilities import hash_file_content
from utilities import hash_json_object
from utilities import hash_string_object
from utilities import hash_bytes_object
from utilities import dump_json_to_file

from nodedb import NodeDB
from node import Messenger

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

import cryptography.hazmat.primitives.serialization as serialization

logger = logging.getLogger('DOR')


class DataObjectRepository:
    def __init__(self, node, datastore_path, custodian_key=None):
        self.node = node
        self.datastore_path = datastore_path
        self.custodian_key = custodian_key

    def export_custodian_public_key(self):
        # do we have a custodian key in the first place?
        if self.custodian_key is None:
            return None

        # try to export the custodian key
        try:
            result = subprocess.check_output(['gpg', '--armor', '--export', self.custodian_key])
            result = result.decode('utf-8')
            return result

        except subprocess.CalledProcessError as e:
            raise Exception("error while exporting custodian public key '{}': {}".format(self.custodian_key, e))

    def search(self, search_tags=None):
        result = {}

        try:
            # do we have search tags?
            if search_tags is None:
                # get the number of records
                result['number_of_records'] = self.db.get_number_of_records()

                # get all distinct keys
                result['distinct_tags'] = self.db.get_distinct_tag_keys()

            else:
                # prepare the search tags for the SQL query
                keys = ','.join(map(str, search_tags))

                # get the record ids and data_object_ids that have the tag
                objects = self.db.get_all_objects_with_tag_keys(keys)
                for obj in objects:
                    logger.info("obj={}".format(obj))

        except Exception as e:
            logger.error("exception encountered: {}".format(e))

        return result

    def add(self, data_object_path, header):
        # calculate hashes for the data object header and content
        h_hash = hash_json_object(header)
        c_hash = hash_file_content(data_object_path)

        # calculate the data object id as a hash of the hashed data object header and content
        digest = hashes.Hash(hashes.SHA256())
        digest.update(h_hash)
        digest.update(c_hash)
        obj_id = digest.finalize()

        # convert into strings
        h_hash = h_hash.hex()
        c_hash = c_hash.hex()
        obj_id = obj_id.hex()

        # logger.info("header: {}".format(header))
        # logger.info("h_hash: {}".format(h_hash))
        # logger.info("c_hash: {}".format(c_hash))
        # logger.info("obj_id: {}".format(obj_id))

        # check if there is already a data object with the same id
        if self.node.db.get_data_object_by_id(obj_id) is not None:
            # the data object already exists, nothing to do here.
            # TODO: decide if this is correct behaviour - in the meantime, just return the object id
            # current behaviour makes it impossible for the caller to know if a data object already existed
            # or not. question is whether this matters or not. the important point is that after calling
            # 'add' the data object is in the DOR.
            logger.warning("data object '{}' already exists. not adding to DOR.".format(obj_id))
            return obj_id

        # check if there are already data objects with the same content
        if self.node.db.get_data_objects_by_content_hash(c_hash):
            # it is possible for cases like this to happen. despite the exact same content, this may well be
            # a legitimate different data object. for example, different provenance has led to the exact same
            # outcome. we thus create a new data object
            logger.info("data object content '{}' already exists. not adding to DOR.".format(c_hash))

        else:
            logger.info("data object content '{}' does not exist yet. adding to DOR.".format(c_hash))

            # create a copy of the data object content
            destination_path = os.path.join(self.datastore_path, "{}.content".format(c_hash))
            subprocess.check_output(['cp', data_object_path, destination_path])

        # create header file
        destination_path = os.path.join(self.datastore_path, "{}.header".format(obj_id))
        dump_json_to_file(header, destination_path)
        logger.info("data object '{}' header stored at '{}'.".format(obj_id, destination_path))

        # insert record into db
        self.node.db.insert_data_object_record(h_hash, c_hash, obj_id, self.node.id, header['created_by'])
        logger.info("data object '{}' record added to database.".format(obj_id))

        return obj_id

    def remove(self, obj_id):
        # check if we have the corresponding header?
        header = self.get_header(obj_id)
        if header:
            # remove the header file
            header_path = os.path.join(self.datastore_path, "{}.header".format(obj_id))
            os.remove(header_path)

            # delete the database record
            record = self.node.db.delete_data_object_record(obj_id)

            # check if there are still reference to this data object content (there could be more than one)
            # we only count the ones for which we are custodian
            records = []
            for record in self.node.db.get_data_objects_by_content_hash(record['c_hash']):
                if record['custodian_id'] == self.node.id:
                    records.append(record)

            # if there are no other records that refer to this data object content, then we can delete it
            if not records:
                path = os.path.join(self.datastore_path, "{}.content".format(record['c_hash']))
                os.remove(path)
                logger.info("data object content '{}' deleted.".format(record['c_hash']))

            return header

        else:
            return None

    def get_header(self, obj_id):
        header_path = os.path.join(self.datastore_path, "{}.header".format(obj_id))
        if os.path.isfile(header_path):
            with open(header_path, 'r') as f:
                return json.loads(f.read())

        return None

    def get_content(self, obj_id, destination_path):
        # check if we have the data object
        record = self.node.db.get_data_object_by_id(obj_id)

        # TODO: remove - this is just fake right now until proper testing is in place.
        # get the last known address of the custodian
        custodian_address = ('127.0.0.1', 4000)
        logger.info("custodian id={} address={}".format(record['custodian_id'], custodian_address))

        # create messenger
        peer = socket.create_connection(custodian_address)
        messenger = Messenger(peer)
        peer_id = messenger.handshake(self.node.id)
        logger.info("connected to peer '{}'".format(peer_id))

        response = messenger.request({
            'request': 'fetch',
            'obj_id': obj_id
        })
        logger.info("response received: {}".format(response))

        if response['reply'] == 'found':
            messenger.receive_attachment(destination_path)

        return destination_path

    def migrate(self, obj_id, destination):
        pass

    def transfer_ownership(self, public_key_a, public_key_b, signed_token):
        pass

    def grant_access(self, public_key, signed_token):
        pass

    def remove_access(self, public_key, signed_token):
        pass

    def get_permissions(self):
        pass
