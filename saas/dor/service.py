import os
import logging
import subprocess
import json

from saas.cryptography.hashing import hash_json_object, hash_file_content, hash_byte_objects
from saas.helpers import dump_json_to_file
from saas.dor.protocol import DataObjectRepositoryP2PProtocol

logger = logging.getLogger('dor.service')


class DataObjectRepositoryService:
    infix_master_path = 'dor-master'
    infix_cache_path = 'dor-cache'

    def obj_content_path(self, c_hash, cache=False):
        if cache:
            return os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_cache_path, f"{c_hash}.content")
        else:
            return os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_master_path, f"{c_hash}.content")

    def obj_descriptor_path(self, obj_id, cache=False):
        if cache:
            return os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_cache_path, f"{obj_id}.descriptor")
        else:
            return os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_master_path, f"{obj_id}.descriptor")

    def __init__(self, node):
        # initialise properties
        self.node = node
        self.protocol = DataObjectRepositoryP2PProtocol(node)

        # initialise directories
        subprocess.check_output(['mkdir', '-p', os.path.join(self.node.datastore(),
                                                             DataObjectRepositoryService.infix_master_path)])
        subprocess.check_output(['mkdir', '-p', os.path.join(self.node.datastore(),
                                                             DataObjectRepositoryService.infix_cache_path)])

    def add(self, owner_iid, descriptor, content_path, access_restricted, content_encrypted, content_key):
        # calculate the hash for the data object content
        c_hash = hash_file_content(content_path)

        # add the c_hash to the descriptor and calculate the hash for the descriptor
        descriptor['c_hash'] = c_hash.hex()
        d_hash = hash_json_object(descriptor)

        # calculate the data object id as a hash of the descriptor and content hashes
        obj_id = hash_byte_objects(d_hash, c_hash)

        # convert into strings
        d_hash = d_hash.hex()
        c_hash = c_hash.hex()
        obj_id = obj_id.hex()
        logger.info(f"attempt to add object with id={obj_id} (d_hash={d_hash} and c_hash={c_hash})")

        # check if there is already a data object with the same id
        if self.node.db.get_object_by_id(obj_id) is not None:
            # the data object already exists, nothing to do here.
            # TODO: decide if this is correct behaviour - in the meantime, just return the object id
            # current behaviour makes it impossible for the caller to know if a data object already existed
            # or not. question is whether this matters or not. the important point is that after calling
            # 'add' the data object is in the DOR.
            logger.info(f"data object '{obj_id}' already exists. not adding to DOR.")
            return 200, {'data_object_id': obj_id}

        # check if there are already data objects with the same content
        if self.node.db.get_objects_by_content_hash(c_hash):
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

        # try to resolve the owner identity
        owner = self.node.db.get_identity(iid=owner_iid)
        if owner is None:
            logger.info(f"no identity found for owner '{owner_iid}'. not adding to DOR.")
            return 404, {'owner_iid': owner_iid}

        # add data object to database
        self.node.db.add_data_object(obj_id, d_hash, c_hash, owner.id(), access_restricted, content_encrypted)

        # grant permission to access this data object to the owner, using the content key (if any)
        self.node.db.grant_access(obj_id, owner, content_key)

        return 201, {'data_object_id': obj_id, 'descriptor': descriptor}

    def delete(self, obj_id):
        # do we have a record for this data object?
        record = self.node.db.get_object_by_id(obj_id)
        if not record:
            return 404, f"Database record for data object '{obj_id}' not found."

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
        self.node.db.revoke_access(obj_id)
        self.node.db.remove_tags(obj_id)
        self.node.db.remove_data_object(obj_id)
        logger.info(f"database records for data object '{obj_id}' deleted.")

        # next we need to check if there are other data objects that point to the same content (very unlikely but
        # not impossible). if not, then we can also safely delete the data object content.
        if not self.node.db.get_objects_by_content_hash(record.c_hash):
            content_path = self.obj_content_path(record.c_hash)
            os.remove(content_path)
            logger.info(f"data object content '{record.c_hash}' for data object '{obj_id}' deleted.")

        return 200, descriptor
