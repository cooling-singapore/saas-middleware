import os
import logging
import subprocess
import json

from saas.cryptography.hashing import hash_json_object, hash_file_content, hash_byte_objects
from saas.dor.exceptions import CloneRepositoryError, CheckoutCommitError, DataObjectDescriptorNotFoundError, \
    InvalidDataObjectDescriptorError, OwnerIdentityNotFoundError, DataObjectNotFoundError
from saas.helpers import write_json_to_file, read_json_from_file, validate_json
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.keystore.assets.credentials import GithubCredentials, CredentialsAsset
from saas.schemas import processor_descriptor_schema

logger = logging.getLogger('dor.service')


class DataObjectRepositoryService:
    infix_master_path = 'dor-master'
    infix_cache_path = 'dor-cache'
    infix_repo_path = 'dor-repositories'

    def obj_content_path(self, c_hash: str, cache: bool = False) -> str:
        if cache:
            return os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_cache_path, f"{c_hash}.content")
        else:
            return os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_master_path, f"{c_hash}.content")

    def obj_descriptor_path(self, obj_id: str, cache: bool = False) -> str:
        if cache:
            return os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_cache_path, f"{obj_id}.descriptor")
        else:
            return os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_master_path, f"{obj_id}.descriptor")

    def __init__(self, node) -> None:
        # initialise properties
        self.node = node
        self.protocol = DataObjectRepositoryP2PProtocol(node)

        # initialise directories
        os.makedirs(os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_master_path), exist_ok=True)
        os.makedirs(os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_cache_path), exist_ok=True)
        os.makedirs(os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_repo_path), exist_ok=True)

    def add_gpp(self, owner_iid: str, descriptor: dict, gpp: dict) -> (int, dict):
        # in case of a GPP, we verify validity first before adding the data object

        # calculate the hash for the data object content
        c_hash = hash_json_object(gpp)

        # prepare for cloning
        target_path = os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_repo_path, c_hash.hex())
        url = gpp['source']

        # does the node identity have credentials for that?
        credentials: CredentialsAsset = self.node.keystore.get_asset('github-credentials')
        if credentials is not None:
            credentials: GithubCredentials = credentials.get(url)
            if credentials:
                insert = f"{credentials.login}:{credentials.personal_access_token}@"
                index = url.find('github.com')
                url = url[:index] + insert + url[index:]

        # does the repository already exist?
        if os.path.isdir(target_path):
            subprocess.run(['rm', '-rf', target_path])

        # try to clone the repository
        result = subprocess.run(['git', 'clone', url, target_path], capture_output=True)
        if result.returncode != 0:
            raise CloneRepositoryError({
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })

        # try to checkout the commit
        result = subprocess.run(['git', 'checkout', gpp['commit_id']], capture_output=True, cwd=target_path)
        if result.returncode != 0:
            raise CheckoutCommitError({
                'commit-id': gpp['commit-id'],
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })

        # does the processor descriptor exist?
        proc_descriptor_path = os.path.join(target_path, gpp['proc_path'], 'descriptor.json')
        if not os.path.isfile(proc_descriptor_path):
            raise DataObjectDescriptorNotFoundError(proc_descriptor_path)

        # read the processor descriptor
        proc_descriptor = read_json_from_file(proc_descriptor_path)
        if not validate_json(proc_descriptor, processor_descriptor_schema):
            raise InvalidDataObjectDescriptorError(proc_descriptor)

        # write the content of the data object
        content_path = os.path.join(target_path, 'gpp.json')
        write_json_to_file(gpp, content_path)

        # add the c_hash and proc descriptor to the data object descriptor and calculate the hash for the descriptor
        descriptor['c_hash'] = c_hash.hex()
        descriptor['proc_descriptor'] = proc_descriptor

        return self._add(owner_iid, c_hash, descriptor, content_path, False, False)

    def add(self, owner_iid: str, descriptor: dict, content_path: str,
            access_restricted: bool, content_encrypted: bool) -> (int, dict):

        # calculate the hash for the data object content
        c_hash = hash_file_content(content_path)

        # add the c_hash to the descriptor
        descriptor['c_hash'] = c_hash.hex()

        return self._add(owner_iid, c_hash, descriptor, content_path, access_restricted, content_encrypted)

    def _add(self, owner_iid: str, c_hash: bytes, descriptor: dict, content_path: str,
             access_restricted: bool, content_encrypted: bool) -> (int, dict):

        # calculate the hash for the descriptor
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
            return {
                'data_object_id': obj_id,
                'descriptor': descriptor
            }

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
            subprocess.check_output(['mv', '-f', content_path, destination_path])
            subprocess.check_output(['chmod', 'ugo-w', destination_path])

        # create descriptor file
        descriptor_path = self.obj_descriptor_path(obj_id)
        write_json_to_file(descriptor, descriptor_path)
        logger.info(f"data object '{obj_id}' descriptor stored at '{descriptor_path}'.")

        # try to resolve the owner identity
        owner = self.node.db.get_identity(owner_iid)
        if owner is None:
            raise OwnerIdentityNotFoundError(obj_id=obj_id, owner_iid=owner_iid)

        # add data object to database
        self.node.db.add_data_object(obj_id, d_hash, c_hash, owner.id,
                                     access_restricted, content_encrypted,
                                     descriptor['data_type'], descriptor['data_format'])

        # grant permission to access this data object to the owner, using the content key (if any)
        self.node.db.grant_access(obj_id, owner)

        return {
            'obj_id': obj_id,
            'descriptor': descriptor
        }

    def delete(self, obj_id: str) -> dict:
        # do we have a record for this data object?
        record = self.node.db.get_object_by_id(obj_id)
        if not record:
            raise DataObjectNotFoundError(obj_id)

        # do we have a descriptor for this data object?
        descriptor_path = self.obj_descriptor_path(obj_id)
        if not os.path.isfile(descriptor_path):
            raise DataObjectDescriptorNotFoundError(descriptor_path)

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
        if not self.node.db.get_objects_by_content_hash(record['c_hash']):
            content_path = self.obj_content_path(record['c_hash'])
            os.remove(content_path)
            logger.info(f"data object content '{record['c_hash']}' for data object '{obj_id}' deleted.")

        return {
            'obj_id': obj_id,
            'descriptor': descriptor
        }
