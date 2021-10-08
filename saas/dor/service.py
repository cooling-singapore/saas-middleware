import os
import logging
import shutil
import subprocess
from stat import S_IREAD, S_IRGRP
from typing import Optional

from saas.cryptography.hashing import hash_file_content, hash_string_object
from saas.dor.exceptions import CloneRepositoryError, CheckoutCommitError, DataObjectNotFoundError, \
    ProcessorDescriptorNotFoundError, InvalidProcessorDescriptorError, InvalidGPPDataObjectError, IdentityNotFoundError
from saas.helpers import write_json_to_file, read_json_from_file, validate_json, generate_random_string
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.keystore.assets.credentials import GithubCredentials, CredentialsAsset
from saas.keystore.identity import Identity
from saas.schemas import processor_descriptor_schema, git_proc_pointer_schema

logger = logging.getLogger('dor.service')


class DataObjectRepositoryService:
    infix_master_path = 'dor-master'
    infix_temp_path = 'dor-temp'

    def __init__(self, node) -> None:
        # initialise properties
        self.node = node
        self.protocol = DataObjectRepositoryP2PProtocol(node)

        # initialise directories
        os.makedirs(os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_master_path), exist_ok=True)
        os.makedirs(os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_temp_path), exist_ok=True)

    def obj_content_path(self, c_hash: str) -> str:
        return os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_master_path, c_hash)

    def add_gpp(self, created_by: str, created_t: int, gpp: dict, owner_iid: str, recipe: Optional[dict]) -> dict:
        # get the owner identity
        owner = self.node.db.get_identity(owner_iid)
        if owner is None:
            raise IdentityNotFoundError(owner_iid)

        # verify the GPP object
        if not validate_json(gpp, git_proc_pointer_schema):
            raise InvalidGPPDataObjectError({
                'gpp': gpp
            })

        # determine URL including credentials (if any)
        url = gpp['source']
        credentials: CredentialsAsset = self.node.keystore.get_asset('github-credentials')
        if credentials is not None:
            credentials: GithubCredentials = credentials.get(url)
            if credentials:
                insert = f"{credentials.login}:{credentials.personal_access_token}@"
                index = url.find('github.com')
                url = url[:index] + insert + url[index:]

        # try to clone the repository
        temp_id = generate_random_string(8)
        repo_path = os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_temp_path, f"{temp_id}.repo")
        result = subprocess.run(['git', 'clone', url, repo_path], capture_output=True)
        if result.returncode != 0:
            raise CloneRepositoryError({
                'url': url,
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })

        # try to checkout the specific commit
        result = subprocess.run(['git', 'checkout', gpp['commit_id']], capture_output=True, cwd=repo_path)
        if result.returncode != 0:
            raise CheckoutCommitError({
                'commit-id': gpp['commit-id'],
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })

        # does the processor descriptor exist?
        proc_descriptor_path = os.path.join(repo_path, gpp['proc_path'], 'descriptor.json')
        if not os.path.isfile(proc_descriptor_path):
            raise ProcessorDescriptorNotFoundError({
                'gpp': gpp,
                'proc_descriptor_path': proc_descriptor_path
            })

        # read the processor descriptor
        gpp['proc_descriptor'] = read_json_from_file(proc_descriptor_path)
        if not validate_json(gpp['proc_descriptor'], processor_descriptor_schema):
            raise InvalidProcessorDescriptorError({
                'gpp': gpp
            })

        # we don't need the repository anymore -> delete it
        shutil.rmtree(repo_path)

        # store the GPP object to a temporary location and generate the c_cash
        gpp_path = os.path.join(self.node.datastore(), DataObjectRepositoryService.infix_temp_path, f"{temp_id}.gpp")
        write_json_to_file(gpp, gpp_path)
        c_hash = hash_file_content(gpp_path).hex()

        return self._add(c_hash, gpp_path, 'Git-Processor-Pointer', 'json', created_by, created_t,
                         recipe, gpp, owner, False, False)

    def add(self, temp_content_path: str, data_type: str, data_format: str, created_by: str, created_t: int,
            recipe: Optional[dict], owner_iid: str, access_restricted: bool, content_encrypted: bool) -> dict:

        # get the owner identity
        owner = self.node.db.get_identity(owner_iid)
        if owner is None:
            raise IdentityNotFoundError(owner_iid)

        # calculate the hash for the data object content
        c_hash = hash_file_content(temp_content_path).hex()

        return self._add(c_hash, temp_content_path, data_type, data_format, created_by, created_t,
                         recipe, None, owner, access_restricted, content_encrypted)

    def _add(self, c_hash: str, temp_content_path: str, data_type: str, data_format: str,
             created_by: str, created_t: int, recipe: Optional[dict], gpp: Optional[dict],
             owner: Identity, access_restricted: bool, content_encrypted: bool) -> dict:

        # calculate the hash for the meta information
        m_hash = hash_string_object(f"{data_type}{data_format}{created_by}{created_t}"
                                    f"{recipe if recipe is not None else ''}").hex()

        # calculate the data object id as a hash of the meta information and content hashes
        obj_id = hash_string_object(f"{m_hash}{c_hash}").hex()

        logger.debug(f"attempt to add object with id={obj_id} (m_hash={m_hash} and c_hash={c_hash})")

        # check if there is already a data object with the same id
        record = self.node.db.get_object_by_id(obj_id)
        if record is not None:
            # the data object already exists, nothing to do here.
            # TODO: decide if this is correct behaviour - in the meantime, just return the object id
            # current behaviour makes it impossible for the caller to know if a data object already existed
            # or not. question is whether this matters or not. the important point is that after calling
            # 'add' the data object is in the DOR.
            logger.info(f"data object '{obj_id}' already exists -> not adding to DOR.")
            return record

        # check if there are already data objects with the same content
        records = self.node.db.get_objects_by_content_hash(c_hash)
        if len(records) > 0:
            # it is possible for cases like this to happen. despite the exact same content, this may well be
            # a legitimate different data object. for example, different provenance has led to the exact same
            # outcome. we thus create a new data object
            logger.info(f"data object content '{c_hash}' already exists -> not adding to DOR.")

            # delete the temporary content as it is not needed
            os.remove(temp_content_path)

        else:
            logger.info(f"data object content '{c_hash}' does not exist yet -> adding to DOR.")

            # move the temporary content to its destination and make it read-only
            destination_path = self.obj_content_path(c_hash)
            os.rename(temp_content_path, destination_path)
            os.chmod(destination_path, S_IREAD | S_IRGRP)

        # add data object to database
        record = self.node.db.add_data_object(obj_id, m_hash, c_hash, data_type, data_format,
                                              created_by, created_t, recipe, gpp, owner,
                                              access_restricted, content_encrypted)

        # grant access permission to the owner
        self.node.db.grant_access(obj_id, owner)

        return record

    def delete(self, obj_id: str) -> dict:
        # do we have a record for this data object?
        record = self.node.db.get_object_by_id(obj_id)
        if not record:
            raise DataObjectNotFoundError(obj_id)

        # we delete the database entries associated with this data object
        self.node.db.revoke_access(obj_id)
        self.node.db.remove_tags(obj_id)
        self.node.db.remove_data_object(obj_id)
        logger.info(f"database records for data object '{obj_id}' deleted.")

        # next we need to check if there are other data objects that point to the same content (very unlikely but
        # not impossible). if not, then we can also safely delete the data object content.
        if len(self.node.db.get_objects_by_content_hash(record['c_hash'])) == 0:
            content_path = self.obj_content_path(record['c_hash'])
            os.remove(content_path)
            logger.info(f"data object content '{record['c_hash']}' for data object '{obj_id}' deleted.")

        return record
