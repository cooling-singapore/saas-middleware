import os
import shutil
import subprocess
from stat import S_IREAD, S_IRGRP
from typing import Optional

from saas.cryptography.helpers import hash_file_content
from saas.dor.exceptions import CloneRepositoryError, CheckoutCommitError, ProcessorDescriptorNotFoundError, \
    InvalidProcessorDescriptorError, InvalidGPPDataObjectError, IdentityNotFoundError
from saas.helpers import write_json_to_file, read_json_from_file, validate_json, generate_random_string
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.keystore.assets.credentials import GithubCredentials, CredentialsAsset
from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.schemas import processor_descriptor_schema, git_proc_pointer_schema

logger = Logging.get('dor.service')


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

    def add_gpp(self, created_by: str, gpp: dict, owner_iid: str, recipe: Optional[dict]) -> dict:
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

        return self._add(c_hash, gpp_path, 'Git-Processor-Pointer', 'json', created_by,
                         recipe, gpp, owner, False, False)

    def add(self, temp_content_path: str, data_type: str, data_format: str, created_by: str,
            recipe: Optional[dict], owner_iid: str, access_restricted: bool, content_encrypted: bool) -> dict:

        # get the owner identity
        owner = self.node.db.get_identity(owner_iid)
        if owner is None:
            raise IdentityNotFoundError(owner_iid)

        # calculate the hash for the data object content
        c_hash = hash_file_content(temp_content_path).hex()

        return self._add(c_hash, temp_content_path, data_type, data_format, created_by,
                         recipe, None, owner, access_restricted, content_encrypted)

    def _add(self, c_hash: str, temp_content_path: str, data_type: str, data_format: str,
             created_by: str, recipe: Optional[dict], gpp: Optional[dict],
             owner: Identity, access_restricted: bool, content_encrypted: bool) -> dict:

        # check if there are already data objects with the same content
        if len(self.node.db.get_objects_by_content_hash(c_hash)) > 0:
            # it is possible for cases like this to happen. despite the exact same content, this may well be
            # a legitimate different data object. for example, different provenance has led to the exact same
            # outcome. we thus create a new data object
            logger.info(f"data object content '{c_hash}' already exists -> not adding content to DOR.")

            # delete the temporary content as it is not needed
            os.remove(temp_content_path)

        else:
            logger.info(f"data object content '{c_hash}' does not exist yet -> adding content to DOR.")

            # move the temporary content to its destination and make it read-only
            destination_path = self.obj_content_path(c_hash)
            os.rename(temp_content_path, destination_path)
            os.chmod(destination_path, S_IREAD | S_IRGRP)

        # add data object to database
        record = self.node.db.add_data_object(c_hash, data_type, data_format, created_by, gpp,
                                              owner, access_restricted, content_encrypted)
        obj_id = record['obj_id']
        logger.info(f"database records for data object '{obj_id}' added with c_hash={c_hash}.")

        # add the recipe (if any) and broadcast it
        if recipe is not None:
            # insert the missing c_hash
            recipe['product']['c_hash'] = c_hash

            # add the recipe to the NodeDB
            self.node.db.add_recipe(c_hash, recipe)
            self.node.db.protocol.broadcast_update('add_recipe', {
                'c_hash': c_hash,
                'recipe': recipe
            })

        return record

    def delete(self, obj_id: str) -> dict:
        # delete the database entries associated with this data object EXCEPT for the provenance information
        record = self.node.db.remove_data_object(obj_id)
        logger.info(f"database records for data object '{obj_id}' deleted.")

        # next we need to check if there are other data objects that point to the same content (very unlikely but
        # not impossible) AND still expect the data object content to be available. if so, then do NOT delete the
        # data object content. otherwise delete it.
        referenced = [r['obj_id'] for r in self.node.db.get_objects_by_content_hash(record['c_hash'])]

        if len(referenced) == 0:
            logger.info(f"data object content '{record['c_hash']}' not referenced by any data object -> delete.")
            content_path = self.obj_content_path(record['c_hash'])
            os.remove(content_path)
        else:
            logger.info(f"data object content '{record['c_hash']}' referenced by data objects ({referenced}) -> "
                        f"do not delete.")

        return record
