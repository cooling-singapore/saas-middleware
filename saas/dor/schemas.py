from typing import Optional, List

from pydantic import BaseModel

from saas.schemas import ProcessorDescriptor


class SearchParameters(BaseModel):
    patterns: Optional[List[str]]
    owner_iid: Optional[str]
    data_type: Optional[str]
    data_format: Optional[str]
    c_hashes: Optional[List[str]]


class DORStatistics(BaseModel):
    data_types: List[str]
    data_formats: List[str]
    tag_keys: List[str]


class GithubCredentials(BaseModel):
    login: str
    personal_access_token: str


class GitProcessorPointer(BaseModel):
    source: str
    commit_id: str
    proc_path: str
    proc_config: str


class DataObjectRecipe(BaseModel):
    class GPPObject(GitProcessorPointer):
        c_hash: str
        proc_descriptor: ProcessorDescriptor

    class Object(BaseModel):
        c_hash: str
        name: str
        data_type: str
        data_format: str
        value: Optional[dict]

    product: Object
    processor: GPPObject
    input: List[Object]


class DataObjectProvenance(BaseModel):
    class ObjectNode(BaseModel):
        is_derived: bool
        c_hash: str
        data_type: str
        data_format: str
        content: Optional[dict]

    class ProcNode(BaseModel):
        gpp: GitProcessorPointer
        proc_descriptor: ProcessorDescriptor
        consumes: dict[str, int]
        produces: int

    data_nodes: List[ObjectNode]
    proc_nodes: List[ProcNode]


class DataObject(BaseModel):
    obj_id: str
    c_hash: str
    data_type: str
    data_format: str
    creator_iid: str
    created_t: int
    owner_iid: str
    access_restricted: bool
    access: List[str]
    tags: dict


class GPPDataObject(DataObject):
    source: str
    commit_id: str
    proc_path: str
    proc_config: str
    proc_descriptor: ProcessorDescriptor


class CDataObject(DataObject):
    content_encrypted: bool
    r_hash: Optional[str]
    recipe: Optional[DataObjectRecipe]


class AddDataObjectParameters(BaseModel):
    owner_iid: str
    creator_iid: str


class AddGPPDataObjectParameters(AddDataObjectParameters):
    source: str
    commit_id: str
    proc_path: str
    proc_config: str
    github_credentials: Optional[GithubCredentials]


class AddCDataObjectParameters(AddDataObjectParameters):
    data_type: str
    data_format: str
    access_restricted: bool
    content_encrypted: bool
    recipe: Optional[DataObjectRecipe]


class Tag(BaseModel):
    key: str
    value: str
