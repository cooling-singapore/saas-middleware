from typing import Optional, List, Dict, Union

from pydantic import BaseModel

from saas.schemas import GitProcessorPointer


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


class CObjectNode(BaseModel):
    c_hash: str
    data_type: str
    data_format: str
    content: Optional[dict]


class DataObjectRecipe(BaseModel):
    processor: GitProcessorPointer
    consumes: Dict[str, CObjectNode]
    product: CObjectNode
    name: str


class DataObjectProvenance(BaseModel):
    class Step(BaseModel):
        processor: str
        consumes: Dict[str, str]
        produces: Dict[str, str]

    data_nodes: Dict[str, CObjectNode]
    proc_nodes: Dict[str, GitProcessorPointer]
    steps: List[Step]
    missing: List[str]


class DataObject(BaseModel):
    class CreationDetails(BaseModel):
        timestamp: int
        creators_iid: List[str]

    obj_id: str
    c_hash: str
    data_type: str
    data_format: str
    created: CreationDetails
    owner_iid: str
    access_restricted: bool
    access: List[str]
    tags: dict


class GPPDataObject(DataObject):
    gpp: GitProcessorPointer


class DataObjectLicense(BaseModel):
    by: bool  # if True -> must credit creators
    sa: bool  # if True -> adaptations (derivatives) must use same terms
    nc: bool  # if True -> must not be used for commercial purposes
    nd: bool  # if True -> not allowed to create derivatives


class CDataObject(DataObject):
    content_encrypted: bool
    license: DataObjectLicense
    recipe: Optional[DataObjectRecipe]


class AddDataObjectParameters(BaseModel):
    owner_iid: str
    creators_iid: List[str]


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
    license: DataObjectLicense
    recipe: Optional[DataObjectRecipe]


class Tag(BaseModel):
    key: str
    value: Union[str, int, float, List, Dict]