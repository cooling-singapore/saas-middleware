from typing import Optional, List

from pydantic import BaseModel

from saas.schemas import ObjectRecipe


class DataObject(BaseModel):
    obj_id: str
    c_hash: str
    data_type: str
    data_format: str
    created_by: str
    created_t: int
    owner_iid: str
    access_restricted: bool
    content_encrypted: bool
    r_hash: Optional[str]
    tags: List[dict]
    access: List[str]


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


class AddDataObjectParameters(BaseModel):
    data_type: str
    data_format: str
    created_by: str
    owner_iid: str
    access_restricted: Optional[bool]
    content_encrypted: Optional[bool]
    recipe: Optional[ObjectRecipe]


class AddGPPDataObjectParameters(AddDataObjectParameters):
    class GPP(BaseModel):
        source: str
        commit_id: str
        proc_path: str
        proc_config: str

    class GithubCredentials(BaseModel):
        login: str
        personal_access_token: str

    gpp: GPP
    created_by: str
    owner_iid: str
    recipe: Optional[ObjectRecipe]
    github_credentials: Optional[GithubCredentials]


class Tag(BaseModel):
    key: str
    value: str
