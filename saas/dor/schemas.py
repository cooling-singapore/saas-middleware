from typing import List, Optional, Dict, Union

from pydantic import BaseModel


class DORStatistics(BaseModel):
    data_types: List[str]
    data_formats: List[str]
    tag_keys: List[str]


class ProcessorDescriptor(BaseModel):
    class IODataObject(BaseModel):
        name: str
        data_type: str
        data_format: str
        data_schema: Optional[dict]

    name: str
    input: List[IODataObject]
    output: List[IODataObject]
    configurations: List[str]


class GitProcessorPointer(BaseModel):
    source: str
    commit_id: str
    proc_path: str
    proc_config: str
    proc_descriptor: ProcessorDescriptor


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

    class Tag(BaseModel):
        key: str
        value: Optional[Union[str, int, float, bool, List, Dict]]

    obj_id: str
    c_hash: str
    data_type: str
    data_format: str
    created: CreationDetails
    owner_iid: str
    access_restricted: bool
    access: List[str]
    tags: Dict[str, Union[str, int, float, bool, List, Dict]]


class GPPDataObject(DataObject):
    gpp: GitProcessorPointer


class CDataObject(DataObject):
    class License(BaseModel):
        by: bool  # if True -> must credit creators
        sa: bool  # if True -> adaptations (derivatives) must use same terms
        nc: bool  # if True -> must not be used for commercial purposes
        nd: bool  # if True -> not allowed to create derivatives

    content_encrypted: bool
    license: License
    recipe: Optional[DataObjectRecipe]
