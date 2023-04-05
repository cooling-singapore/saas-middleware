from __future__ import annotations

from typing import Optional, List, Dict, Tuple

from saas.core.identity import Identity
from saas.nodedb.schemas import NodeInfo
from saas.rest.proxy import EndpointProxy, Session

DB_ENDPOINT_PREFIX = "/api/v1/db"


class NodeDBProxy(EndpointProxy):
    @classmethod
    def from_session(cls, session: Session) -> NodeDBProxy:
        return NodeDBProxy(remote_address=session.address, credentials=session.credentials,
                           endpoint_prefix=(session.endpoint_prefix_base, 'db'))

    def __init__(self, remote_address: (str, int), credentials: (str, str) = None,
                 endpoint_prefix: Tuple[str, str] = ('/api/v1', 'db')):
        super().__init__(endpoint_prefix, remote_address, credentials=credentials)

    def get_node(self) -> NodeInfo:
        result = self.get("node")
        return NodeInfo.parse_obj(result)

    def get_network(self) -> List[NodeInfo]:
        results = self.get("network")
        return [NodeInfo.parse_obj(result) for result in results]

    def get_identities(self) -> Dict[str, Identity]:
        return {
            item['id']: Identity.parse_obj(item) for item in self.get("identity")
        }

    def get_identity(self, iid: str) -> Optional[Identity]:
        serialised_identity = self.get(f"identity/{iid}")
        return Identity.parse_obj(serialised_identity) if serialised_identity else None

    def update_identity(self, identity: Identity) -> Optional[Identity]:
        serialised_identity = self.post('identity', body=identity.dict())
        return Identity.parse_obj(serialised_identity) if serialised_identity else None
