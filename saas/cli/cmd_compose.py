from typing import List, Dict

import yaml
from pydantic import BaseModel

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, extract_address, load_keystore
from saas.core.keystore import Keystore
from saas.dor.proxy import DORProxy
from saas.nodedb.proxy import NodeDBProxy
from saas.rti.proxy import RTIProxy


class ProcInfo(BaseModel):
    name: str
    deployment: str = "native"
    ssh_credentials: str = None


class DeploySpec(BaseModel):
    class NodeSpec(BaseModel):
        rest_address: str
        processors: List[ProcInfo]

    class ProcessorSpec(BaseModel):
        source: str
        # TODO: Allow commit_id to be None as latest commit. Let node figure it out.
        commit_id: str
        proc_path: str
        proc_config: str

    nodes: Dict[str, NodeSpec]
    processors: Dict[str, ProcessorSpec]

    def validate_nodes(self):
        """
        Checks if nodes are contactable and have required components e.g. DOR to upload GPP
        """
        missing_nodes = []
        for node, info in self.nodes.items():
            address = extract_address(info.rest_address)
            # FIXME: This will hang if there is no response from the server
            db = NodeDBProxy(address)
            if not db.get_node().dor_service:
                missing_nodes.append(node)

        if missing_nodes:
            raise CLIRuntimeError(f"Required nodes do not have a DOR: {missing_nodes}")


def deploy_processors(spec: DeploySpec, keystore: Keystore):
    for _, node_spec in spec.nodes.items():
        node_address = extract_address(node_spec.rest_address)
        rti = RTIProxy(node_address)
        dor = DORProxy(node_address)

        # Make sure node knows about caller identity before deploying
        # FIXME: Will throw error if node is in strict mode and caller is not node owner
        db = NodeDBProxy(node_address)
        db.update_identity(keystore.identity)

        for proc in node_spec.processors:
            proc_spec = spec.processors[proc.name]
            ssh_credentials = keystore.ssh_credentials.get(proc.ssh_credentials)
            github_credentials = keystore.github_credentials.get(proc_spec.source)

            print(f"Uploading proc gpp: {proc_spec}")
            meta = dor.add_gpp_data_object(proc_spec.source,
                                           proc_spec.commit_id,
                                           proc_spec.proc_path,
                                           proc_spec.proc_config,
                                           keystore.identity,
                                           github_credentials=github_credentials)

            print(f"Deploying proc: {proc}")
            rti.deploy(meta.obj_id,
                       keystore,
                       proc.deployment,
                       ssh_credentials=ssh_credentials,
                       github_credentials=github_credentials)


class Compose(CLICommand):
    def __init__(self) -> None:
        super().__init__('compose', 'deploy processors based on yml file', arguments=[
            Argument('file', metavar='file', type=str, nargs=1,
                     help="file containing the content of the data object")
        ])

    def execute(self, args: dict) -> None:
        spec_file = args["file"][0]
        with open(spec_file, 'r') as stream:
            data_loaded = yaml.load(stream, Loader=yaml.Loader)

        spec = DeploySpec.parse_obj(data_loaded)
        spec.validate_nodes()

        # Load caller keystore
        keystore = load_keystore(args, ensure_publication=False)
        deploy_processors(spec, keystore)


if __name__ == '__main__':
    compose = Compose()
    compose.execute({
        "file": ["/Users/reynoldmok/Library/Application Support/JetBrains/PyCharm2022.2/scratches/compose.yml"],
        "keystore": "/Users/reynoldmok/.keystore",
        "keystore-id": "hnx0rxlhv2bsovj65xu2w4oz682xbeo1hfakad3jhheh2qzlbfm01nq7w38vcauz",
        "password": "1234"
    })
