import os.path
import signal
import time
from enum import Enum
from typing import List, Dict

import yaml
from pydantic import BaseModel

from saas.cli.helpers import CLICommand, Argument, extract_address
from saas.core.keystore import Keystore
from saas.dor.proxy import DORProxy
from saas.dor.service import fetch_proc_descriptor, _generate_gpp_hash
from saas.node import Node
from saas.rti.proxy import RTIProxy
from saas.service import SignalListener


class ProcInfo(BaseModel):
    name: str
    deployment: str = "native"
    ssh_credentials: str = None


class NodeType(str, Enum):
    full = 'full'
    storage = 'storage'
    execution = 'execution'


class DeploySpec(BaseModel):
    class NodeSpec(BaseModel):
        datastore_path: str = "~/.datastore"
        keystore_path: str = "~/.keystore"
        log_path: str = "~/.log"
        keystore_id: str
        password: str
        rest_address: str
        p2p_address: str
        boot_node_address: str
        type: NodeType = "full"
        processors: List[ProcInfo]

    class ProcessorSpec(BaseModel):
        source: str
        # TODO: Allow commit_id to be None as latest commit. Let node figure it out.
        commit_id: str
        proc_path: str
        proc_config: str
        dor: str = None

    nodes: Dict[str, NodeSpec]
    processors: Dict[str, ProcessorSpec]


def startup_node(node_spec: DeploySpec.NodeSpec):
    # create node and startup services
    keystore_path = os.path.join(os.path.expanduser(os.path.expanduser(node_spec.keystore_path)),
                                 f"{node_spec.keystore_id}.json")
    datastore_path = os.path.expanduser(os.path.expanduser(node_spec.datastore_path))

    keystore = Keystore.load(keystore_path, node_spec.password)
    node = Node.create(keystore=keystore,
                       storage_path=datastore_path,
                       p2p_address=extract_address(node_spec.p2p_address),
                       boot_node_address=extract_address(node_spec.boot_node_address),
                       rest_address=extract_address(node_spec.rest_address),
                       enable_dor=node_spec.type == 'full' or node_spec.type == 'storage',
                       enable_rti=node_spec.type == 'full' or node_spec.type == 'storage')

    return node


def deploy_processors(spec: DeploySpec, nodes: dict[str, Node]):
    for node_key, node_spec in spec.nodes.items():
        node_address = extract_address(node_spec.rest_address)
        rti = RTIProxy(node_address)

        keystore = nodes[node_key].keystore

        for proc in node_spec.processors:
            proc_spec = spec.processors[proc.name]
            ssh_credentials = keystore.ssh_credentials.get(proc.ssh_credentials)
            github_credentials = keystore.github_credentials.get(proc_spec.source)

            dor_address = extract_address(spec.nodes[proc_spec.dor].rest_address) if proc_spec.dor else node_address
            dor = DORProxy(dor_address)

            # fetch proc descriptor
            proc_descriptor = fetch_proc_descriptor(proc_spec.source, proc_spec.commit_id, proc_spec.proc_path,
                                                    proc_spec.proc_config, github_credentials)
            # determine the content hash for the GPP
            c_hash = _generate_gpp_hash(proc_spec.source, proc_spec.commit_id, proc_spec.proc_path,
                                        proc_spec.proc_config, proc_descriptor.dict())
            # check if gpp already found in dor
            items = dor.search(c_hashes=[c_hash])
            if items:
                # use the first item if multiple exist
                obj_id = items[0].obj_id
            else:
                print(f"Uploading proc gpp to {dor_address}: {proc_spec}")
                meta = dor.add_gpp_data_object(proc_spec.source,
                                               proc_spec.commit_id,
                                               proc_spec.proc_path,
                                               proc_spec.proc_config,
                                               keystore.identity,
                                               github_credentials=github_credentials)
                obj_id = meta.obj_id

            print(f"Deploying proc ({obj_id}): {proc}")
            rti.deploy(obj_id,
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

        spec: DeploySpec = DeploySpec.parse_obj(data_loaded)

        nodes = dict()
        try:
            for node_key, node_spec in spec.nodes.items():
                print(f"Starting up {node_key} | {node_spec.keystore_id}")
                node = startup_node(node_spec)
                nodes[node_key] = node

            print("Deploying processors to nodes")
            deploy_processors(spec, nodes)

            print("Nodes ready")

            # Block until interrupt
            signal_listener = SignalListener([signal.SIGTERM])
            while not signal_listener.triggered:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Interrupted by user. Shutting down.")
        finally:
            for _, node in nodes.items():
                node.shutdown()


if __name__ == '__main__':
    compose = Compose()
    compose.execute({
        "file": ["/Users/reynoldmok/Library/Application Support/JetBrains/PyCharm2022.2/scratches/compose.yml"],
    })
