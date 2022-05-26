from saascore.api.sdk.proxies import NodeDBProxy
from saascore.log import Logging
from tabulate import tabulate

from saas.cli.helpers import CLICommand, prompt_for_string, prompt_if_missing

logger = Logging.get('cli.network')


class NetworkShow(CLICommand):
    def __init__(self) -> None:
        super().__init__('show', 'shows the known nodes in the network', arguments=[])

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'address', prompt_for_string,
                          message="Enter the target node's REST address",
                          default='127.0.0.1:5001')

        db = NodeDBProxy(args['address'].split(':'))
        network = db.get_network()

        print(f"Found {len(network)} nodes in the network:")

        # headers
        lines = [
            ['NODE IDENTITY ID', 'DOR?', 'RTI?', 'REST ADDRESS', 'P2P ADDRESS', 'LAST SEEN'],
            ['----------------', '----', '----', '------------', '-----------', '---------']
        ]

        # list
        lines += [
            [node['iid'],
             'Yes' if node['dor_service'] else 'No',
             'Yes' if node['rti_service'] else 'No',
             node['rest_address'],
             node['p2p_address'],
             node['last_seen']] for node in network
        ]

        print(tabulate(lines, tablefmt="plain"))
