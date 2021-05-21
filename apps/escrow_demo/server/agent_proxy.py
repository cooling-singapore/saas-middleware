import logging

from saas.rest.proxy import EndpointProxy

logger = logging.getLogger('escrow_demo.agent.proxy')
endpoint_prefix = "/api/v1/agent"


class AgentProxy(EndpointProxy):
    def __init__(self, remote_address, sender):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address, sender, use_auth=False)

    def get_identity(self):
        r = self.get(f"/identity")
        return r

    def add_transaction(self, name, description, provider, consumer, review_algorithm, review_output):
        body = {
            'name': name,
            'description': description,
            'provider_iid': provider.iid,
            'consumer_iid': consumer.iid,
            'review_algorithm': review_algorithm,
            'review_output': review_output
        }

        r = self.post(f"/transaction", body=body)
        return r

    def get_transaction(self, tx_id):
        r = self.get(f"/transaction/{tx_id}")
        return r

    def get_transactions(self):
        r = self.get(f"/transaction")
        return r

    def confirm_input(self, tx_id, obj_name, data_type, data_format, input_path):
        body = {
            'obj_name': obj_name,
            'data_type': data_type,
            'data_format': data_format
        }

        r = self.post(f"/confirm/{tx_id}/input", body=body, attachment=input_path)
        return r

    def confirm_processor(self, tx_id, source, commit_id, path):
        body = {
            'source': source,
            'commit_id': commit_id,
            'path': path
        }

        r = self.post(f"/confirm/{tx_id}/processor", body=body)
        return r

    def confirm_execute(self, tx_id):
        r = self.post(f"/confirm/{tx_id}/execute")
        return r
