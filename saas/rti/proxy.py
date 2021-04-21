import json

from saas.utilities.blueprint_helpers import create_authentication, post, get, delete
from saas.utilities.general_helpers import all_in_dict


class EndpointProxy:
    def __init__(self, remote_address, sender):
        self.remote_address = remote_address
        self.sender = sender

    def get_deployed(self):
        url = f"http://{self.remote_address}/processor"

        authentication = create_authentication(f"GET:/processor", self.sender)
        content = {
            'authentication': json.dumps(authentication),
        }

        r = get(url, content)
        return r['reply']['deployed'] if 'deployed' in r['reply'] else None

    def deploy(self, proc_id):
        url = f"http://{self.remote_address}/processor/{proc_id}"

        authentication = create_authentication(f"POST:/processor/{proc_id}", self.sender)
        content = {
            'authentication': json.dumps(authentication),
        }

        r = post(url, content)
        return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None

    def undeploy(self, proc_id):
        url = f"http://{self.remote_address}/processor/{proc_id}"

        authentication = create_authentication(f"DELETE:/processor/{proc_id}", self.sender)
        content = {
            'authentication': json.dumps(authentication),
        }

        r = delete(url, content)
        return r

    def get_descriptor(self, proc_id):
        url = f"http://{self.remote_address}/processor/{proc_id}"

        authentication = create_authentication(f"GET:/processor/{proc_id}", self.sender)
        content = {
            'authentication': json.dumps(authentication),
        }

        r = get(url, content)
        return r['reply']['descriptor']

    def submit_job(self, proc_id, proc_input, output_owner):
        url = f"http://{self.remote_address}/processor/{proc_id}/jobs"

        body = {
            'type': 'task',
            'descriptor': {
                'processor_id': proc_id,
                'input': proc_input,
                'output': {
                    'owner_public_key': output_owner.public_as_string()
                }
            }
        }

        authentication = create_authentication(f"POST:/processor/{proc_id}/jobs", self.sender, body)
        content = {
            'body': json.dumps(body),
            'authentication': json.dumps(authentication)
        }

        r = post(url, content)
        return r['reply']['job_id'] if 'job_id' in r['reply'] else None

    def submit_workflow(self, name, tasks):
        url = f"http://{self.remote_address}/processor/workflow/jobs"

        body = {
            'type': 'workflow',
            'descriptor': {
                'name': name,
                'tasks': tasks
            }
        }

        authentication = create_authentication("POST:/processor/workflow/jobs", self.sender, body)
        content = {
            'body': json.dumps(body),
            'authentication': json.dumps(authentication)
        }

        r = post(url, content)
        return r['reply']['job_id'] if 'job_id' in r['reply'] else None

    def get_jobs(self, proc_id):
        url = f"http://{self.remote_address}/processor/{proc_id}/jobs"

        authentication = create_authentication(f"GET:/processor/{proc_id}/jobs", self.sender)
        content = {
            'authentication': json.dumps(authentication)
        }

        r = get(url, content)
        return r['reply']['jobs'] if 'jobs' in r['reply'] else None

    def get_job(self, proc_id, job_id):
        url = f"http://{self.remote_address}/processor/{proc_id}/jobs/{job_id}"

        authentication = create_authentication(f"GET:/processor/{proc_id}/jobs/{job_id}", self.sender)
        content = {
            'authentication': json.dumps(authentication)
        }

        r = get(url, content)
        return r['reply'] if all_in_dict(['job_descriptor', 'status'], r['reply']) else None
