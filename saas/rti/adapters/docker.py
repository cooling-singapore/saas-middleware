import socket

from saas.rti.adapters.adapters import RTITaskProcessorAdapter


def find_open_port():
    """
    Use socket's built in ability to find an open port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        port = s.getsockname()[1]
    return port


class RTIDockerProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, descriptor, content_path, node):
        super().__init__(proc_id, node)
        # self.processor_name = self.processor_descriptor['name']
        # self.processor_version = self.processor_descriptor['commit']

        self.port = None
        self.docker_image_id = None
        self.docker_container_id = None
        # self.docker_container_name = f'{self.processor_name}-{self.processor_version}'

    @property
    def uri(self):
        if self.port is not None:
            return f'http://localhost:{self.port}'
        else:
            raise ValueError('Port has not been initialised.')

    # def build_docker_image(self):
    #     client = docker.from_env()
    #
    #     image, logs = client.images.build(path=processor_path,
    #                                       dockerfile=os.path.join(dockerfile_directory, 'Dockerfile'),
    #                                       rm=True)
    #
    # def start_docker_container(self):
    #     client = docker.from_env()
    #
    #     # bind rti.jobs_path to jobs_path in Docker
    #     jobs_path = os.path.realpath(self._node.rti.get_job_wd())
    #     self.port = find_open_port()
    #     container = client.containers.run(self.docker_image_id,
    #                                       name=self.docker_container_name,
    #                                       ports={'5000/tcp': self.port},
    #                                       volumes={jobs_path: {'bind': '/jobs_path', 'mode': 'rw'}},
    #                                       detach=True)
    #
    #     while True:
    #         if container.status != 'running':
    #             time.sleep(1)
    #             container.reload()  # refresh container attrs
    #         else:  # check if server is responding to requests
    #             r = requests.get(f'{self.uri}/descriptor')
    #             if r.status_code == 200:
    #                 break
    #
    #     client.close()
    #
    #     self.docker_container_id = container.id

    # def startup(self):
    #     self.parse_io_interface(self.descriptor)
    #     logger.info(f"[{self.__class__.__name__}] startup: started docker processor '{self.processor_name}'")
    #
    # def shutdown(self):
    #     client = docker.from_env()
    #
    #     # Kill and remove docker container
    #     try:
    #         container = client.containers.get(self.docker_container_id)
    #     except docker.errors.NotFound:
    #         logger.warning(
    #             f"[{self.__class__.__name__}] shutdown: could not find docker processor '{self.processor_name}'")
    #     else:
    #         container.stop()
    #         container.wait()
    #         container.remove()
    #
    #     # Remove image from docker
    #     client.images.remove(self.docker_image_id)
    #
    #     client.close()
    #     logger.info(f"[{self.__class__.__name__}] shutdown: shutdown docker processor '{self.processor_name}'")
    #
    # def execute(self, task_descriptor, working_directory, status_logger):
    #     try:
    #         job_id = os.path.basename(working_directory)
    #         r = requests.post(f'{self.uri}/execute', json={'job_id': job_id,
    #                                                        'task_descriptor': task_descriptor})
    #         status_code = r.status_code
    #     except Exception as e:
    #         logger.warning(
    #             f"[{self.__class__.__name__}] execute: execute failed for docker processor '{self.processor_name}'")
    #         return False
    #     else:
    #         return r.status_code == 200
