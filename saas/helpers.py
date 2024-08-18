import socket
import netifaces
import ipaddress
from typing import List, Optional, Tuple

import docker
from docker.models.images import Image


def determine_local_ip() -> Optional[str]:
    # determine all private IPv4 addresses that are not loopback devices
    private_ipv4_addresses = []
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for entry in addresses[netifaces.AF_INET]:
                ip_address = entry['addr']

                # check if the address is private and not a loopback device
                addr = ipaddress.IPv4Address(ip_address)
                if addr.is_private and not addr.is_loopback:
                    private_ipv4_addresses.append(ip_address)

    return private_ipv4_addresses[0] if private_ipv4_addresses else None


LOCAL_IP = determine_local_ip()


def determine_default_p2p_address() -> str:
    return f"{LOCAL_IP}:4001" if LOCAL_IP else "127.0.0.1:4001"


def determine_default_rest_address() -> str:
    return f"{LOCAL_IP}:5001" if LOCAL_IP else "127.0.0.1:5001"


def determine_default_ws_address() -> str:
    return f"{LOCAL_IP}:6001" if LOCAL_IP else "127.0.0.1:6001"


def find_available_port(host: str = 'localhost', port_range: (int, int) = (6000, 7000)) -> Optional[int]:
    for port in range(port_range[0], port_range[1], 1):
        # create a socket object and set a timeout to avoid blocking indefinitely
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        # try to connect to the specified host and port
        try:
            sock.connect((host, port))
        except socket.error as e:
            if isinstance(e, (TimeoutError, ConnectionRefusedError)):
                return port

        finally:
            sock.close()

    return None


def docker_find_image(image_name: str) -> List[Image]:
    client = docker.from_env()
    return [image for image in client.images.list() if image_name in image.tags]


def docker_delete_image(image_name: str) -> None:
    client = docker.from_env()
    image = client.images.get(image_name)
    client.images.remove(image.id, force=True)


def docker_export_image(image_name: str, output_path: str, keep_image: bool = True) -> None:
    client = docker.from_env()

    # save the docker image
    image = client.images.get(image_name)
    with open(output_path, 'wb') as f:
        for chunk in image.save(named=True):
            f.write(chunk)

    # delete the image (if applicable)
    if not keep_image:
        client.images.remove(image.id, force=True)


def docker_load_image(image_path: str, image_name: str, undo_if_no_match: bool = True) -> Optional[Image]:
    client = docker.from_env()
    with open(image_path, 'rb') as f:
        loaded_images = client.images.from_file(f.read())

        # does the image name match?
        found = None
        for image in loaded_images:
            if image_name in image.tags:
                found = image
                break

        # if not found, undo?
        if undo_if_no_match and not found:
            for image in loaded_images:
                client.images.remove(image.id, force=True)

        return found


def docker_run_job_container(image_name: str, job_path: str, job_address: Tuple[str, int]) -> None:
    client = docker.from_env()
    client.containers.run(
        image=image_name,
        volumes={
            job_path: {'bind': '/job', 'mode': 'rw'}
        },
        ports={
            '5000/tcp': job_address,
        },
        detach=True,
        stderr=True, stdout=True,
        auto_remove=True
    )
