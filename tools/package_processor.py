import argparse
import gzip
import json
import os
import shutil
import docker


def package_docker(processor_path: str, verbose=False):
    """
    Takes in a Processor directory and builds a docker image. The docker image is exported as a .tar
    """
    client = docker.from_env()

    dockerfile_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'docker_build')

    # copy docker build files to a temp folder
    temp_folder = os.path.join(processor_path, '__tmp__')
    if os.path.exists(temp_folder):
        shutil.rmtree(temp_folder)
    os.makedirs(temp_folder)
    shutil.copy(os.path.join(dockerfile_directory, 'docker_wrapper.py'), os.path.join(temp_folder, 'docker_wrapper.py'))

    image, logs = client.images.build(path=processor_path,
                                      dockerfile=os.path.join(dockerfile_directory, 'Dockerfile'),
                                      rm=True)

    if verbose:
        # print docker build logs
        for log in logs:
            stream = log.get('stream')
            if stream is not None and stream != '\n':
                print(stream.strip('\n'))

    image_hash = image.id.split(':')[1]

    build_path = os.path.join(processor_path, 'builds', 'docker')
    if not os.path.exists(build_path):
        os.makedirs(build_path)

    with open(os.path.join(processor_path, 'descriptor.json')) as f:
        descriptor = json.load(f)
        descriptor['type'] = 'docker'

    descriptor_output_path = os.path.join(build_path, 'docker_descriptor.json')
    with open(descriptor_output_path, 'w') as f:
        json.dump(descriptor, f)

    image_output_path = os.path.join(build_path, f'{image_hash}.tar.gz')
    with gzip.GzipFile(image_output_path, "wb") as f:
        for chunk in image.save():
            f.write(chunk)
    print(f'Docker package exported to: {image_output_path}')

    # remove image from docker once saved as .tar
    client.images.remove(image.id)

    # cleanup
    shutil.rmtree(temp_folder)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Processor Packaging Tool')

    # Add the arguments
    parser.add_argument('type', type=str, help='Packaging Type')
    parser.add_argument('processor_path', type=str, help='Path to Processor')
    parser.add_argument('-v', '--verbose', type=bool, help='Show logs')
    args = parser.parse_args()

    if args.type == 'docker':
        package_docker(args.processor_path, args.verbose)


