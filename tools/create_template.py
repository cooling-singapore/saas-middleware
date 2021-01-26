import argparse
import os
import shutil

from jinja2 import Environment, FileSystemLoader

template_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'template')


def create_folder_structure(output_path):
    shutil.copytree(os.path.join(template_directory, 'folder_structure'), output_path)


def generate_descriptor(processor_name: str, output_path: str):
    env = Environment(loader=FileSystemLoader(template_directory))
    template = env.get_template('descriptor_template.json')
    generated_code = template.render(name=processor_name)

    code_path = os.path.join(output_path, 'descriptor.json')
    with open(code_path, "w") as f:
        f.write(generated_code)


def create_template(args):
    processor_name = args.name
    output_dir = args.output
    output_folder = os.path.join(output_dir, processor_name)

    create_folder_structure(output_folder)
    generate_descriptor(processor_name, output_folder)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Processor Template Generator')

    # Add the arguments
    parser.add_argument('name', type=str, help='Name of Processor')
    parser.add_argument('output', type=str, help='Path to output generated files')
    args = parser.parse_args()
    create_template(args)




