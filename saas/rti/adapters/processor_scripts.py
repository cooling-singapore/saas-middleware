import json
import os
import subprocess

# TODO: Create cli interface for this script


def clone_repo(git_local_path: str, git_spec: dict):
    git_url = git_spec['source']
    commit_id = git_spec['commit_id']

    if not os.path.exists(git_local_path):  # Only clone if path does not exist
        subprocess.run(['git', 'clone', git_url, git_local_path], check=True)

    result = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=git_local_path, check=True, capture_output=True)
    current_commit_id = str(result.stdout)
    if not current_commit_id.startswith(commit_id):
        subprocess.run(['git', 'checkout', commit_id], cwd=git_local_path, check=True)


def get_repo_descriptor(local_git_path: str):
    descriptor_path = os.path.join(local_git_path, 'descriptor.json')
    if not os.path.exists(descriptor_path):
        raise FileNotFoundError(f'Could not find descriptor in path `{descriptor_path}`')

    with open(descriptor_path, 'r') as descriptor_file:
        descriptor = json.load(descriptor_file)

    return descriptor


def get_processor(local_git_path: str, git_spec: dict):
    processor_dir = os.path.join(local_git_path, git_spec['path'])

    processor_path = os.path.join(processor_dir, 'processor.py')
    descriptor_path = os.path.join(processor_dir, 'descriptor.json')

    if not os.path.exists(processor_path):
        raise FileNotFoundError(f'Could not find processor in path `{processor_path}`')
    if not os.path.exists(descriptor_path):
        raise FileNotFoundError(f'Could not find processor descriptor in path `{descriptor_path}`')

    with open(descriptor_path, 'r') as descriptor_file:
        descriptor = json.load(descriptor_file)

    return processor_path, descriptor


def install_dependencies(local_git_path: str, log_dir: str = None):
    repo_descriptor = get_repo_descriptor(local_git_path)

    install_scripts = repo_descriptor.get('install_scripts')
    requirements_file = repo_descriptor.get('requirements_file')

    # Run install scripts if found
    if install_scripts is not None:
        for script_relpath in install_scripts:
            script_path = os.path.join(local_git_path, script_relpath)
            if os.path.exists(script_path):
                # with open(script_path, 'rb') as f:
                #     script_contents = f.read()

                _, script_name = os.path.split(script_path)
                print(f"Running install script {script_name}")
                subprocess.run(['chmod', '+x', script_path], check=True)
                # FIXME: Using shell is insecure
                result = subprocess.run(script_path, shell=True, capture_output=True, check=True)

                # Print output of script
                for line in (result.stdout.decode("utf-8") ).split('\\n'):
                    print(line)
                for line in (result.stderr.decode("utf-8")).split('\\n'):
                    print(line)

                if log_dir:
                    # Save script output as log file
                    log_path = os.path.join(log_dir, f'script_{script_name}_log.txt')
                    with open(log_path, 'ab') as f:
                        f.write(result.stdout)
                        f.write(result.stderr)
            else:
                print(f"Install script {script_relpath} not found")

    # Create venv
    venv_path = os.path.join(local_git_path, 'venv')
    subprocess.run(['python', "-m", "venv", venv_path], check=True)

    # Install python dependencies if found
    if requirements_file is not None:
        requirements_file_path = os.path.join(local_git_path, requirements_file)
        if os.path.exists(requirements_file_path):
            venv_py_path = os.path.join(venv_path, 'bin', 'python')
            # Install dependencies into venv
            result = subprocess.run([venv_py_path, '-m', 'pip', 'install', '-r', requirements_file_path],
                                    capture_output=True, check=True)

            if log_dir:
                # Save script output as log file
                log_path = os.path.join(log_dir, f'requirements_file_log.txt')
                with open(log_path, 'ab') as f:
                    f.write(result.stdout)
                    f.write(result.stderr)
        else:
            print(f"Requirements file {requirements_file} not found")


def deploy_git_processor(local_git_path: str, git_spec: dict, log_dir: str = None):
    clone_repo(local_git_path, git_spec)
    install_dependencies(local_git_path, log_dir)
