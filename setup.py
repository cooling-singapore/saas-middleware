#!/usr/bin/env python
from setuptools import setup, find_packages

long_description = open('README.md').read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

version = '0.2.0-alpha'

setup(
    name='saas-middleware',
    version=version,
    install_requires=requirements,
    packages=find_packages(),
    include_package_data=True,
    url='https://github.com/cooling-singapore/saas-middleware',
    project_urls={
        'Source': 'https://github.com/cooling-singapore/saas-middleware',
        'Tracker': 'https://github.com/cooling-singapore/saas-middleware/issues',
    },
    license='MIT',
    description='Middleware for powering federation of digital twins',
    long_description=long_description,
    long_description_content_type='text/markdown',
    entry_points={
        'console_scripts': [
            'saas-cli = saas.cli.saas_cli:main',
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3'
        'License :: OSI Approved :: MIT License'
        'Operating System :: OS Independent'
    ],
)
