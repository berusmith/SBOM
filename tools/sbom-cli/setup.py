#!/usr/bin/env python3
"""Setup for SBOM CLI tool."""

from setuptools import setup

setup(
    name='sbom-cli',
    version='0.1.0',
    description='SBOM CLI tool for CI/CD integration',
    author='SBOM Team',
    python_requires='>=3.9',
    py_modules=['sbom'],
    entry_points={
        'console_scripts': [
            'sbom=sbom:main',
        ],
    },
    long_description=open('README.md', encoding='utf-8').read() if __import__('os').path.exists('README.md') else '',
    long_description_content_type='text/markdown',
)
