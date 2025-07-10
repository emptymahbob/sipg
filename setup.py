#!/usr/bin/env python3
"""
Setup script for SIPG (Shodan IP Grabber)
A professional command-line tool for searching IP addresses using Shodan API
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="sipg",
    version="2.0.2",
    author="Mahbob Alam",
    author_email="emptymahbob@gmail.com",
    description="A professional command-line tool for searching IP addresses using Shodan API",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/emptymahbob/sipg",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",

        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP :: Indexing/Search",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Utilities",
    ],
    python_requires=">=3.7",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "sipg=sipg.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "sipg": ["*.json"],
    },
    keywords="shodan, ip, grabber, security, reconnaissance, network, api",
    project_urls={
        "Bug Reports": "https://github.com/emptymahbob/sipg/issues",
        "Source": "https://github.com/emptymahbob/sipg",
        "Documentation": "https://github.com/emptymahbob/sipg#readme",
    },
) 