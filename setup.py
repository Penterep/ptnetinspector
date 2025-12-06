#!/usr/bin/env python3
from setuptools import setup, find_packages
from pathlib import Path

# Read the long description from README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = (this_directory / "requirements.txt").read_text(encoding='utf-8').splitlines()
# Filter out empty lines and comments
requirements = [req.strip() for req in requirements if req.strip() and not req.startswith('#')]

# Read version from _version.py without importing
version_file = this_directory / "ptnetinspector" / "_version.py"
version = None
with open(version_file) as f:
    for line in f:
        if line.startswith('__version__'):
            version = line.split('=')[1].strip().strip("'\"")
            break

if version is None:
    raise RuntimeError("Unable to find version string.")

setup(
    name='ptnetinspector',
    version=version,
    author='Penterep',
    author_email='info@penterep.com',
    description='A reconnaissance tool for IPv6/IPv4 local network scanning with vulnerability detection',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://www.penterep.com',
    project_urls={
        'Source': 'https://github.com/Penterep/ptnetinspector',
        'Bug Reports': 'https://github.com/Penterep/ptnetinspector/issues',
        'Homepage': 'https://www.penterep.com/',
    },
    packages=find_packages(exclude=['test', 'test.*', 'myenv', 'myenv.*', 'doc', 'doc.*']),
    package_data={
        'ptnetinspector': ['data/manuf'],
    },
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'ptnetinspector=ptnetinspector.main:main',
        ],
    },
    install_requires=requirements,
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Monitoring',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console',
    ],
    keywords='network scanner ipv6 security vulnerability-detection penetration-testing',
    license='GPLv3',
    zip_safe=False,
)