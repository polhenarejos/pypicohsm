# -*- coding: utf-8 -*-
"""
/*
 * This file is part of the pypicohsm distribution (https://github.com/polhenarejos/pypicohsm).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
"""

from setuptools import setup
from setuptools import find_packages

import re, sys
VERSIONFILE = 'picohsm/_version.py'
verstrline = open(VERSIONFILE, 'rt').read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    version = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

INSTALL_REQUIRES = [
    'setuptools',
    'cryptography>=3.3',
    'base58',
    'pyusb',
    'pycvc',
    'pyscard',
]

if sys.platform.startswith('win32'):
    INSTALL_REQUIRES.append("pywin32")

try:
    import pypandoc
    long_description = pypandoc.convert_file('README.md', 'rst')
except(IOError, ImportError):
    long_description = open('README.md').read()

setup(
    name='pypicohsm',
    packages=['picohsm','picohsm/tools'],
    version=version,
    description='Pico HSM for Python',
    license='GPLv3',
    license_files='LICENSE',
    author="Pol Henarejos",
    author_email='pol.henarejos@cttc.es',
    url='https://github.com/polhenarejos/pypicohsm',
    long_description=long_description,
    long_description_content_type='text/markdown',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
    install_requires=INSTALL_REQUIRES,
    include_package_data=True,
    entry_points={
        'console_scripts': [
        ],
    },
)
