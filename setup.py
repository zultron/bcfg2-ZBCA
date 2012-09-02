#!/usr/bin/env python

import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
      name='Bcfg2-ZBCA',
      version='0.1.0',
      description='A Bcfg2 plugin to manage an SSL certificate authority',
      long_description=read('README'),
      author='John Morris',
      author_email='john@zultron.com',
      url='https://github.com/zultron/bcfg2-ZBCA',
      packages=['Bcfg2.Server.Plugins.ZBCA',
                ],
      install_requires=[
        'Bcfg2.Server',
        'OpenSSL',
        ],
      license='GPL v2+',
      classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Operating System :: POSIX',
        'Topic :: System :: Systems Administration',
        ],
      )
