#!/usr/bin/env python
"""
Setup script for lograptor
"""
#
# Copyright (C), 2011-2017, by SISSA - International School for Advanced Studies.
#
# This file is part of lograptor.
#
# Lograptor is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# file 'LICENSE' in the root directory of the present distribution
# for more details.
#
# @Author Davide Brunato <brunato@sissa.it>
#
import glob
import os
import os.path
import platform
import shutil

import distutils.command.sdist
import distutils.command.build
import distutils.command.build_scripts
import distutils.command.bdist_rpm
import distutils.command.install
from distutils.core import setup

import lograptor.info


distro_tags = {
    'centos': 'el',
    'redhat': 'el',
    'Ubuntu': 'ubuntu1'
    }

MAN_SOURCE_DIR = 'doc/_build/man/'
PDF_SOURCE_DIR = 'doc/_build/latex/'


class my_sdist(distutils.command.sdist.sdist):
    """
    Custom version of sdist command, to update master script
    and compressed version of manual pages.
    """
    
    def run(self):
        if os.path.isfile('lograptor.py'):
            if not os.path.isdir('scripts'):
                os.mkdir('scripts')
            print("Copy lograptor.py -> scripts/lograptor")
            shutil.copyfile("lograptor.py", "scripts/lograptor")

        print("Copy {0}lograptor.pdf -> doc/lograptor.pdf".format(PDF_SOURCE_DIR))
        os.system("cp -p {0}lograptor.pdf doc/lograptor.pdf".format(PDF_SOURCE_DIR))
        print("Compress {0}lograptor.8 -> man/lograptor.8.gz".format(MAN_SOURCE_DIR))
        os.system("gzip -c {0}lograptor.8 > man/lograptor.8.gz".format(MAN_SOURCE_DIR))
        print("Compress {0}lograptor.conf.5 -> man/lograptor.conf.5.gz".format(MAN_SOURCE_DIR))
        os.system("gzip -c {0}lograptor.conf.5 > man/lograptor.conf.5.gz".format(MAN_SOURCE_DIR))
        print("Compress {0}lograptor-apps.5 -> man/lograptor-apps.5.gz".format(MAN_SOURCE_DIR))
        os.system("gzip -c {0}lograptor-apps.5 > man/lograptor-apps.5.gz".format(MAN_SOURCE_DIR))
        print("Compress {0}lograptor-examples.8 -> man/lograptor-examples.8.gz".format(MAN_SOURCE_DIR))
        os.system("gzip -c {0}lograptor-examples.8 > man/lograptor-examples.8.gz".format(MAN_SOURCE_DIR))
        distutils.command.sdist.sdist.run(self)


class my_bdist_rpm(distutils.command.bdist_rpm.bdist_rpm):

    def _make_spec_file(self):
        """
        Customize spec file inserting %config section
        """
        spec_file = distutils.command.bdist_rpm.bdist_rpm._make_spec_file(self)
        spec_file.append('%config(noreplace) /etc/lograptor/lograptor.conf')
        spec_file.append('%config(noreplace) /etc/lograptor/report_template.*')
        spec_file.append('%config(noreplace) /etc/lograptor/conf.d/*.conf')
        return spec_file

    def initialize_options(self):
        distutils.command.bdist_rpm.bdist_rpm.initialize_options(self)
        distro = platform.linux_distribution()
        self.distribution_name = "{0} {1}".format(distro[0], distro[1].split('.')[0])

    def run(self):
        distutils.command.bdist_rpm.bdist_rpm.run(self)

        msg = 'moving {0} -> {1}'
        print('cd dist/')
        os.chdir('dist')
        files = glob.glob('*-[1-9].noarch.rpm') + glob.glob('*-[1-9][0-9].noarch.rpm')

        distro = platform.linux_distribution(full_distribution_name=False)
        distro_name = distro[0].lower()
        if distro_name in ['centos', 'redhat', 'fedora']:
            if distro_name == 'fedora':
                tag = '.fc' + distro[1].split('.')[0]
            else:
                tag = '.el' + distro[1].split('.')[0]
            for filename in files:
                new_name = filename[:-11] + tag + filename[-11:]
                print(msg.format(filename, new_name))
                os.rename(filename, new_name)

        elif distro_name in ['ubuntu', 'debian']:
            for filename in files:
                print('alien -k {0}'.format(filename))
                os.system('/usr/bin/alien -k {0}'.format(filename))
                print('removing {0}'.format(filename))
                os.unlink(filename)
                if distro[0] == 'Ubuntu':
                    filename = filename[:-11].replace('-', '_', 1) + '_all.deb'
                    new_name = filename[:-8] + 'ubuntu1_all.deb'
                    print(msg.format(filename, new_name))
                    os.rename(filename, new_name)
        

class my_install(distutils.command.install.install):

    def run(self):
        distutils.command.install.install.run(self)
        # os.system('cat INSTALLED_FILES | grep -v "/etc/lograptor" > INSTALLED_FILES.new')
        # os.system('mv INSTALLED_FILES.new INSTALLED_FILES')


setup(
    name='lograptor',
    version=lograptor.info.__version__,
    author=lograptor.info.__author__,
    author_email=lograptor.info.__email__,
    description=lograptor.info.__description__,
    license=lograptor.info.__license__,
    maintainer=lograptor.info.__maintainer__,
    long_description=lograptor.info.LONG_DESCRIPTION,
    url='https://github.com/brunato/lograptor',
    packages=['lograptor'],
    platform='linux2',
    package_data={
        'lograptor': [
            'README',
            'LICENSE',
            'doc/lograptor.pdf',
            'etc/lograptor/lograptor.conf',
            'etc/lograptor/report_template.html',
            'etc/lograptor/report_template.txt',
            'etc/lograptor/conf.d/*.conf',
            'man/lograptor*.gz',
            'lograptor/*.py',
        ],
    },
    data_files=[('/usr/share/man/man8', ['man/lograptor.8.gz']),
                ('/usr/share/man/man5', ['man/lograptor.conf.5.gz']),
                ('/usr/share/man/man5', ['man/lograptor-apps.5.gz']),
                ('/usr/share/man/man8', ['man/lograptor-examples.8.gz']),
                ('/etc/lograptor', [
                    'etc/lograptor/lograptor.conf',
                    'etc/lograptor/report_template.html',
                    'etc/lograptor/report_template.txt']),
                ('/etc/lograptor/conf.d', glob.glob('etc/lograptor/conf.d/*.conf'))],
    entry_points={
        'console_scripts': [
            'lograptor=lograptor.api:main'
        ]
    },
    requires=['python (>=2.7)'],
    cmdclass={
        "sdist": my_sdist,
        "install": my_install,
        "bdist_rpm": my_bdist_rpm
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Lesser General Public License v2.1 or later (LGPLv2.1+)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Internet :: Log Analysis',
        'Topic :: System :: Systems Administration',
        'Topic :: Text Processing :: Filters',
        'Topic :: Utilities'
    ]
)
