#!/usr/bin/env python
"""
Setup script for Lograptor
"""

import glob
import os
import shutil
import distutils.command.sdist
import distutils.command.build
import distutils.command.build_scripts
import distutils.command.bdist_rpm
import distutils.command.install
from distutils.core import setup


LONG_DESCRIPTION ="""
Lograptor is a syslog parser and searching tool which provide a command-line interface for manually or automated log
processing. Instant pattern matching are joinable with a set of common
filters and date/time range scope delimitation. Each search should
produce report that should be easllily send to you by email, or saved
into a filesystem directory. Lograptor take reporting ideas and part
of the code from Epylog, one of the most popular log analysis tools,
remixing all with other code developed by the author for Postfix's log
searches.
"""


class my_sdist(distutils.command.sdist.sdist):
    """
    Custom version of sdist command, to update master script
    and compressed version of manual pages.
    """
    
    def run(self):
        print("copy lograptor.py -> scripts/lograptor")
        shutil.copyfile("lograptor.py", "scripts/lograptor")
        print("compress man/lograptor.8 -> man/lograptor.8.gz")
        os.system('gzip -c man/lograptor.8 > man/lograptor.8.gz')
        print("compress man/lograptor.conf.5 -> man/lograptor.conf.5.gz")
        os.system('gzip -c man/lograptor.conf.5 > man/lograptor.conf.5.gz')
        print("compress man/lograptor-apps.5 -> man/lograptor-apps.5.gz")
        os.system('gzip -c man/lograptor-apps.5 > man/lograptor-apps.5.gz')
        distutils.command.sdist.sdist.run(self)


class my_build_scripts(distutils.command.build_scripts.build_scripts):

    def run(self):
        try:
            print("copy lograptor.py -> scripts/lograptor")
            shutil.copyfile("lograptor.py", "scripts/lograptor")
            print("compress man/lograptor.8 -> man/lograptor.8.gz")
            os.system('gzip -c man/lograptor.8 > man/lograptor.8.gz')
            print("compress man/lograptor.conf.5 -> man/lograptor.conf.5.gz")
            os.system('gzip -c man/lograptor.conf.5 > man/lograptor.conf.5.gz')
            print("compress man/lograptor-apps.5 -> man/lograptor-apps.5.gz")
            os.system('gzip -c man/lograptor-apps.5 > man/lograptor-apps.5.gz')
        except Exception as msg:
            print("Error in copying script: not in base dir, skip custom operations "
                  "in build_scripts subclass ...")
            
        distutils.command.build_scripts.build_scripts.run(self)    


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


class my_install(distutils.command.install.install):

    def run(self):
        distutils.command.install.install.run(self)
        os.system('cat INSTALLED_FILES | grep -v "/etc/lograptor" > INSTALLED_FILES.new')
        os.system('mv INSTALLED_FILES.new INSTALLED_FILES')

        
setup(name='lograptor',
      version='0.8b2',
      author='Davide Brunato',
      author_email='brunato@sissa.it',
      description='Command-line utility for searching into log files.',
      license='GPLv2+',
      maintainer='Davide Brunato',
      long_description=LONG_DESCRIPTION,
      url='https://github.com/brunato/Lograptor',
      packages=['lograptor','lograptor.backports'],
      scripts=['scripts/lograptor'],
      data_files=[('/usr/share/man/man8',['man/lograptor.8.gz']),
                  ('/usr/share/man/man5',['man/lograptor.conf.5.gz']),
                  ('/usr/share/man/man5',['man/lograptor-apps.5.gz']),
                  ('/etc/lograptor',['etc/lograptor/lograptor.conf',
                                     'etc/lograptor/report_template.html',
                                     'etc/lograptor/report_template.txt']),
                  ('/etc/lograptor/conf.d',glob.glob('etc/lograptor/conf.d/*.conf'))],
      requires = ['python (>=2.6)'],
      cmdclass = {"sdist": my_sdist,
                  "build_scripts": my_build_scripts,
                  "install" : my_install,
                  "bdist_rpm" : my_bdist_rpm},
      )
