#!/usr/bin/env python
"""
Setup script for Lograptor
"""

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
    'centos' : 'el',
    'redhat' : 'el',
    'Ubuntu' : 'ubuntu1'
    }

MAN_SOURCE_DIR = 'doc/_build/man/'
PDF_SOURCE_DIR = 'doc/_build/latex/'

class my_sdist(distutils.command.sdist.sdist):
    """
    Custom version of sdist command, to update master script
    and compressed version of manual pages.
    """
    
    def run(self):
        print("Copy lograptor.py -> scripts/lograptor")
        if not os.path.isdir('scripts'):
            os.mkdir('scripts')
        shutil.copyfile("lograptor.py", "scripts/lograptor")

        print("Copy {0}Lograptor.pdf -> doc/Lograptor.pdf".format(PDF_SOURCE_DIR))
        os.system("cp -p {0}Lograptor.pdf doc/Lograptor.pdf".format(PDF_SOURCE_DIR))
        print("Compress {0}lograptor.8 -> man/lograptor.8.gz".format(MAN_SOURCE_DIR))
        os.system("gzip -c {0}lograptor.8 > man/lograptor.8.gz".format(MAN_SOURCE_DIR))
        print("Compress {0}lograptor.conf.5 -> man/lograptor.conf.5.gz".format(MAN_SOURCE_DIR))
        os.system("gzip -c {0}lograptor.conf.5 > man/lograptor.conf.5.gz".format(MAN_SOURCE_DIR))
        print("Compress {0}lograptor-apps.5 -> man/lograptor-apps.5.gz".format(MAN_SOURCE_DIR))
        os.system("gzip -c {0}lograptor-apps.5 > man/lograptor-apps.5.gz".format(MAN_SOURCE_DIR))
        print("Compress {0}lograptor-examples.8 -> man/lograptor-examples.8.gz".format(MAN_SOURCE_DIR))
        os.system("gzip -c {0}lograptor-examples.8 > man/lograptor-examples.8.gz".format(MAN_SOURCE_DIR))
        distutils.command.sdist.sdist.run(self)


class my_build_scripts(distutils.command.build_scripts.build_scripts):

    def run(self):
        if os.path.isfile('lograptor.py'):
            if not os.path.isdir('scripts'):
                os.mkdir('scripts')
            print("Copy lograptor.py -> scripts/lograptor")
            shutil.copyfile("lograptor.py", "scripts/lograptor")

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

    def run(self):
        distutils.command.bdist_rpm.bdist_rpm.run(self)

        msg = 'moving {0} -> {1}'
        print('cd dist/')
        os.chdir('dist')
        filelist = glob.glob('*-[1-9].noarch.rpm') + glob.glob('*-[1-9][0-9].noarch.rpm') 

        distro = platform.dist()
        if distro[0] in ['centos', 'redhat']:
            tag = '.el' + distro[1].split('.')[0]
        elif distro[0] == 'fedora':
            tag = '.fc' + distro[1].split('.')[0]
        elif distro[0] == 'Ubuntu':
            tag = 'ubuntu1'
        
        if distro[0] in ['centos', 'redhat', 'fedora']:
            for filename in filelist:
                newname = filename[:-11] + tag + filename[-11:]
                print(msg.format(filename, newname))
                os.rename(filename, newname)
        elif distro[0] in ['Ubuntu', 'debian']:
            for filename in filelist:
                print('alien -k {0}'.format(filename))
                os.system('/usr/bin/alien -k {0}'.format(filename))
                print('removing {0}'.format(filename))
                os.unlink(filename)
                if distro[0] == 'Ubuntu':
                    filename = filename[:-11].replace('-', '_', 1) + '_all.deb'
                    newname = filename[:-8] + tag + '_all.deb'
                    print(msg.format(filename, newname))
                    os.rename(filename, newname)
        

class my_install(distutils.command.install.install):

    def run(self):
        distutils.command.install.install.run(self)
        os.system('cat INSTALLED_FILES | grep -v "/etc/lograptor" > INSTALLED_FILES.new')
        os.system('mv INSTALLED_FILES.new INSTALLED_FILES')

        
setup(name='lograptor',
      version=lograptor.info.__version__,
      author=lograptor.info.__author__,
      author_email=lograptor.info.__email__,
      description=lograptor.info.__description__,
      license=lograptor.info.__license__,
      maintainer=lograptor.info.__maintainer__,
      long_description=lograptor.info.LONG_DESCRIPTION,
      url='https://github.com/brunato/Lograptor',
      packages=['lograptor', 'lograptor.backports'],
      scripts=['scripts/lograptor'],
      data_files=[('/usr/share/man/man8', ['man/lograptor.8.gz']),
                  ('/usr/share/man/man5', ['man/lograptor.conf.5.gz']),
                  ('/usr/share/man/man5', ['man/lograptor-apps.5.gz']),
                  ('/usr/share/man/man8', ['man/lograptor-examples.8.gz']),
                  ('/etc/lograptor', ['etc/lograptor/lograptor.conf',
                                     'etc/lograptor/report_template.html',
                                     'etc/lograptor/report_template.txt']),
                  ('/etc/lograptor/conf.d', glob.glob('etc/lograptor/conf.d/*.conf'))],
      requires = ['python (>=2.6)'],
      cmdclass = {"sdist": my_sdist,
                  "build_scripts": my_build_scripts,
                  "install" : my_install,
                  "bdist_rpm" : my_bdist_rpm},
      )
