"""
This module contains classes and methods to handle Lograptor environment variables.
"""
##
# Copyright (C) 2012-2014 by SISSA and Davide Brunato
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# @Author Davide Brunato <brunato@sissa.it>
##

import os
import re
import logging
import string
import socket

try:
    from collections import UserDict
except ImportError:
    # Fall back for Python 2.x
    from UserDict import IterableUserDict as UserDict

try:
    import configparser
except ImportError:
    # Fall back for Python 2.x
    import ConfigParser as configparser

try:
    from collections import OrderedDict
except ImportError:
    # Backport for Python 2.4-2.6 (from PyPI)
    from lograptor.backports.ordereddict import OrderedDict

import lograptor.__init__ as lograptor


logger = logging.getLogger('lograptor')


class ConfigMap(UserDict):
    """
    This is a container class to manage Lograptor environment configuration and options.
    """

    # Fixed sections in the config file
    _cfgfile_sections = {
        'main' : ('cfgdir', 'logdir', 'tmpdir', 'pidfile',
                  'fromaddr', 'smtpserv',),
        'patterns' : ('rfc3164_pattern', 'rfc5424_pattern', 'dnsname_pattern',
                      'ipaddr_pattern', 'email_pattern', 'username_pattern',
                      'pid_pattern',),
        'filters' : ('user', 'from', 'rcpt', 'client', 'pid'),  
        'report' : ('title', 'html_template', 'text_template', ), 
        'subreports' : ()
        }

    def __init__(self, cfgfile=None, options=None):
        UserDict.__init__(self)

        # Defaults for the configuration file
        self._cfgfile_defaults = {
            # options of the section 'main'
            'cfgdir' : '/etc/lograptor/',
            'logdir' : '/var/log',
            'tmpdir' : '/var/tmp',
            'pidfile' : "/var/run/lograptor.pid",
            'fromaddr' : 'root@{0}'.format(socket.gethostname()),
            'smtpserv' : '/usr/sbin/sendmail -t',

            # options of the section 'patterns'
            'rfc3164_pattern' : r'^(?:<(?P<pri>[0-9]{1,3})>|)'
                r'(?P<month>[A-Z,a-z]{3}) (?P<day>(?:[1-3]| )[0-9]) '
                r'(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}) '
                r'(?:last message repeated (?P<repeat>[0-9]{1,3}) times|'
                r'(?P<host>\S{1,255}) (?P<datamsg>(?P<tag>[^ \[\(\:]{1,32}).*))',
            'rfc5424_pattern' : r'^(?:<(?P<prix>[0-9]{1,3})>(?P<ver>[0-9]{0,2}) |)'
                r'(?:-|(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T)'
                r'(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})(?:|\.(?P<secfrac>[0-9]{1,6}))'
                r'(?:Z |(?P<offset>(?:\+|-)[0-9]{2}:[0-9]{2}) )'
                r'(?:-|(?P<host>\S{1,255})) (?P<datamsg>(?:-|(?P<tag>\S{1,48})) .*)',
            'dnsname_pattern' : r'((\b[a-zA-Z]\b|\b[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9]\b)\.)'
                r'*(\b[A-Za-z]\b|\b[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9]\b)',
            'ipaddr_pattern' : r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))',
            'email_pattern' : r'\b([\=A-Za-z0-9!$%&*+_~-]+(?:\.[\=A-Za-z0-9!$%&*+_~-]+)*)(@(?:[A-Za-z0-9]'
                r'(?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)?\b',
            'username_pattern' : r'\b([A-Za-z0-9!$%&*+_~-]+(?:\.[A-Za-z0-9!$%&*+_~-]+)*)'
                r'(@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)?\b',
            'pid_pattern' : r'[0-9]+',

            # options of the section 'filters'
            'user' : r'${username_pattern}',
            'from' : r'${email_pattern}',
            'rcpt' : r'${email_pattern}',
            'client' : r'(${dnsname_pattern}|${ipaddr_pattern})',
            'pid' : r'${pid_pattern}',

            # options of the section 'report'
            'title' : '$hostname system events: $localtime',
            'html_template' : '$cfgdir/report_template.html',
            'text_template' : '$cfgdir/report_template.txt',

            # options of the section 'subreports'
            'logins_report' : 'Logins',
            'mail_report' : 'Message delivery',
            'command_report' : 'System commands',
            'query_report': 'Database & directory lookups',

            # options for all publisher sections 
            'method' : None,
            'mailto' : 'root',
            # options for mail publisher sections
            'include_rawlogs' : False,
            'rawlogs_limit' : 200,
            'gpg_encrypt' : False,
            'gpg_keyringdir' : None,
            'gpg_recipients' : None,
            # options for file publisher sections
            'pubdir' : '/var/www/lograptor',
            'dirmask' : '%Y-%b-%d_%a',
            'filemask' :'%H%M',
            'save_rawlogs' : False,
            'expire_in' : 7,
            'notify' : '',
            'pubroot' : 'http://localhost/lograptor'
            }
        
        # Defaults for command line options
        self._options_defaults = {
            # General options
            'cfgfile' : "/etc/lograptor/lograptor.conf",
            'loglevel': 1,

            # Scope options
            'hosts' : "*",
            'apps' : '',
            'period' : None,
            'timerange' : None,

            # Matching control options
            'pattern' : None,
            'pattern_file' : None,
            'case' : False,
            'invert' : False,
            'filter' : None,
            'thread' : False,
            'unparsed' : False,

            # Output control options
            'count' : False,
            'max_count' : None,
            'quiet' : False,
            'no_messages' : False,
            'out_filenames' : None,

            # Report control options
            'report' : None,
            'format' : 'plain',
            'publish' : None,
            'ip_lookup' : False,
            'uid_lookup' : False
            }

        # Create the config parser instance, read & parse configuration file        
        self.parser = configparser.RawConfigParser(dict_type=OrderedDict)
        try:
            if not os.path.isfile(cfgfile):
                msg = "Configuration file {0} not found!".format(cfgfile)
                raise lograptor.OptionError('cfgfile', msg)
            self.parser.read(cfgfile)
        except configparser.ParsingError:
            raise FormatError('Could not parse configuration file {0}'
                              .format(self.data['cfgfile']))

        logger.debug('Reading entries from configuration file')
        for sect,sect_options in self._cfgfile_sections.items():
            
            # If option list is empty, read option list from cfgfile.
            if not sect_options:
                sect_options = self.parser.options(sect)

            # Reverse to put the setting of options in correct order
            #sect_options.reverse()
            
            for opt in sect_options:
                try:
                    if isinstance(self._cfgfile_defaults[opt], bool):
                        self.data[opt] = self.parser.getboolean(sect, opt)
                    elif isinstance(self._cfgfile_defaults[opt], int):
                        self.data[opt] = self.parser.getint(sect, opt)
                    elif isinstance(self._cfgfile_defaults[opt], float):
                        self.data[opt] = self.parser.getfloat(sect, opt)
                    else:
                        self.data[opt] = self.parser.get(sect, opt).strip('\'"')
                except KeyError:
                    self.data[opt] = self.parser.get(sect, opt)
                except configparser.NoOptionError as s:
                    logger.debug('No option "{0}" in section "{1}": use default.'.format(opt, sect))    
                    self.parser.set(sect,opt,self._cfgfile_defaults[opt])
                    self.data[opt] = self._cfgfile_defaults[opt]
                except configparser.NoSectionError:
                    logger.debug('No section "{0}" in the configuration file'.format(sect))        
                    self.parser.add_section(sect)
                    self.parser.set(sect,opt,self._cfgfile_defaults[opt])
                    self.data[opt] = self._cfgfile_defaults[opt]
        
        logger.debug('Reading entries from options')
        for opt in self._options_defaults:
            self.data[opt] = self._options_defaults[opt]
            if options is not None:
                try:
                    if isinstance(options, dict):
                        if option[opt] is not None:
                            self.data[opt] = options[opt]
                    elif getattr(options, opt) is not None:
                        self.data[opt] = getattr(options, opt)
            
                except (KeyError, AttributeError):
                    logger.debug('Option "{0}" not passed'.format(opt))
                    continue

        # Interpolation for all strings. Also the default strings
        # are interpolated to mantain the equality comparisons.        
        for opt in self.data:
            if isinstance(self.data[opt], str):
                self.data[opt] = self._interpolate(self.data[opt])
                
        for opt in self._options_defaults:
            if isinstance(self._options_defaults[opt], str):
                self._options_defaults[opt] = self._interpolate(self._options_defaults[opt])
        
        for opt in self._cfgfile_defaults:
            if isinstance(self._cfgfile_defaults[opt], str):
                self._cfgfile_defaults[opt] = self._interpolate(self._cfgfile_defaults[opt]) 

        self.paths = {
            'cfgdir' : self.data['cfgdir'],
            'logdir' : self.data['logdir'],
            'tmpdir' : self.data['tmpdir'],
            }

    def _interpolate(self, option):
        """
        Make an option interpolation using UserDict data dictionary
        """
        return string.Template(option).safe_substitute(self.data)
        
    def __setitem__(self, option, value):
        """
        Setting an option. Do nothing if the option's value is None, so
        an option with a default value not None, cannot be assigned with
        None.
        """
        if value is None:
            return
        if option in self:
            del self[option]
        else:
            raise KeyError("Key {0} not in options".format(option))
        UserDict.__setitem__(self, option, value)

    def is_default(self, option):
        """
        Compare key value with the default
        """
        if option in self._options_defaults:
            return self.data[option]==self._options_defaults[option]
        elif option in self._cfgfile_defaults:
            if self._cfgfile_defaults[option] is None:
                return self.data[option] is None
            return self.data[option]==self._cfgfile_defaults[option]
        else:
            raise KeyError('Option "{0}" is not in defaults'.format(option))


    def get_default(self, option):
        """
        Get the default value of an option
        """
        if option in self._options_defaults:
            return self._options_defaults[option]
        elif option in self._cfgfile_defaults:
            return self._cfgfile_defaults[option]
        else:
            raise KeyError('Option "{0}" is not in defaults'.format(option))

    def get(self, section, option):
        """
        Get an option from a section of configuration file
        """
        try:
            return self.parser.get(section, option)
        except configparser.NoOptionError:
            default = self.get_default(option) 
            if default is None:
                raise configparser.NoOptionError(option, section)
            return default        

    def getboolean(self, section, option):
        """
        Get a boolean option from a section of configuration file 
        """
        if not isinstance(self._cfgfile_defaults[option], bool):        
            raise TypeError('"{0}" not a boolean option!!'.format(option))

        try:
            return self.parser.getboolean(section, option)
        except configparser.NoOptionError:
            default = self.get_default(option) 
            if default is None:
                raise configparser.NoOptionError(option, section)
            return default


    def getint(self, section, option):
        """
        Get an integer option from a section of configuration file 
        """
        if not isinstance(self._cfgfile_defaults[option], int):        
            raise TypeError('"{0}" not an integer option!!'.format(option))

        try:
            return self.parser.getint(section, option)
        except configparser.NoOptionError:
            default = self.get_default(option) 
            if default is None:
                raise configparser.NoOptionError(option, section)
            return default
        

    def getfloat(self, section, option):
        """
        Get a floating point option from a section of configuration file 
        """
        if not isinstance(self._cfgfile_defaults[option], float):        
            raise TypeError('"{0}" not a floating point option!!'.format(option))

        try:
            return self.parser.getfloat(section, option)
        except configparser.NoOptionError:
            default = self.get_default(option) 
            if default is None:
                raise configparser.NoOptionError(option, section)
            return default

    def options(self, section):
        """
        Get the options list for a section of configuration file
        """    
        return self.parser.options(section)
