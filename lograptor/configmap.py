#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module contains classes and methods to handle Lograptor configurations.
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
import logging
import string

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

from lograptor.exceptions import ConfigError, FileMissingError, FormatError


logger = logging.getLogger('lograptor')


class ConfigMap(UserDict):
    """
    This is a container class to manage environment configuration and options.
    """

    def __init__(self, cfgfile=None, default_config=None, extra_options=None, ):
        UserDict.__init__(self)

        # Setting defaults. Don't allows duplicates for default keys.
        self.defaults = {}
        if default_config is not None:
            logger.debug('Setting configuration defaults')
            for sect_defaults in default_config.values():
                for key, value in sect_defaults.items():
                    if key not in self.defaults:
                        self.defaults[key] = value
                    else:
                        msg = "Duplicate key '{0}' in defaults!".format(key)
                        raise ConfigError(msg)

        # Create the config parser instance, read & parse configuration file
        self.parser = configparser.RawConfigParser(dict_type=OrderedDict)
        try:
            if not os.path.isfile(cfgfile):
                msg = "Configuration file {0} not found!".format(cfgfile)
                raise FileMissingError(msg)
            self.parser.read(cfgfile)
        except configparser.ParsingError:
            raise FormatError('Could not parse configuration file %s!' % cfgfile)

        # Read configuration from file
        logger.debug('Reading other entries from configuration file')
        for sect, sect_options in default_config.items():
            # Skip unnamed (None) section
            if sect is None:
                continue

            for opt, value in sect_options.items():
                logger.debug("Get option '%s' from section '%s'" % (opt, sect))
                try:
                    if isinstance(value, bool):
                        self.data[opt] = self.parser.getboolean(sect, opt)
                    elif isinstance(value, int):
                        self.data[opt] = self.parser.getint(sect, opt)
                    elif isinstance(value, float):
                        self.data[opt] = self.parser.getfloat(sect, opt)
                    else:
                        self.data[opt] = self.parser.get(sect, opt).strip('\'"').replace('\n', '')
                except (configparser.NoSectionError, configparser.NoOptionError):
                    # If missing section/option then use default value
                    if not self.parser.has_section(sect):
                        self.parser.add_section(sect)
                    self.parser.set(sect, opt, self.defaults[opt])
                    self.data[opt] = self.defaults[opt]

            # Read additional options from cfgfile.
            if self.parser.has_section(sect):
                for opt in self.parser.options(sect):
                    if opt in sect_options:
                        continue
                    if opt not in self.data:
                        logger.debug("Add option '%s' from section '%s'" % (opt, sect))
                        self.data[opt] = self.parser.get(sect, opt).strip('\'"').replace('\n', '')
                    else:
                        # Don't allows duplicates in configuration file to avoid errors
                        msg = "Duplicate option '{0}' in configuration file!".format(opt)
                        raise KeyError(msg)

        # Update data with extra options (allows override of configuration
        # file options)
        logger.debug('Reading entries from extra options')
        if extra_options is not None:
            if isinstance(extra_options, dict):
                self.data.update(extra_options)
            else:
                self.data.update(vars(extra_options))

        # Interpolation for all strings. Also the default strings
        # are interpolated to mantain the equality comparisons.
        while True:
            changed = False
            for opt in self.data:
                if isinstance(self.data[opt], str):
                    new = self._interpolate(self.data[opt])
                    if new != self.data[opt]:
                        self.data[opt] = new
                        changed = True
            if not changed:
                break

        for opt, value in self.defaults.items():
            if isinstance(value, str):
                self.defaults[opt] = self._interpolate(value)

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
        if option in self.defaults:
            if self.defaults[option] is None:
                return self.data[option] is None
            return self.data[option] == self.defaults[option]
        else:
            raise KeyError('Option "{0}" is not in defaults'.format(option))

    def get_default(self, option):
        """
        Get the default value of an option
        """
        if option in self.defaults:
            return self.defaults[option]
        else:
            raise KeyError('Option "{0}" is not in defaults'.format(option))

    def getstr(self, section, option):
        """
        Get an option from a section of configuration file
        """
        try:
            return self.parser.get(section, option).strip('\'"').replace('\n', '')
        except configparser.NoOptionError:
            default = self.get_default(option) 
            if default is None:
                raise configparser.NoOptionError(option, section)
            return default        

    def getboolean(self, section, option):
        """
        Get a boolean option from a section of configuration file 
        """
        if not isinstance(self.defaults[option], bool):
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
        if not isinstance(self.defaults[option], int):
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
        if not isinstance(self.defaults[option], float):
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
