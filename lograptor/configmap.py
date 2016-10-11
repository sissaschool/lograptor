# -*- coding: utf-8 -*-
"""
This module contains classes and methods to handle Lograptor configurations.
"""
#
# Copyright (C), 2011-2016, by SISSA - International School for Advanced Studies.
#
# This file is part of Lograptor.
#
# Lograptor is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# See the file 'LICENSE' in the root directory of the present
# distribution or http://www.gnu.org/licenses/gpl-2.0.en.html.
#
# @Author Davide Brunato <brunato@sissa.it>
#
import logging
import string
import copy

try:
    import configparser
except ImportError:
    # Fall back for Python 2.x
    import ConfigParser as configparser

from collections import OrderedDict
from .exceptions import NoSectionError, NoOptionError, FileMissingError

logger = logging.getLogger(__name__)


class ConfigMap(object):
    """
    This is a container class to manage structured configurations.
    It uses a default 2-level dictionary to store default values and
    to determine the option types. String type values are stripped by quotes and
    spaces. The base_sections and the env keywords arguments defines the values
    considered for the interpolation, considering the options of the sections passed.
    """
    def __init__(self, cfgfiles, defaults=None, base_sections=None, **env):
        defaults = defaults or {}
        base_sections = base_sections or {}

        self.config = {}
        self.defaults = copy.deepcopy(defaults)
        self.parser = configparser.RawConfigParser(dict_type=OrderedDict)
        self.base_sections = base_sections
        self.env = env
        self.cfgfile = ', '.join(self.parser.read(cfgfiles))

        if not self.cfgfile:
            raise FileMissingError("no configuration file found in paths: %r" % cfgfiles)

        # Read default sections from configuration file
        for sect, options in defaults.items():
            self.config[sect] = dict()
            for opt, value in options.items():
                try:
                    if isinstance(value, bool):
                        self.config[sect][opt] = self.parser.getboolean(sect, opt)
                    elif isinstance(value, int):
                        self.config[sect][opt] = self.parser.getint(sect, opt)
                    elif isinstance(value, float):
                        self.config[sect][opt] = self.parser.getfloat(sect, opt)
                    else:
                        self.config[sect][opt] = self.parser.get(sect, opt).strip('\'"').replace('\n', '')
                except (configparser.NoSectionError, configparser.NoOptionError):
                    # If missing section/option then use the default value
                    if not self.parser.has_section(sect):
                        self.parser.add_section(sect)
                    self.parser.set(sect, opt, self.defaults[sect][opt])
                    self.config[sect][opt] = self.defaults[sect][opt]

            # Add options not in defaults
            for opt, value in self.parser.items(sect):
                if opt not in options:
                    self.config[sect][opt] = value

            # Update environment if it's a base section
            if sect in base_sections:
                self.env.update(self.config[sect])

        self._interpolate()

    @staticmethod
    def _get(config, section, option):
        try:
            sect = config[section]
        except KeyError:
            try:
                sect = config['%s.default' % section.split('.', 1)[0]]
            except KeyError:
                raise NoSectionError(section)

        try:
            return sect[option]
        except KeyError as err:
            raise NoOptionError(section, err)

    def _interpolate(self, env=None):
        """
        Make string interpolation using an environment dict.

        :param env: The environment dictionary.
        """
        env = env or self.env
        while True:
            changed = False
            for sect_name, section in self.config.items():
                for opt, value in filter(lambda x: isinstance(x[1], str), section.items()):
                    if string.Template(value).safe_substitute({opt: value}) == value:
                        new = string.Template(value).safe_substitute(env)
                        if new != value:
                            section[opt] = new
                            self.defaults[sect_name][opt] = new
                            self.parser.set(sect_name, opt, new)
                            changed = True
            if not changed:
                break

    def get_default(self, section, option):
        try:
            return self._get(self.defaults, section, option)
        except (NoSectionError, NoOptionError):
            return None

    def is_default(self, section, option):
        default = self.get_default(section, option)
        if default is None:
            return self.config[option] is None
        else:
            return self.config[section][option] == default

    def getstr(self, section, option):
        default = self.get_default(section, option)
        if default is not None and not isinstance(default, str) and not isinstance(default, type(u'')):
            raise TypeError("option %r of section %r: not a string!" % (option, section))
        try:
            value = self._get(self.config, section, option)
            return value.strip('\'"').replace('\n', '')
        except (NoOptionError, NoSectionError):
            if default is None:
                raise
            return default

    def getbool(self, section, option):
        default = self.get_default(section, option)
        if default is not None and not isinstance(default, bool):
            raise TypeError("option %r of section %r: not a boolean!" % (option, section))
        try:
            return bool(self._get(self.config, section, option))
        except (NoOptionError, NoSectionError):
            if default is None:
                raise
            return default

    def getint(self, section, option):
        default = self.get_default(section, option)
        if default is not None and not isinstance(default, int):
            raise TypeError("option %r of section %r: not an integer!" % (option, section))
        try:
            return int(self._get(self.config, section, option))
        except (NoOptionError, NoSectionError):
            if default is None:
                raise
            return default

    def getfloat(self, section, option):
        default = self.get_default(section, option)
        if default is not None and not isinstance(default, float):
            raise TypeError("option %r of section %r: not a string!" % (option, section))
        try:
            return float(self._get(self.config, section, option))
        except (NoOptionError, NoSectionError):
            if default is None:
                raise
            return default

    def options(self, section):
        return self.parser.options(section)

    def sections(self):
        return self.parser.sections()

    def items(self, section):
        return self.parser.items(section)
