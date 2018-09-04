# -*- coding: utf-8 -*-
"""
This module contains classes and methods to handle lograptor configurations.
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
import string
import socket
import re

try:
    import configparser
except ImportError:
    # Fall back for Python 2.x
    import ConfigParser as configparser
finally:
    RawConfigParser = configparser.RawConfigParser

from .exceptions import LogRaptorNoSectionError, LogRaptorNoOptionError, FileMissingError


class EnvInterpolation(object):
    _KEYCRE = re.compile(r"%\(([^)]+)\)s")

    def before_get(self, parser, section, option, value, defaults):
        L = []
        self._interpolate_some(parser, option, L, value, section, defaults, 1)
        return ''.join(L)

    def before_set(self, parser, section, option, value):
        tmp_value = value.replace('%%', '')  # escaped percent signs
        tmp_value = self._KEYCRE.sub('', tmp_value)  # valid syntax
        if '%' in tmp_value:
            raise ValueError("invalid interpolation syntax in %r at "
                             "position %d" % (value, tmp_value.find('%')))
        return value

    def before_read(self, parser, section, option, value):
        return value

    def before_write(self, parser, section, option, value):
        return value

    def _interpolate_some(self, parser, option, accum, rest, section, map, depth):
        rawval = parser.get(section, option, raw=True)
        if rawval:
            accum.append(string.Template(rawval).safe_substitute(parser.env))


class EnvConfigParser(RawConfigParser):
    """
    Environment-based configuration parser.

    It uses a 2-level dictionary for default values and to determine non-string
    option types. String type values are stripped by quotes and spaces. Configuration
    is determined by specific settings and complemented by a configuration file or a by
    default values. The env keyword arguments dictionary defines the values considered
    for the interpolation.

    :param settings: A two-level dictionary with customized sections and options.
    :param cfgfiles: A list of file paths where search for a configuration file or a \
    string with a path to a configuration file.
    :param defaults: A two-level dictionary with default settings.
    :param env: Environment values passed as keyword arguments.
    """
    _DEFAULT_INTERPOLATION = EnvInterpolation()
    optionxform = str  # Case sensitive option names

    _DEFAULTS = {}

    # noinspection PyMissingConstructor
    def __init__(self, settings=None, cfgfiles=None, defaults=None, **env):
        RawConfigParser.__init__(self, defaults=None, allow_no_value=False)
        self.__defaults = defaults if defaults is not None else self._DEFAULTS
        self.env = env
        self._interpolation = self._DEFAULT_INTERPOLATION   # Python 2.7 compatibility

        if cfgfiles:
            self.cfgfile = self.read_first(cfgfiles)
        else:
            self.cfgfile = None

        if settings is not None:
            self.read_dict(settings, 'settings')

    def __repr__(self):
        return u'%s(cfgfile=%r)' % (self.__class__.__name__, self.cfgfile)

    def defaults(self):
        return self.__defaults

    def get_default(self, section, option):
        try:
            return self.__defaults[section][option]
        except KeyError:
            return None

    def read_first(self, filenames):
        for filename in filenames if isinstance(filenames, (list, tuple)) else [filenames]:
            try:
                with open(filename) as fp:
                    try:
                        self.readfp(fp)
                    except AttributeError:
                        getattr(self, 'read_file')(fp)
            except IOError:
                pass
            else:
                return filename
        else:
            raise FileMissingError(
                "no configuration file in the list {} exists or is accessible!".format(filenames)
            )

    def get(self, section, option, default_section=None, raw=False, vars=None):
        if default_section is None:
            default_section = section

        used_defaults = False
        if section in self._sections:
            try:
                value = self._sections[section][option]
            except KeyError:
                try:
                    value = self.__defaults[default_section][option]
                    used_defaults = True
                except KeyError:
                    raise LogRaptorNoOptionError(option, section)

        elif default_section not in self.__defaults:
            raise LogRaptorNoSectionError(section)
        else:
            try:
                value = self.__defaults[default_section][option]
                used_defaults = True
            except KeyError:
                raise LogRaptorNoOptionError(option, section)

        if raw or value is None:
            return value
        elif used_defaults:
            options = self.options(section)
            return self._interpolation.before_get(self, default_section, option, value, options)
        else:
            options = self.options(section)
            return self._interpolation.before_get(self, section, option, value, options)

    def _get(self, section, conv, option, **kwargs):
        return conv(self.get(section, option))

    def getint(self, section, option, default_section=None):
        try:
            return RawConfigParser.getint(self, section, option)
        except configparser.NoOptionError:
            if default_section is None:
                raise
            return RawConfigParser.getint(self, default_section, option)

    def getfloat(self, section, option, default_section=None):
        try:
            return RawConfigParser.getfloat(self, section, option)
        except configparser.NoOptionError:
            if default_section is None:
                raise
            return RawConfigParser.getfloat(self, default_section, option)

    def getboolean(self, section, option, default_section=None):
        try:
            return RawConfigParser.getboolean(self, section, option)
        except configparser.NoOptionError:
            if default_section is None:
                raise
            return RawConfigParser.getboolean(self, default_section, option)

    def read_dict(self, dictionary, source='<dict>'):
        for section, options in dictionary.items():
            section = str(section)
            try:
                self.add_section(section)
            except (configparser.DuplicateSectionError, ValueError):
                pass

            for key, value in options.items():
                if value is not None:
                    default = self.get_default(section, key)
                    if isinstance(value, type(default)):
                        raise TypeError(' '.join([
                            "While reading from ", repr(source), ": wrong type for option ", repr(key),
                            " in section ", repr(section), ", ", repr(type(default)), "expected."
                        ]))
                    value = str(value)
                self.set(section, key, value)

    def options(self, section, prefix='', suffix='', default_section=None):
        try:
            opts = self._sections[section].copy()
        except KeyError:
            try:
                opts = self.__defaults[default_section or section].copy()
            except KeyError:
                raise LogRaptorNoSectionError(section)
        else:
            try:
                opts.update(self.__defaults[default_section or section])
            except KeyError:
                pass

        if '__name__' in opts:
            del opts['__name__']
        return list(filter(lambda x: x.startswith(prefix) and x.endswith(suffix), opts.keys()))

    def sections(self, prefix='', suffix=''):
        sections = self.__defaults.copy()
        sections.update(self._sections)
        return list(filter(lambda x: x.startswith(prefix) and x.endswith(suffix), sections.keys()))

    def items(self, section, raw=False, vars_=None):
        try:
            opts = self.__defaults[section].copy()
        except KeyError:
            opts = {}

        try:
            opts.update(self._sections[section])
        except KeyError:
            raise LogRaptorNoSectionError(section)

        if vars_:
            for key, value in vars_.items():
                opts[key] = value
        if '__name__' in opts:
            del opts['__name__']

        if raw:
            return [(k, opts[k]) for k in opts.keys()]
        else:
            return [
                (k, self._interpolation.before_get(self, section, k, opts[k], opts))
                for k in opts.keys()
            ]


class LogRaptorConfig(EnvConfigParser, object):
    _DEFAULTS = {
        'main': {
            'confdir': './conf.d/',
            'tmpdir': '/var/tmp/',
            'logdir': '/var/log/',
            'logfile': '/var/log/lograptor.log',
            'email_address': 'root@{0}'.format(socket.gethostname()),
            'smtp_server': '/usr/sbin/sendmail -t',
            'encodings': 'utf_8, latin1, latin2',
            'mapexp': 4,
        },
        'patterns': {
            'ASCII': r'[\x01-\x7f]*',
            'DNSNAME': r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*'
                       r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\b',
            'IPV4_ADDRESS': r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
            'IPV6_ADDRESS': r'(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}'
                            r'(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}'
                            r'(?: (?<=::)|(?<!:)|(?<=:) (?<!::) :)|'
                            r'(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)'
                            r'(?: \.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})',
            'USERNAME': r'[A-Za-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&\'*+/=?^_`{|}~-]+)*',
            'EMAIL': r'(?:|${USERNAME}|"${ASCII}")'
                     r'(?:|@(?:${DNSNAME}|\[(?:${IPV4_ADDRESS}|${IPV6_ADDRESS})\]))+',
            'ID': r'[0-9]+',
        },
        'fields': {
            'user': r'(|${USERNAME})',
            'mail': r'${EMAIL}',
            'from': r'${EMAIL}',
            'rcpt': r'${EMAIL}',
            'client': r'(${DNSNAME}|${IPV4_ADDRESS}|'
                      r'${DNSNAME}\[${IPV4_ADDRESS}\])',
            'pid': r'${ID}',
            'uid': r'${ID}',
            'msgid': r'${ASCII}',
        },
        # Reports
        'default_report': {
            'title': '${host} system events: ${localtime}',
            'html_template': './report_template.html',
            'text_template': './report_template.txt',
            'login_subreport': 'Logins',
            'mail_subreport': 'Mail report',
            'command_subreport': 'System commands',
            'query_subreport': 'Database lookups',
        },
        # Channels
        'stdout_channel': {
            'type': 'tty',
            'formats': 'text',
        },
        'mail_channel': {
            'type': 'mail',
            'formats': 'text, html, csv',
            'mailto': 'root',
            'include_rawlogs': 'False',
            'rawlogs_limit': '200',
            'gpg_encrypt': 'False',
            'gpg_keyringdir': '/root/.gnupg',
            'gpg_recipients': '',
            'gpg_signers': '',
        },
        'file_channel': {
            'type': 'file',
            'formats': 'text, html, csv',
            'notify': '',
            'pubdir': '/var/www/lograptor',
            'dirmask': '%Y-%b-%d_%a',
            'filemask': '%H%M',
            'save_rawlogs': 'False',
            'expire_in': '7',
            'pubroot': 'http://localhost/lograptor',
        }
    }

    def get_subreports(self, report):
        return [
            opt[:-10] for opt in self.options('%s_report' % report, suffix='_subreport')
        ]


class AppConfig(EnvConfigParser, object):
    _DEFAULTS = {
        'main': {
            'description': '${appname}',
            'tags': '${appname}',
            'sources': '${logdir}/messages',
            'enabled': True,
            'priority': 1,
        }
    }
