# -*- coding: utf-8 -*-
"""
This module classes and methods for parsing log headers.
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
import re
from collections import namedtuple
from .exceptions import LogRaptorConfigError


class LogParser(object):
    """
    Base class for building parsers for logs.
    """
    def __init__(self, pattern, app=None):
        """
        Compile the pattern and record group fields. Check if pattern
        include mandatory named groups.
        """
        self.parser = re.compile(pattern)
        self.app = app
        self.LogData = namedtuple('LogData', self.parser.groupindex.keys())
        self.fields = tuple(self.parser.groupindex.keys())

        for field in ('month', 'day', 'ltime', 'message'):
            if field not in self.parser.groupindex:
                msg = '%s: missing mandatory named group "%s"' % (self.__class__.__name__, field)
                raise LogRaptorConfigError(msg)

    def match(self, line):
        return self.parser.match(line)

    def get_data(self, match):
        return self.LogData(*map(match.group, self.fields))


class ParserRFC3164(LogParser):
    """
    Parser and extraction methods for BSD Syslog format (RFC 3164).
    """
    PATTERN = (r'^(?:<(?P<pri>[0-9]{1,3})>|)'
               r'(?P<month>[A-Z,a-z]{3}) (?P<day>(?:[1-3]| )[0-9]) '
               r'(?P<ltime>[0-9]{2}:[0-9]{2}:[0-9]{2}) '
               r'(?:last message repeated (?P<repeat>[0-9]{1,3}) times|'
               r'(?P<host>\S{1,255})\s+'
               r'(?P<message>(?P<apptag>[^ \[\(\:]{1,32})(?:[\[\(\:])?.*))')

    def __init__(self, pattern=None):
        LogParser.__init__(self, pattern or self.PATTERN)
        rfc3164_fields = tuple([
            'pri', 'month', 'day', 'ltime', 'repeat', 'host', 'apptag', 'message'
            ])
        extra = set(self.fields) - set(rfc3164_fields)
        if extra:
            msg = u'no RFC 3164 fields in pattern: {0}'.format(extra)
            raise LogRaptorConfigError(msg)
            

class ParserRFC5424(LogParser):
    """
    Parser for IETF-syslog logs (RFC 5424) .
    """
    PATTERN = (r'^(?:<(?P<pri>[0-9]{1,3})>(?P<ver>[0-9]{0,2}) |)'
               r'(?:-|(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})T)'
               r'(?P<ltime>[0-9]{2}:[0-9]{2}:[0-9]{2})(?:|\.(?P<secfrac>[0-9]{1,6}))'
               r'(?:Z |(?P<offset>(?:\+|-)[0-9]{2}:[0-9]{2}) )'
               r'(?:-|(?P<host>\S{1,255})) (?:-|(?P<apptag>\S{1,48})) '
               r'(?:-|(?P<procid>\S{1,128})) (?:-|(?P<msgid>\S{1,32})) '
               r'(?P<message>.*)')

    # The RFC5424 no-value
    NILVALUE = '-'

    def __init__(self, pattern=None):
        LogParser.__init__(self, pattern or self.PATTERN)
        rfc5424_fields = tuple([
            'pri', 'ver', 'year', 'month', 'day', 'ltime', 'secfrac', 'offset',
            'host', 'apptag', 'procid', 'msgid', 'message'
            ])
        extra = set(self.fields) - set(rfc5424_fields)
        if extra:
            msg = u'no RFC 5424 fields in pattern: {0}'.format(extra)
            raise LogRaptorConfigError(msg)


class CycleParsers(object):
    """
    Class that define an iterator for a set of parsers. The additional
    method "detect" permits to find the first parser suitable for the
    argument or return None in alternative.
    """
    PARSERS = [ParserRFC3164(), ParserRFC5424()]

    def __init__(self, parsers=None):
        self.parsers = parsers or self.PARSERS
        self.index = 0
        self.num_parsers = len(self.parsers)

    def __iter__(self):
        return self

    def __next__(self):
        self.index = (self.index + 1) % self.num_parsers
        return self.parsers[self.index]

    def next(self):
        return self.__next__()

    def detect(self, line):
        for i in range(self.num_parsers):
            parser = self.__next__()
            match = parser.match(line)
            if match is not None:
                return parser, match
        else:
            return None, None
