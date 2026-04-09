"""
This module defines classes and methods for parsing log headers.
"""
#
# Copyright (C), 2011-2026, by SISSA - International School for Advanced Studies.
#
# This file is part of lograptor.
#
# Lograptor is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License or (at your option) any later version.
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
from collections.abc import Sequence
from typing import NamedTuple, TYPE_CHECKING, ClassVar

from lograptor.exceptions import LogRaptorConfigError

if TYPE_CHECKING:
    from lograptor.application import AppRule


class LogData(NamedTuple):
    """Base log data namedtuple, used for type annotations."""
    app: str
    host: str
    message: str


_registered_parsers: dict[str, type['LogParser']] = {}


class LogParser:
    """
    Base class for building parsers for logs. It cannot be used directly. Define subclasses
    for each parsing log type with a specific pattern.

    :param app: Optional related AppRule to use the parser instance only with a specific app.

    :cvar PATTERN: Pattern to match logs, optional in subclasses.

    """
    NAME: ClassVar[str]
    PATTERN: ClassVar[str]

    parser: ClassVar[re.Pattern[str]]
    fields: ClassVar[tuple[str, ...]]
    LogData: ClassVar[type[tuple[str, ...]]]

    def __init_subclass__(cls, **kwargs):
        cls.parser = re.compile(cls.PATTERN)
        cls.fields = tuple(cls.parser.groupindex.keys())
        cls.LogData = namedtuple('LogData', cls.fields)

        if cls.NAME in _registered_parsers:
            raise TypeError('parser name already registered: %r' % cls.NAME)
        _registered_parsers[cls.NAME] = cls

    def __init__(self, app: 'AppRule | None' = None):
        self.app = app
        if self.__class__ is LogParser:
            raise TypeError('LogParser is an abstract class')

    @classmethod
    def match(cls, line: str) -> 're.Match[str] | None':
        return cls.parser.match(line)

    @classmethod
    def get_data(cls, match: 're.Match[str]') -> tuple[str, ...]:
        return cls.LogData(*map(match.group, cls.fields))


class ParserRFC3164(LogParser):
    """
    Parser and extraction methods for BSD Syslog format (RFC 3164).
    """
    NAME = 'rfc3164'
    PATTERN = (r'^(?:<(?P<pri>[0-9]{1,3})>|)'
               r'(?P<month>[A-Z,a-z]{3}) (?P<day>(?:[1-3]| )[0-9]) '
               r'(?P<ltime>[0-9]{2}:[0-9]{2}:[0-9]{2}) '
               r'(?:last message repeated (?P<repeat>[0-9]{1,3}) times|'
               r'(?P<host>\S{1,255})\s+'
               r'(?P<message>(?P<apptag>[^ \[\(\:]{1,32})(?:[\[\(\:])?.*))')


class ParserRFC5424(LogParser):
    """
    Parser for IETF-syslog logs (RFC 5424) .
    """
    NAME = 'rfc5424'
    PATTERN = (r'^(?:<(?P<pri>[0-9]{1,3})>(?P<ver>[0-9]{0,2}) |)'
               r'(?:-|(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})T)'
               r'(?P<ltime>[0-9]{2}:[0-9]{2}:[0-9]{2})(?:|\.(?P<secfrac>[0-9]{1,6}))'
               r'(?:Z |(?P<offset>(?:\+|-)[0-9]{2}:[0-9]{2}) )'
               r'(?:-|(?P<host>\S{1,255})) (?:-|(?P<apptag>\S{1,48})) '
               r'(?:-|(?P<procid>\S{1,128})) (?:-|(?P<msgid>\S{1,32})) '
               r'(?P<message>.*)')


class CycleParsers:
    """
    Class that define an iterator for a set of parsers. The additional
    method "detect" permits founding the first parser suitable for the
    argument or return None in alternative.
    """
    __slots__ = ('parsers', 'index', 'num_parsers')

    def __init__(self, parsers: Sequence[LogParser] | None = None):
        if parsers is None:
            parsers = tuple(c() for c in _registered_parsers.values())

        self.parsers = tuple(parsers)
        self.index = -1
        self.num_parsers = len(self.parsers)

    def __iter__(self):
        return self

    def __next__(self):
        self.index = (self.index + 1) % self.num_parsers
        return self.parsers[self.index]

    def detect(self, line: str) -> 'tuple[LogParser, re.Match[str]] | tuple[None, None]':
        for _ in range(self.num_parsers):
            parser = next(self)
            match = parser.match(line)
            if match is not None:
                return parser, match
        else:
            return None, None
