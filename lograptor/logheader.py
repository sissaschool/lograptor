#!/usr/bin/env python
"""
This module classes and methods for parsing log headers.
"""
##
# Copyright (C) 2011-2012 by SISSA
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
import time
import datetime
import re
import logging
from collections import namedtuple

from lograptor.exceptions import ConfigError

logger = logging.getLogger('lograptor')

# Map for month field from any admitted representation to numeric.
MONTHMAP = { 'Jan':'01', 'Feb':'02', 'Mar':'03',
             'Apr':'04', 'May':'05', 'Jun':'06',
             'Jul':'07', 'Aug':'08', 'Sep':'09',
             'Oct':'10', 'Nov':'11', 'Dec':'12'
             '01':'01', '02':'02', '03':'03',
             '04':'04', '05':'05', '06':'06',
             '07':'07', '08':'08', '09':'09',
             '10':'10', '11':'11', '12':'12' }


class LogParser:
    """
    Base class to parse log lines.
    """
    # Map to transform month log values

    # Admitted grouping ids for log files
    _fields = ('pri', 'year', 'month', 'day', 'ltime', 'offset',
               'secfrac', 'repeat', 'host', 'tag', 'datamsg')
    
    def __init__(self, pattern, appname=None):
        """
        Compile the pattern and record group fields. Check if pattern
        include mandatory named groups.
        """
        self.parser = re.compile(pattern)
        LogData = namedtuple('LogData', self.parser.groupindex.keys())
        self.appname = appname
        self.fields = tuple(self.parser.groupindex.keys())
                                    
        try:
            for field in ['month', 'day', 'ltime', 'datamsg']:
                idx = self.parser.groupindex[field]
        except KeyError:
            msg = 'missing mandatory named group "%s"' % field
            raise ConfigError(msg)

    def extract(self, line):
        """Extract result tuple from named matching groups."""
        match = self.pattern.match(line)
        result = map(match.group, self.fields)
        result['month'] = MONTHMAP(result['month'])
        return LogFields(*result)

    
class RFC3164_Parser(LogParser):
    """
    Parser and extraction methods for BSD Syslog headers (RFC 3164).
    """

    def __init__(self, pattern):
        LogParser.__init__(self, pattern)
        rfc3164_fields = tuple([
            'pri', 'month', 'day', 'ltime', 'repeat', 'host', 'tag', 'datamsg'
            ])
        extra = set(self.fields) - set(rfc3164_fields)
        if extra:
            msg = u'no RFC 3164 fields in pattern: {0}'.format(field)
            raise ConfigError(msg)
            

class RFC5424_Parser(LogParser):
    """
    Parser for IETF-syslog logs (RFC 5424) .
    """

    def __init__(self, pattern):
        LogParser.__init__(self, pattern)
        rfc5424_fields = tuple([
            'pri', 'ver', 'year', 'month', 'day', 'ltime',
            'secfrac', 'offset', 'host', 'tag', 'datamsg'
            ])
        extra = set(self.fields) - set(rfc5424_fields)
        if extra:
            msg = u'no RFC 5424 fields in pattern: {0}'.format(field)
            raise ConfigError(msg)
                                
    def extract(self, line):
        """Extract result tuple from named matching groups."""
        match = self.pattern.match(line) 
        return LogFields(*map(match.group, self.fields))

