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

logger = logging.getLogger('lograptor')


class LogHeader:
    """
    Class to parse and translate log line headers.
    """

    def __init__(self, pattern):
        """
        Compile the pattern and define common mandatory attributes.
        """
        self.parser = re.compile(pattern)
        self.gids = self.parser.groupindex.keys()
        
        try:
            self.datagid = self.parser.groupindex['datamsg']
        except KeyError:
            self.datagid = self.parser.groups
        
    def extract(self, match):
        """ 
        Extract or derive values from matching object. 
        """
        return [match.group(idx) for idx in range(1, self.parser.groups)]

    def set_file_mtime(self, mtime):
        """
        Use file mtime (file modification time) to set reference
        modification date, that is necessary for partial date header
        formats like RFC3164.
        """
        file_mtime = datetime.datetime.fromtimestamp(mtime)
        self.file_year = file_mtime.year
        self.file_month = file_mtime.month
        self.file_day = file_mtime.day
        
    
class RFC3164_Header(LogHeader):
    """
    Parser and extraction methods for BSD Syslog headers (RFC 3164).
    """

    def __init__(self, pattern):
        LogHeader.__init__(self, pattern)
        self._year = str(datetime.datetime.now().year)
        self._prev_year = str(datetime.datetime.now().year - 1)
        self._monthmap = { 'Jan':'01', 'Feb':'02', 'Mar':'03',
                           'Apr':'04', 'May':'05', 'Jun':'06',
                           'Jul':'07', 'Aug':'08', 'Sep':'09',
                           'Oct':'10', 'Nov':'11', 'Dec':'12' }
        
        self.gids = ['pri', 'month', 'day', 'time', 'repeat', 'host', 'tag']    
        try:
            for gid in self.gids:
                idx = self.parser.groupindex[gid]
        except KeyError:
            msg = "RFC3164 header: missing a named group, use fixed extraction."
            logger.info(msg)
            self.extract = self._fixed_extract

    def set_file_mtime(self, mtime):
        """
        Set the a reference mtime, ie the mtime of the processed file,
        that is necessary for partial header formats (RFC3164).
        """
        LogHeader.set_file_mtime(self, mtime)
        self._year = str(self.file_year)
        self._prev_year = str(self.file_year - 1) 
            
    def extract(self, match):
        """
        Extract result tuple from named matching groups. 
        """
        pri = match.group('pri')
        month = self._monthmap[match.group('month')]
        day = match.group('day')
        ltime = match.group('time')
        repeat = match.group('repeat')
        host = match.group('host')
        tag = match.group('tag')

        if month != '01' and self.file_month == 1:
            year = self._prev_year
        else:
            year = self._year
        
        return(pri, None, year, month, day, ltime, None, None, repeat, host, tag)

    def _fixed_extract(self, match):
        """
        Extract result tuple using fixed indexes for matching groups. 
        """
        pri = match.group(1)
        month = self._monthmap[match.group('month')]
        day = match.group(3)
        ltime = match.group(4)
        repeat = match.group(5)
        host = match.group(6)
        tag = match.group(7)

        if month != '01' and self.file_month == 1:
            year = self._prev_year
        else:
            year = self._year
        
        return(pri, None, year, month, day, ltime, None, None, repeat, host, tag)
        

class RFC5424_Header(LogHeader):
    """
    Parser and extraction methods for IETF-syslog headers (RFC 5424).
    """

    def __init__(self, pattern):
        LogHeader.__init__(self, pattern)

        self.gids = ['pri', 'ver', 'date', 'time', 'secfrac',
                     'offset', 'host', 'tag']    
        try:
            for gid in self.gids:
                idx = self.parser.groupindex[gid]
        except KeyError:
            msg = "RFC5424 header: missing a named group, use fixed extraction."
            logger.info(msg)
            self.extract = self._fixed_extract

    def extract(self, match):
        """
        Extract result tuple from named matching groups. 
        """
        pri = match.group('pri')
        ver = match.group('ver')
        ldate = match.group('date')
        ltime = match.group('time')
        secfrac = match.group('secfrac')
        offset = match.group('offset')
        host = match.group('host')
        tag = match.group('tag')

        year = ldate[0:4]
        month = ldate[5:7]
        day = ldate[8:]
        
        return(pri, ver, year, month, day, ltime, secfrac, offset, None, host, tag)

    def _fixed_extract(self, match):
        """
        Extract result tuple using fixed indexes for matching groups. 
        """
        pri = match.group(1)
        ver = match.group(2)
        ldate = match.group(3)
        ltime = match.group(4)
        secfrac = match.group(5)
        offset = match.group(6)
        host = match.group(7)
        tag = match.group(8)
        
        year = ldate[0:4]
        month = ldate[5:7]
        day = ldate[8:]
        
        return(pri, ver, year, month, day, ltime, secfrac, offset, None, host, tag)
