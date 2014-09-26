#!/usr/bin/env python
"""
This module contains class to handle log line caching for Lograptor's
application class instances.
"""
##
# Copyright (C) 2012 by SISSA
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
from __future__ import print_function

try:
    from collections import UserDict
except ImportError:
    # Fall back for Python 2.x
    from UserDict import IterableUserDict as UserDict

try:
    from collections import OrderedDict
except ImportError:
    # Backport for Python 2.4-2.6
    from lograptor.backports.ordereddict import OrderedDict
    

class CacheEntry:
    """
    Simple container class for cache entries
    """
    def __init__(self, event_time):
        self.pattern_match = False
        self.full_match = False
        self.counted = False
        self.buffer = list()
        self.start_time = self.end_time = event_time


class LineCache:
    """
    A class to manage line caching
    """
    
    def __init__(self):
        self.data = OrderedDict()

    def add_line(self, line, thread, pattern_match, full_match, event_time):
        try:
            cache_entry = self.data[thread]
        except KeyError:
            cache_entry = self.data[thread] = CacheEntry(event_time)
        
        if pattern_match:
            cache_entry.pattern_match = True
        if full_match:
            cache_entry.full_match = True
        cache_entry.buffer.append(line)
        cache_entry.end_time = event_time
        
    def flush_cache(self, event_time, print_out_lines, max_threads=None):
        """
        Flush the cache to output. Only matched threads are printed.
        Delete cache entries older (last updated) than 1 hour. Return
        the total lines of matching threads.
        """
        cache = self.data
        counter = 0
        
        for thread in cache.keys():
            if cache[thread].pattern_match and cache[thread].full_match:
                if max_threads is not None:
                    max_threads -= 1
                    if max_threads < 0:
                        break

                if not cache[thread].counted:
                    counter += 1
                    cache[thread].counted = True

                if cache[thread].buffer:
                    if print_out_lines:
                        print(len(cache[thread].buffer))
                        for line in cache[thread].buffer:
                            print(line, end='')
                        print('--')
                    cache[thread].buffer = []
            if abs(event_time - cache[thread].end_time) > 3600:
                del cache[thread]
        return counter
    
    def flush_old_cache(self, event_time, print_out_lines, max_threads=None):
        """
        Flush the older cache to output. Only matched threads are printed.
        Delete cache entries older (last updated) than 1 hour. Return the
        total lines of old matching threads.
        """
        cache = self.data
        counter = 0
        for thread in cache.keys():
            if (abs(event_time - cache[thread].end_time) > 3600):
                if cache[thread].pattern_match and cache[thread].full_match:
                    if max_threads is not None:
                        max_threads -= 1
                        if max_threads < 0:
                            break

                    if not cache[thread].counted:
                        counter += 1
                        cache[thread].counted = True

                    if print_out_lines and cache[thread].buffer:
                        for line in cache[thread].buffer:
                            print(line, end='')
                        print('--')
                del cache[thread]
        return counter
