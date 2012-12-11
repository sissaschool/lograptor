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
    def __init__(self, line, pattern_match, filter_match, event_time):
        self.pattern_match = pattern_match
        self.filter_match = filter_match
        self.start_time = self.end_time = event_time
        self.buffer = [line]
        

class LineCache(UserDict):
    """
    A class to manage line caching
    """
    
    def __init__(self, rules_list):
        #UserDict.__init__(self)
        self._rules_list = rules_list
        self.data = OrderedDict()
    
    def add_line(self, line, thread, pattern_match, filter_match, event_time):        
        if thread in self.data:
            cache_entry = self.data[thread]
            if pattern_match:
                cache_entry.pattern_match = True
            if filter_match:
                cache_entry.filter_match = True
            cache_entry.buffer.append(line)
            cache_entry.end_time = event_time
        else:
            self.data[thread] = CacheEntry(line, pattern_match, filter_match, event_time)

    def purge_results(self, event_time):
        """
        Purge results for unmatched threads
        """

        cache = self.data
        
        for key, rule in self._rules_list:
            try:
                pos = rule.key_gids.index('thread')
            except ValueError:
                continue

            purge_list = []
            for idx in rule.results:
                thread = idx[pos]
                if thread in cache:
                    if (not (cache[thread].pattern_match and cache[thread].filter_match) and
                        (abs(event_time - cache[thread].end_time) > 3600)):
                        
                        purge_list.append(idx)
                
            for idx in purge_list:
                del rule.results[idx]

    def flush_cache(self, prefix, event_time=None):
        """
        Flush the cache to output. Only matched threads are printed.
        Delete cache entries older (last updated) than 1 hour.
        """

        cache = self.data
        for thread in cache.keys(): #sorted(cache, key=lambda x:cache[x].end_time):
            if cache[thread].pattern_match and cache[thread].filter_match:
                if cache[thread].buffer:
                    for line in cache[thread].buffer:
                        print('{0}{1}'.format(prefix, line), end='')
                    print('--')
                    self[thread].buffer = []
            if (abs(event_time - cache[thread].end_time) > 3600):
                del self[thread]
        
    def purge_cache(self, prefix, event_time=None):
        """
        Flush the cache to output. Only matched threads are printed.
        Delete cache entries older (last updated) than 1 hour.
        """

        cache = self.data
        for thread in cache.keys(): #sorted(cache, key=lambda x:cache[x].end_time):
            if (abs(event_time - cache[thread].end_time) > 3600):
                if cache[thread].pattern_match and cache[thread].filter_match:
                    if cache[thread].buffer:
                        for line in cache[thread].buffer:
                            print('{0}{1}'.format(prefix, line), end='')
                        print('--')
                del self[thread]
