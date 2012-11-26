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
    def __init__(self, matching, line):
        self.matching = matching
        self.buffer = [line]
        

class LineCache(UserDict):
    """
    A class to manage line caching
    """
    
    def __init__(self):
        #UserDict.__init__(self)
        self.data = OrderedDict()
    
    def add_line(self, line, thread, matching):        
        if thread in self.data:
            if matching:
                self.data[thread].matching = True
            self.data[thread].buffer.append(line)
        else:
            self.data[thread] = CacheEntry(matching, line)
            
    def flush_cache(self, prefix, preserve_last=True):
        """
        Flush the cache. Print to output if the thread match.
        Delete the older threads (4/5 older entries) if a preserve option
        is provided.
        """
        
        if preserve_last:
            k = max(10, int(len(self.data)/5)*4)
        else:
            k = -1

        for thread in self:
            if self[thread].matching:
                if self[thread]:
                    for line in self[thread].buffer:
                        print('{0}{1}'.format(prefix, line), end='')
                    print('--')
                if k > 0:
                    del self[thread]
                    k -= 1
                else:
                    self[thread].buffer = []
            elif k > 0:
                del self[thread]
                k -= 1
        
