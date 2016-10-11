# -*- coding: utf-8 -*-
"""
This module contains class to handle caching for Lograptor's
application class instances.
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
from __future__ import print_function

import re
import socket
import string
from collections import OrderedDict, deque

try:
    import pwd
except ImportError:
    pwd = None

from .utils import build_dispatcher


class CacheEntry(object):
    """
    Simple container class for cache entries
    """
    def __init__(self, event_time):
        self.pattern_match = False
        self.full_match = False
        self.counted = False
        self.buffer = list()
        self.start_time = self.end_time = event_time


class FileInputDeque(deque):
    """
    A deque subclass to read a text file with a deque line buffering.
    """

    def __init__(self, input_file, before=0, after=0):
        super(FileInputDeque, self).__init__(maxlen=before+after+1)
        self.input_file = input_file
        self.before = before
        self.after = after

    def __iter__(self):
        # Attempt to fill the buffer
        for k in range(self.after):
            try:
                self.append(next(self.input_file))
            except StopIteration:
                break
        self.index = 0

        return self

    def __next__(self):
        try:
            self.append(next(self.input_file))
        except StopIteration:
            try:
                self.popleft()
                next_line = self[self.index]
            except IndexError:
                raise StopIteration
            return next_line
        else:
            try:
                next_line = self[self.index]
            except IndexError:
                raise StopIteration
            if self.index < self.before:
                self.index += 1
            return next_line

    def iter_before(self):
        if self.index >= self.before:
            return range(0, self.before)
        else:
            return range(0, self.index)

    def iter_after(self):
        for k, i in enumerate(range(self.index + 1, len(self))):
            yield k + 1, i


class ThreadLineCache(object):
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
            if abs(event_time - cache[thread].end_time) > 3600:
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


class RenameCache(object):
    """
    Name cache for names, that map IPs to DNS names, UIDs to usernames.
    The names can be mapped into random generated values for obfuscate
    the input names maintaining a correspondance for the entire process.
    """

    def __init__(self, args, config):
        self.mapexp = config['mapexp']
        self.mapmax = 10 ** self.mapexp
        self.ip_lookup = args.ip_lookup
        self.uid_lookup = args.uid_lookup
        self.anonymyze = args.anonymize
        self.maps = dict()
        filters = args.filters or []
        for flt in set(filters + ['host', 'thread', 'uid']):
            self.maps[flt] = {}
        self.hostsmap = self.maps['host']
        self.uidsmap = self.maps['uid']
        self.base_gid_pattern = re.compile('^([a-zA-Z_]+)')
        self.ip_pattern = re.compile(u'({0}|{1})'.format(config['ipv4_pattern'], config['ipv6_pattern']))

    def map_value(self, gid, value):
        """
        Return the value for a group id, applying requested mapping.
        Map only groups related to a filter, ie when the basename of
        the group is identical to the name of a filter.
        """
        base_gid = self.base_gid_pattern.search(gid).group(1)
        if self.anonymyze:
            try:
                if value in self.maps[base_gid]:
                    return self.maps[base_gid][value]
                else:
                    k = (len(self.maps[base_gid]) + 1) % self.mapmax
                    new_item = u'{0}_{1:0{2}d}'.format(base_gid.upper(), k, self.mapexp)
                    self.maps[base_gid][value] = new_item
                    return new_item
            except KeyError:
                return value
        elif base_gid in ['client', 'mail', 'from', 'rcpt', 'user'] and self.ip_lookup:
            ip_match = self.ip_pattern.search(value)
            if ip_match is None:
                return value
            host = self.gethost(ip_match.group(1))
            if host == ip_match.group(1) or value.startswith(host):
                return value
            return u''.join([
                value[:ip_match.start(1)],
                self.gethost(ip_match.group(1)),
                value[ip_match.end(1):]])
        elif (base_gid == 'user' or base_gid == 'uid') and self.uid_lookup:
            return self.getuname(value)
        else:
            return value

    def map2dict(self, gids, match):
        """
        Map values from match into a dictionary.
        """
        values = {}
        for gid in gids:
            try:
                values[gid] = self.map_value(gid, match.group(gid))
            except IndexError:
                pass
        return values

    def map2str(self, gids, match, values=None):
        """
        Return the mapped string from match object. If a dictionary of
        values is provided then use it to build the string.
        """
        s = match.string
        parts = []
        k = 0
        for gid in sorted(gids, key=lambda x: gids[x]):
            if values is None:
                try:
                    value = self.map_value(gid, match.group(gid))
                    parts.append(s[k:match.start(gid)])
                    parts.append(value)
                    k = match.end(gid)
                except IndexError:
                    continue
            elif gid in values:
                parts.append(s[k:match.start(gid)])
                parts.append(values[gid])
                k = match.end(gid)
        parts.append(s[k:])
        return u"".join(parts)

    def gethost(self, ip_addr):
        """
        Do reverse lookup on an ip address
        """
        # Handle silly fake ipv6 addresses
        try:
            if ip_addr[:7] == '::ffff:':
                ip_addr = ip_addr[7:]
        except TypeError:
            pass

        if ip_addr[0] in string.letters:
            return ip_addr

        try:
            return self.hostsmap[ip_addr]
        except KeyError:
            pass

        try:
            name = socket.gethostbyaddr(ip_addr)[0]
        except socket.error:
            name = ip_addr

        self.hostsmap[ip_addr] = name
        return name

    def getuname(self, uid):
        """
        Get the username of a given uid.
        """
        uid = int(uid)
        try:
            return self.uidsmap[uid]
        except KeyError:
            pass

        try:
            name = pwd.getpwuid(uid)[0]
        except (KeyError, AttributeError):
            name = "uid=%d" % uid

        self.uidsmap[uid] = name
        return name


class LineCache(deque):

    def __init__(self, channels, before_context, after_context):
        super(LineCache, self).__init__(maxlen=before_context)
        self.channels = channels
        self.before_context = before_context
        self.after_context = after_context
        self.last_line = 0
        self.context_until = 0
        self.send_event = build_dispatcher(channels, 'send_event')
        self.send_context = build_dispatcher(channels, 'send_context')
        self.send_separator = build_dispatcher(channels, 'send_separator')

    def register_event(self, filename, line_number, pattern_match, **kwargs):
        next_line = line_number - len(self)
        if self.last_line and (next_line - self.last_line > 1):
            self.send_separator()
        for n_line in range(line_number - len(self), line_number):
            self.send_context(
                filename=filename,
                line_number=n_line,
                rawlog=self.popleft(),
                pattern_match=pattern_match
            )
        self.last_line = line_number
        self.context_until = line_number + self.after_context
        self.send_event(filename=filename, line_number=line_number, pattern_match=pattern_match, **kwargs)

    def register_context(self, line_number, rawlog, **kwargs):
        if self.after_context and self.context_until >= line_number:
            self.send_context(line_number=line_number, rawlog=rawlog, **kwargs)
            last_line = line_number
        elif self.before_context:
            self.append(rawlog)

    def reset(self):
        self.last_line = 0
        self.context_until = 0
        self.clear()


class ThreadsCache(OrderedDict):

    def __init__(self, channels, before_context, after_context, max_threads=1000):
        super(ThreadsCache, self).__init__()
        self.channels = channels
        if before_context <= 0:
            raise ValueError("before_context must be a positive integer")
        if after_context <= 0:
            raise ValueError("after_context must be a positive integer")
        self.before_context = before_context
        self.after_context = after_context
        self.context = before_context + after_context + 1
        self.max_threads = max_threads
        self.send_event = build_dispatcher(channels, 'send_event')
        self.send_context = build_dispatcher(channels, 'send_context')
        self.send_separator = build_dispatcher(channels, 'send_separator')
        self._flushed_first = False

    def flush(self, key):
        line_cache, matched, after_context = self[key]
        if not matched:
            return

        if not self._flushed_first:
            self.send_separator()
            self._flushed_first = True
        for entry in line_cache:
            if entry['context']:
                self.send_context(**entry)
            else:
                self.send_event(**entry)
        del self[key]

    def register_event(self, key, **kwargs):
        kwargs.update(context=False)
        try:
            line_cache, matched, after_context = self[key]
        except KeyError:
            line_cache = deque()
            line_cache.append(kwargs)
            self[key] = (line_cache, True, 0)
        else:
            if line_cache.maxlen is not None:
                line_cache = deque()
            del self[key]
            self[key] = (line_cache, True, 0)

    def register_context(self, key, **kwargs):
        kwargs.update(context=True)
        try:
            line_cache, matched, after_context = self[key]
        except KeyError:
            line_cache = deque(self.before_context)
            line_cache.append(kwargs)
            self[key] = (line_cache, False, 0)
        else:
            if after_context >= self.after_context:
                self.flush(key)
            else:
                del self[key]
                line_cache.append(kwargs)
                self[key] = (line_cache, matched, 0 if not matched else after_context + 1)

    def reset(self):
        self.clear()
        self._flushed_first = False

