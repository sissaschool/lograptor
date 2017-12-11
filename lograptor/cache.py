# -*- coding: utf-8 -*-
"""
This module contains class to handle lograptor's lookup cache.
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
import socket
import string

try:
    import pwd
except ImportError:
    pwd = None


class LookupCache(object):
    """
    Name cache for names, that maps IPs to DNS names, UIDs to usernames.
    The names can be mapped into random generated values for obfuscate
    the input names, maintaining a correspondence for the entire process.
    """

    def __init__(self, args, config):
        self._maps = {}
        self.mapexp = config.getint('main', 'mapexp')
        self.mapmax = 10 ** self.mapexp
        self.ip_lookup = args.ip_lookup
        self.uid_lookup = args.uid_lookup
        self.anonymyze = args.anonymize
        self.fields = config.options('fields')
        self.base_gid_pattern = re.compile('^([a-zA-Z_]+)')
        ipv4_pattern = config.get('patterns', 'IPV4_ADDRESS')
        ipv6_pattern = config.get('patterns', 'IPV6_ADDRESS')
        self.ip_pattern = re.compile(u'({0}|{1})'.format(ipv4_pattern, ipv6_pattern))
        self.clear()

    def clear(self):
        self._maps.clear()
        for flt in set(self.fields) | {'host', 'thread', 'uid'}:
            self._maps[flt] = {}

    @property
    def hostsmap(self):
        return self._maps['host']

    @property
    def uidsmap(self):
        return self._maps['uid']

    def map_value(self, value, gid):
        """
        Return the value for a group id, applying requested mapping.
        Map only groups related to a filter, ie when the basename of
        the group is identical to the name of a filter.
        """
        base_gid = self.base_gid_pattern.search(gid).group(1)
        if self.anonymyze:
            try:
                if value in self._maps[base_gid]:
                    return self._maps[base_gid][value]
                else:
                    k = (len(self._maps[base_gid]) + 1) % self.mapmax
                    new_item = u'{0}_{1:0{2}d}'.format(base_gid.upper(), k, self.mapexp)
                    self._maps[base_gid][value] = new_item
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

    def match_to_dict(self, match, gids):
        """
        Map values from match into a dictionary.
        """
        values = {}
        for gid in gids:
            try:
                values[gid] = self.map_value(match.group(gid), gid)
            except IndexError:
                pass
        return values

    def match_to_string(self, match, gids, values=None):
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
                    value = self.map_value(match.group(gid), gid)
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
