# -*- coding: utf-8 -*-
"""
This module contains class to handle output mapping and lookup
internal caching for Lograptor's application class instances.
"""
#
# Copyright (C), 2011-2016, by Davide Brunato and
# SISSA (Scuola Internazionale Superiore di Studi Avanzati).
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
import re
import socket
import string

try:
    import pwd
except ImportError:
    pwd = None


class OutMap(object):
    """
    Output mapping class: translate matching groups for output.
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
        Get username for a given uid
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
