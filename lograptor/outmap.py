#!/usr/bin/env python
"""
This module contains class to handle output mapping and lookup
internal caching for Lograptor's application class instances.
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

import socket
import string

try:
    import pwd
except ImportError:
    pwd = None

class OutMap(object):
    """
    Output mapping class: translate matching group for output
    """

    def __init__(self, config):
        self.ip_lookup = config['ip_lookup']
        self.uid_lookup = config['uid_lookup']
        self.anonymyze = config['anonymize']
        self.hostsmap = {}
        self.uidsmap = {}
        if self.anonymyze:
            self.anonymaps = {
                'host': {},
                'thread': {},
            }
            for flt in config.options('filters'):
                self.anonymaps[flt] = {}

    def map_value(self, gid, value):
        """
        Return the value for a group id, applying translation
        maps if requested by options.
        """
        if self.anonymyze:
            try:
                if value in self.anonymaps[gid]:
                    return self.anonymaps[gid][value]
                else:
                    k = (len(self.anonymaps[gid]) + 1) % 100000
                    new_item = u'{0}_{1:0{2}d}'.format(gid, k, 5)
                    self.anonymaps[gid][value] = new_item
                    return new_item
            except KeyError:
                return value
        elif (gid == 'client' or gid == 'ipaddr') and self.ip_lookup:
            return self.gethost(value)
        elif (gid == 'user' or gid == 'uid') and self.uid_lookup:
            return self.getuname(value)
        else:
            return value

    def map_message(self, match):
        """
        Return the value for a group id, applying translation
        maps if requested by options.
        """
        return match.string
        if self.anonymyze:
            try:
                if value in self.anonymaps[gid]:
                    return self.anonymaps[gid][value]
                else:
                    k = (len(self.anonymaps[gid]) + 1) % 100000
                    new_item = u'{0}_{1:0{2}d}'.format(gid, k, 5)
                    self.anonymaps[gid][value] = new_item
                    return new_item
            except KeyError:
                return value
        elif (gid == 'client' or gid == 'ipaddr') and self.ip_lookup:
            return self.gethost(value)
        elif (gid == 'user' or gid == 'uid') and self.uid_lookup:
            return self.getuname(value)
        else:
            return value


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
