#
# Copyright (C), 2011-2026, by SISSA - International School for Advanced Studies.
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
import pwd
from argparse import Namespace
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import chain
from typing import cast, Hashable, Any

from mypyc.ir.ops import Sequence


@dataclass(slots=True)
class LookupCache:
    """
    Name cache for names, that maps IPs to DNS names, UIDs to usernames.
    Names can be mapped into random generated values for obfuscate the
    input names, maintaining a correspondence for the entire process.
    """
    _maps: dict[str, dict[Any, str]]
    _uidmap: dict[int, str]
    _hostmap: dict[str, str]
    fields: list[str]
    mapexp: int
    mapmax: int
    base_gid_pattern: re.Pattern[str]
    ip_pattern: re.Pattern[str]
    ip_lookup: bool = False
    uid_lookup: bool = False
    anonymize: bool = False

    @classmethod
    def from_args(cls, args: Namespace, config):
        mapexp = config.getint('main', 'mapexp')
        ipv4_pattern = config.get('patterns', 'IPV4_ADDRESS')
        ipv6_pattern = config.get('patterns', 'IPV6_ADDRESS')
        fields = config.options('fields')
        maps: dict[str, dict[Any, str]] = {k: {} for k in chain(fields, ('host', 'thread', 'uid'))}
        return cls(
            _maps=maps,
            _uidmap=maps['uid'],
            _hostmap=maps['host'],
            fields=fields,
            mapexp=mapexp,
            mapmax=10 ** mapexp,
            base_gid_pattern=re.compile('^([a-zA-Z_]+)'),
            ip_pattern=re.compile(f'({ipv4_pattern}|{ipv6_pattern})'),
            ip_lookup=args.ip_lookup,
            uid_lookup=args.uid_lookup,
            anonymize=args.anonymize,
        )

    def clear(self) -> None:
        for values in self._maps.values():
            values.clear()

    @property
    def hostmap(self) -> dict[str, str]:
        return self._hostmap

    @property
    def uidmap(self) -> dict[int, str]:
        return self._uidmap

    def map_value(self, value: str, gid: str) -> str:
        """
        Return the value for a group id, applying requested mapping.
        Map only groups related to a filter, ie when the basename of
        the group is identical to the name of a filter.
        """
        try:
            base_gid = self.base_gid_pattern.search(gid).group(1)  # type:ignore[union-attr]
        except AttributeError:
            return value

        if self.anonymize:
            try:
                if value in self._maps[base_gid]:
                    return self._maps[base_gid][value]
                else:
                    k = (len(self._maps[base_gid]) + 1) % self.mapmax
                    new_item = '{0}_{1:0{2}d}'.format(base_gid.upper(), k, self.mapexp)
                    self._maps[base_gid][value] = new_item
                    return new_item
            except KeyError:
                return value
        elif base_gid in ('client', 'mail', 'from', 'rcpt', 'user') and self.ip_lookup:
            ip_match = self.ip_pattern.search(value)
            if ip_match is None:
                return value
            host = self.get_hostname(ip_match.group(1))
            if host == ip_match.group(1) or value.startswith(host):
                return value
            return ''.join([
                value[:ip_match.start(1)],
                self.get_hostname(ip_match.group(1)),
                value[ip_match.end(1):]])
        elif (base_gid == 'user' or base_gid == 'uid') and self.uid_lookup:
            return self.get_username(value)
        else:
            return value

    def match_to_dict(self, match: re.Match[str], gids: Sequence[str]) -> dict[str, str]:
        """Map values from match into a dictionary."""
        values = {}
        for gid in gids:
            try:
                values[gid] = self.map_value(match.group(gid), gid)
            except IndexError:
                pass
        return values

    def match_to_string(self, match: re.Match[str], gids: Mapping[str, int], values=None):
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
        return ''.join(parts)

    def get_hostname(self, ip_addr: str) -> str:
        """
        Do reverse lookup on an ip address.

        :param ip_addr: ipV4 or ipV6 address
        """
        # Handle silly fake ipv6 addresses
        try:
            if ip_addr[:7] == '::ffff:':
                ip_addr = ip_addr[7:]
        except TypeError:
            pass

        if ip_addr[0] in string.ascii_letters:
            return ip_addr

        try:
            return self.hostmap[ip_addr]
        except KeyError:
            pass

        try:
            name = socket.gethostbyaddr(ip_addr)[0]
        except socket.error:
            name = ip_addr

        self.hostmap[ip_addr] = name
        return name

    def get_username(self, uid: str | int) -> str:
        """
        Get the username of a given uid.
        """
        uid = int(uid)
        try:
            return self.uidmap[uid]
        except KeyError:
            pass

        try:
            name = pwd.getpwuid(uid)[0]
        except (KeyError, AttributeError):
            name = "uid=%d" % uid

        self.uidmap[uid] = name
        return name
