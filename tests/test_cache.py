#
# Copyright (C), 2011-2020, by SISSA - International School for Advanced Studies.
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
import os
import platform

import lograptor
from lograptor.cache import LookupCache
from lograptor.confparsers import LogRaptorConfig

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'test_lograptor.conf')


class TestLookupCache(object):

    cli_parser = lograptor.api.create_argument_parser()
    config = lograptor.confparsers.LogRaptorConfig(cfgfiles=[CONFIG_FILE])

    def setup_method(self, method):
        print("\n%s:%s" % (type(self).__name__, method.__name__))

    def test_init_cache(self):
        args = self.cli_parser.parse_args([])
        cache = LookupCache(args, self.config)

        assert cache.ip_pattern.pattern.startswith('((?:(?:25[0-5]')
        assert cache.hostsmap == {}
        assert cache.uidsmap == {}

    def test_host_lookup(self):
        args = self.cli_parser.parse_args([])
        cache = LookupCache(args, self.config)

        cache.hostsmap['127.0.0.1'] = 'raptor'
        assert cache.gethost('127.0.0.1') == 'raptor'

    def test_uid_lookup(self):
        args = self.cli_parser.parse_args([])
        cache = LookupCache(args, self.config)

        cache.uidsmap[100] = 'foo'
        assert cache.getuname('100') == 'foo'
        assert cache.getuname(100) == 'foo'

        if platform.system() == 'Linux':
            assert cache.getuname('0') == 'root'
            assert cache.getuname(0) == 'root'
