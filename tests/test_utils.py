#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test script for helper functions.
"""
#
# Copyright (C), 2011-2018, by SISSA - International School for Advanced Studies.
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
import pytest
import sys

from lograptor.utils import open_resource, is_redirected, is_pipe


class TestUtils(object):
    def setup_method(self, method):
        print("\n%s:%s" % (type(self).__name__, method.__name__))

    @pytest.mark.unparsed
    def test_open_resource(self):
        open_resource("samples/postfix.log")
        open_resource(open("samples/dovecot.log"))

        with pytest.raises((OSError, IOError)):
            open_resource("samples/nofile.log")

    @pytest.mark.is_redirected
    def test_is_redirected(self):
        try:
            STDIN_FILENO = sys.stdin.fileno()
        except ValueError:
            STDIN_FILENO = 0
        assert is_redirected(STDIN_FILENO) is False

