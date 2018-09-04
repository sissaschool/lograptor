#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test script for resource access.
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
import os
import pytest

import lograptor
from lograptor.utils import open_resource


class TestUtils(object):
    """
    Test which lograptor application have unparsed line issues.
    """
    def setup_method(self, method):
        print("\n%s:%s" % (type(self).__name__, method.__name__))

    @pytest.mark.unparsed
    def test_open_resource(self, capsys):
        open_resource("samples/postfix.log")
        with pytest.raises(ValueError):
            open_resource("samples/nofile.log")

        # pytest.set_trace()
        f = open_resource("samples/iso-8859-sample2.log")
        print(f)

