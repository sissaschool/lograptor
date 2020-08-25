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
import pytest

from lograptor.timedate import parse_last_period


class TestTimeDateHelpers(object):
    def setup_method(self, method):
        print("\n%s:%s" % (type(self).__name__, method.__name__))

    def test_parse_last_period(self):
        assert parse_last_period('1h') == 3600
        assert parse_last_period('hour') == 3600
        assert parse_last_period('2h') == 7200
        assert parse_last_period('1d') == 86400
        assert parse_last_period('1w') == 86400 * 7
        assert parse_last_period('week') == 86400 * 7
        assert parse_last_period('1m') == 86400 * 30
        assert parse_last_period('month') == 86400 * 30

        with pytest.raises(TypeError):
            parse_last_period(2)

        with pytest.raises(ValueError):
            parse_last_period('-2d')

        with pytest.raises(ValueError):
            parse_last_period('1x')

        with pytest.raises(ValueError):
            parse_last_period('year')

        with pytest.raises(ValueError):
            parse_last_period('ax')