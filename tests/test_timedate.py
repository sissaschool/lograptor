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
import datetime

from lograptor.timedate import parse_last_period, get_datetime_interval, \
    parse_date_period, TimeRange, strftimegen


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
            parse_last_period('ad')

    def test_get_datetime_interval(self):
        timestamp = 1598364945
        assert get_datetime_interval(timestamp, diff=86400) == \
               (datetime.datetime(2020, 8, 24, 16, 15, 45),
                datetime.datetime(2020, 8, 25, 16, 15, 45))

        assert get_datetime_interval(timestamp, diff=86400, offset=3600) == \
               (datetime.datetime(2020, 8, 24, 16, 15, 45),
                datetime.datetime(2020, 8, 25, 17, 15, 45))

    def test_parse_date_period(self):
        year = datetime.datetime.today().year

        assert parse_date_period('0213') == \
               (datetime.datetime(year, 2, 13, 0, 0),
                datetime.datetime(year, 2, 13, 23, 59, 59))

        assert parse_date_period('20190213') == \
               (datetime.datetime(2019, 2, 13, 0, 0),
                datetime.datetime(2019, 2, 13, 23, 59, 59))

        assert parse_date_period('0419,0422') == \
               (datetime.datetime(year, 4, 19, 0, 0),
                datetime.datetime(year, 4, 22, 23, 59, 59))

        with pytest.raises(ValueError):
            parse_date_period('0419.0422')

        assert parse_date_period('20190419,20190422') == \
               (datetime.datetime(2019, 4, 19, 0, 0),
                datetime.datetime(2019, 4, 22, 23, 59, 59))

        with pytest.raises(ValueError):
            parse_date_period('20190419.20190422')

        with pytest.raises(ValueError):
            parse_date_period('0419,')

        with pytest.raises(ValueError):
            parse_date_period('20191419')

        with pytest.raises(ValueError):
            parse_date_period('20191131,20191201')

        with pytest.raises(ValueError):
            parse_date_period('20191019,20191401')

        with pytest.raises(ValueError):
            parse_date_period('20190422,20190419')

    def test_time_range_class(self):
        time_range = TimeRange('10:00,11:01')

        assert time_range.h1 == 10
        assert time_range.m1 == 0
        assert time_range.h2 == 11
        assert time_range.m2 == 1

        with pytest.raises(ValueError):
            TimeRange('10:00.10:01')

        with pytest.raises(ValueError):
            TimeRange('10:00,10:00')

        assert time_range.between('10:59') is True
        assert time_range.between('09:59') is False

    def test_strftimegen(self):
        dt1 = datetime.datetime(2020, 8, 15, 23, 59, 59)
        dt2 = datetime.datetime(2020, 8, 18)

        with pytest.raises(ValueError):
            strftimegen(dt2, dt1)

        assert list(strftimegen(dt1, dt2)('%d')) == ['15', '16', '17']
        assert list(strftimegen(dt1, dt2)('%m-%d')) == ['08-15', '08-16', '08-17']
