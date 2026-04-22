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
import pytest
import datetime
import pathlib
import re
from lograptor.api import lograptor
from lograptor.runner import LogRaptor
from lograptor.patterns import PatternTemplate, get_raw_pattern


@pytest.fixture
def config_file():
    return str(pathlib.Path(__name__).parent / 'test_lograptor.conf')


@pytest.fixture
def sshd_log():
    return str(pathlib.Path(__name__).parent / 'samples' / 'sshd.log')


@pytest.fixture
def time_period():
    return datetime.datetime(2011, 6, 21, 10, 34), datetime.datetime(2050, 6, 21, 11, 34)


class TestPatterns(object):
    """
    Test the template patterns expansion as regex.
    """

    def test_filters(self, config_file, sshd_log, time_period):
        # Basic call with patterns and files
        runner = lograptor(
            files=[sshd_log],
            cfgfiles=[config_file],
            time_period=time_period,
        )
        assert isinstance(runner, LogRaptor)
        assert isinstance(runner.filters, dict)
        assert len(runner.filters) == 8

        for name, regex in runner.filters.items():
            assert isinstance(re.compile(regex), re.Pattern)

    def test_pattern_template(self):
        template = PatternTemplate('foo %{BAR} %{BAZ}')
        assert template.safe_substitute({'BAR': 'bar', 'BAZ': 'baz'}) == 'foo bar baz'

    def test_pattern_template_case(self):
        template = PatternTemplate('foo %{bar} %{BAZ}')
        assert template.safe_substitute({'BAR': 'bar', 'BAZ': 'baz'}) == 'foo %{bar} baz'

    def test_pattern_template_multiple(self):
        template = PatternTemplate('foo %{BAR} %{BAZ} %{BAT}')
        mapping = {'BAR': '%{BAZ}', 'BAZ': '%{BAT}', 'BAT': 'bat'}

        result = template.safe_substitute(mapping)
        assert result == 'foo %{BAZ} %{BAT} bat'

        result = PatternTemplate(result).safe_substitute(mapping)
        assert result == 'foo %{BAT} bat bat'

        result = PatternTemplate(result).safe_substitute(mapping)
        assert result == 'foo bat bat bat'

        result = PatternTemplate(result).safe_substitute(mapping)
        assert result == 'foo bat bat bat'

    def test_pattern_template_circularity(self):
        template = PatternTemplate('foo %{BAR} %{BAZ}')
        mapping = {'BAR': '%{BAZ}', 'BAZ': '%{BAR}'}

        assert template.safe_substitute(mapping) == 'foo %{BAZ} %{BAR}'

        with pytest.raises(RuntimeError) as exc_info:
            template.safe_expand(mapping)
        assert exc_info.value.args[0] == 'substitution map has circularity!'

    def test_pattern_template_grok_like(self):
        template = PatternTemplate('foo %{BAR:bar} %{BAZ:baz} %{BAT}')
        mapping = {'BAR': '%{BAZ}', 'BAZ': '%{BAT}', 'BAT': 'bat'}

        result = template.safe_substitute(mapping)
        assert result == 'foo (?<bar>%{BAR}) (?P<baz>%{BAZ}) %{BAT}'

    def test_get_raw_pattern(self):
        pattern = 'foo %{BAR:bar} %{BAZ:baz} %{BAT}'
        raw_pattern = get_raw_pattern(pattern)
        assert raw_pattern == 'foo (?P<bar>%{BAR}) (?P<baz>%{BAZ}) %{BAT}'

    def test_pattern_template_grok_like_with_raw_pattern(self):
        pattern = 'foo %{BAR:bar} %{BAZ:baz} %{BAT}'
        raw_pattern = get_raw_pattern(pattern)

        template = PatternTemplate(raw_pattern)
        mapping = {'BAR': '%{BAZ}', 'BAZ': '%{BAT}', 'BAT': 'bat'}

        result = template.safe_expand(mapping)
        assert result == 'foo (?P<bar>bat) (?P<baz>bat) bat'



