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

from lograptor.exceptions import LogRaptorConfigError, LogRaptorArgumentError
from lograptor.api import lograptor
from lograptor.runner import LogRaptor
from lograptor.timedate import TimeRange


@pytest.fixture
def config_file():
    return str(pathlib.Path(__name__).parent / 'test_lograptor.conf')


@pytest.fixture
def sshd_log():
    return str(pathlib.Path(__name__).parent / 'samples' / 'sshd.log')


@pytest.fixture
def time_period():
    return datetime.datetime(2011, 6, 21, 10, 34), datetime.datetime(2050, 6, 21, 11, 34)


class TestApiInterface(object):
    """
    Test the lograptor() API function.
    """

    def test_api_basic(self, config_file, sshd_log, time_period):
        # Basic call with patterns and files
        runner = lograptor(
            files=[sshd_log],
            cfgfiles=[config_file],
            time_period=time_period,
        )
        assert isinstance(runner, LogRaptor)
        assert runner() == 0

    def test_api_no_match(self, config_file, sshd_log):
        runner = lograptor(
            files=[sshd_log],
            cfgfiles=[config_file],
            patterns=['NONEXISTENT_PATTERN']
        )
        assert runner() is False

    def test_api_invert(self, config_file, sshd_log):
        # With invert, a non-existent pattern should match everything
        runner = lograptor(
            files=[sshd_log],
            cfgfiles=[config_file],
            patterns=['NONEXISTENT_PATTERN'],
            invert=True
        )
        assert runner() is True

    def test_api_count(self, config_file, sshd_log):
        # count=True affects output but __call__ still returns True/False
        runner = lograptor(
            files=[sshd_log],
            cfgfiles=[config_file],
            patterns=['Accepted'],
            count=True
        )
        assert runner() is True

    def test_api_max_count(self, config_file, sshd_log):
        runner = lograptor(
            files=[sshd_log],
            cfgfiles=[config_file],
            patterns=['Accepted'],
            max_count=1
        )
        assert runner() is True

    def test_api_time_range(self, config_file, sshd_log):
        tr = TimeRange("00:00,23:59")
        runner = lograptor(
            files=[sshd_log],
            cfgfiles=[config_file],
            patterns=['Accepted'],
            time_range=tr
        )
        assert runner() is True

    def test_api_time_period(self, config_file, sshd_log):
        # Use a wide time period
        sshd_log_path = pathlib.Path(__file__).parent / 'samples' / 'sshd.log'
        year = datetime.datetime.fromtimestamp(sshd_log_path.stat().st_mtime).year
        tp = (datetime.datetime(year, 1, 1),
              datetime.datetime(year, 12, 31, 23, 59, 59))

        runner = lograptor(
            files=[sshd_log],
            cfgfiles=[config_file],
            patterns=['Accepted'],
            time_period=tp
        )
        assert runner() is True

    def test_api_invalid_type(self, config_file, sshd_log):
        # verify() should catch wrong type for max_count
        with pytest.raises(LogRaptorConfigError):
            lograptor(
                files=[sshd_log],
                cfgfiles=[config_file],
                max_count="ten"
            )

    def test_api_invalid_choice(self, config_file, sshd_log):
        # matcher must be one of the specified choices
        with pytest.raises(LogRaptorArgumentError):
            lograptor(
                files=[sshd_log],
                cfgfiles=[config_file],
                matcher='invalid_matcher'
            )

    def test_api_defaults(self, config_file, sshd_log):
        # Test defaults by providing minimal arguments
        # We need patterns or patterns will be empty
        runner = lograptor(
            files=[sshd_log],
            cfgfiles=[config_file],
            patterns=['.']
        )
        assert runner.args.ignore_case is False
        assert runner.args.invert is False
        assert runner.args.count is False
        assert runner.args.max_count == 0
