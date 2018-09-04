#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Tests for Lograptor configuration.
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
import pytest
from lograptor.confparsers import LogRaptorConfig


@pytest.fixture(scope='class')
def lograptor_config(config_files):
    return LogRaptorConfig(cfgfiles=config_files)


class TestConfigParser(object):

    def setup_method(self, method):
        print("\n%s:%s" % (type(self).__name__, method.__name__))

    @staticmethod
    def check_option(lograptor_config, section, default_section, options):
        for opt, value in options.items():
            if isinstance(value, bool):
                config_value = lograptor_config.getboolean(section, opt, default_section)
            elif isinstance(value, int):
                config_value = lograptor_config.getint(section, opt, default_section)
            elif isinstance(value, float):
                config_value = lograptor_config.getfloat(section, opt, default_section)
            else:
                config_value = lograptor_config.get(section, opt, default_section)
            assert config_value == value, 'config option %r of section %r does not match.' % (opt, section)

    @pytest.mark.mail_options
    def test_mail_channel_options(self, lograptor_config):
        channel = 'mail1_channel'
        default_channel = 'mail_channel'
        options = {
            'type': 'mail',
            'formats': 'text, html',
            'mailto': 'root@localhost.localdomain',
            'include_rawlogs': False,
            'rawlogs_limit': 200,
            'gpg_encrypt': False,
            'gpg_keyringdir': '/root/.gnupg',
            'gpg_recipients': '',
            'gpg_signers': '',
        }
        self.check_option(lograptor_config, channel, default_channel, options)

    @pytest.mark.file_options
    def test_file_channel_options(self, lograptor_config):
        channel = 'file1_channel'
        default_channel = 'file_channel'
        options = {
            'type': 'file',
            'formats': 'html, csv',
            'notify': 'root@localhost.localdomain',
            'pubdir': './var/www/',
            'dirmask': '%Y-%b-%d_%a',
            'filemask': '%H%M',
            'save_rawlogs': True,
            'expire_in': 7,
            'pubroot': 'http://localhost/lograptor',
        }
        self.check_option(lograptor_config, channel, default_channel, options)
