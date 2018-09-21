#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test script for lograptor.
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
import os
import pytest


def pytest_report_header(config):
    return "lograptor test"


@pytest.fixture(scope='module')
def config_files():
    return ('lograptor.conf', 'test_lograptor.conf')


@pytest.fixture(scope="session", autouse=True)
def set_test_files():
    # Change directory
    os.chdir(os.path.dirname(__file__))

    # Creates test directories for program log and temporary files
    os.system('mkdir -p ./var/log')
    os.system('mkdir -p ./var/tmp')
    os.system('mkdir -p ./var/www')

    # Set sample files timestamps
    os.system('touch -m -t 201506211034 samples/apache2.log')
    os.system('touch -m -t 201506210909 samples/apache2_ssl_access.log')
    os.system('touch -m -t 201506210906 samples/apache2_ssl_error.log')
    os.system('touch -m -t 201504010548 samples/catalyst.log')
    os.system('touch -m -t 201504011000 samples/dovecot.log')
    os.system('touch -m -t 201501310950 samples/postfix.log')
    os.system('touch -m -t 200310112214 samples/rfc5424.log')
    os.system('touch -m -t 201501310154 samples/sshd.log')
