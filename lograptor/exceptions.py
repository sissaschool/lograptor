#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module contain exception classes for Lograptor package.
"""
##
# Copyright (C) 2012-2016 by SISSA - International School for Advanced Studies
#
# This file is part of Lograptor.
#
# Lograptor is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Lograptor is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Lograptor; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# @Author Davide Brunato <brunato@sissa.it>
#
##
import logging

logger = logging.getLogger('lograptor')


class FormatError(Exception):
    """
    This exception is raised when there are errors with the
    format of syslog file processed.
    """
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!FormatError: {0}'.format(message))


class ConfigError(Exception):
    """
    This exception is raised when there are errors in a configuration
    file or when there are misconfiguration problems.
    """
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!ConfigError: {0}'.format(message))


class OptionError(Exception):
    """
    This exception is raised when there is a wrong option values or
    when there are conflicts between options.
    """
    def __init__(self, option, message=None):
        if message is None:
            message = 'syntax error for option "{0}"'.format(option)
        else:
            message = 'option "{0}": {1}'.format(option, message)
        Exception.__init__(self, message)
        logger.debug('!OptionError: {0}'.format(message))


class RuleMissingError(Exception):
    """
    This exception is raised when a rule definition is missing.
    """
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!RuleMissingError: {0}'.format(message))


class FileMissingError(Exception):
    """
    This exception is raised when a file is missing.
    """
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!FileMissingError: {0}'.format(message))


class FileAccessError(Exception):
    """
    This exception is raised when Lograptor has problem to access to a file.
    """
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!FileAccessError: {0}'.format(message))
