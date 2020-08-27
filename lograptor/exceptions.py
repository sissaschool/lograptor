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
import logging
import configparser

logger = logging.getLogger(__name__)


class LogRaptorException(Exception):
    pass


class LogFormatError(LogRaptorException):
    """Error in the format of the processed log data."""
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!FormatError: {0}'.format(message))


class LogRaptorConfigError(LogRaptorException):
    """Error in a configuration file or a misconfiguration of the package."""
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!ConfigError: {0}'.format(message))


class LogRaptorArgumentError(LogRaptorException):
    def __init__(self, argument=None, message=None):
        if message is None:
            message = 'syntax error for argument {0}'.format(argument)
        else:
            message = 'argument {0}: {1}'.format(argument, message)
        Exception.__init__(self, message)


class LogRaptorNoSectionError(LogRaptorException, configparser.NoSectionError):
    def __init__(self, section):
        super(LogRaptorNoSectionError, self).__init__(section)


class LogRaptorNoOptionError(LogRaptorException, configparser.NoOptionError):
    def __init__(self, option, section):
        super(LogRaptorNoOptionError, self).__init__(option, section)


class LogRaptorOptionError(LogRaptorException):
    """Error in an option value or conflict between options."""
    def __init__(self, option, message=None):
        if message is None:
            message = 'syntax error for option %r' % option
        else:
            message = 'option %r: %s' % (option, message)
        Exception.__init__(self, message)
        logger.debug('!OptionError: {0}'.format(message))


class RuleMissingError(LogRaptorException):
    """Raised when a rule definition is missing."""
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!RuleMissingError: {0}'.format(message))


class FileMissingError(LogRaptorException):
    """Raised when a file is missing."""
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!FileMissingError: {0}'.format(message))


class FileAccessError(LogRaptorException):
    """Raised when an existing file cannot be accessed."""
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!FileAccessError: {0}'.format(message))


__all__ = ['LogRaptorException', 'LogFormatError', 'LogRaptorNoOptionError',
           'LogRaptorArgumentError', 'LogRaptorNoSectionError', 'LogRaptorConfigError',
           'LogRaptorOptionError', 'RuleMissingError', 'FileMissingError', 'FileAccessError']
