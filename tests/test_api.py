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
import re
import sys

import lograptor
from lograptor.exceptions import (
    LogRaptorArgumentError, LogRaptorOptionError, LogRaptorConfigError,
    LogFormatError, FileMissingError, FileAccessError
)


CONFIG_FILES = ('lograptor.conf', 'test_lograptor.conf')


class TestCommandLineInterface(object):
    """
    Test which lograptor application have unparsed line issues.
    """
    cli_parser = lograptor.api.create_argument_parser()

    def setup_method(self, method):
        print("\n%s:%s" % (type(self).__name__, method.__name__))

    def exec_lograptor(self, cmd_line):
        args = self.cli_parser.parse_args(args=cmd_line.split())
        args.cfgfiles = CONFIG_FILES
