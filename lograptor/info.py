# -*- coding: utf-8 -*-
"""
This module contain general info about Lograptor package.
"""
#
# Copyright (C), 2011-2016, by Davide Brunato and
# SISSA (Scuola Internazionale Superiore di Studi Avanzati).
#
# This file is part of Lograptor.
#
# Lograptor is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# See the file 'LICENSE' in the root directory of the present
# distribution or http://www.gnu.org/licenses/gpl-2.0.en.html.
#
# @Author Davide Brunato <brunato@sissa.it>
#

__author__ = "Davide Brunato"
__copyright__ = "Copyright 2011-2016, SISSA"
__credits__ = ["Davide Brunato"]
__license__ = "GPLv2+"
__version__ = "1.1a"
__maintainer__ = "Davide Brunato"
__email__ = "brunato@sissa.it"
__status__ = "Development"
__description__ = ("Command-line utility for processing log files. "
                   "Produces matching outputs, data and reports.")
LONG_DESCRIPTION = """
Lograptor is a tool which provides a command-line interface for system logs processing.

Pattern matching's searches can be performed together with filtering
rules and scope delimitation options. Each run can produce data and
a report that can be easily sent by e-mail or saved into a file system
directory.
The program can parse logs written in RFC 3164 and RFC 5424 formats.
Lograptor require Python >= 2.7, and is provided with a base configuration for a set
of well known applications. You can easily extend this set adding new applications
with specific pattern search rules.
"""
