#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module contain general info about Lograptor package.
"""
##
# Copyright (C) 2011-2014 by SISSA and Davide Brunato
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# @Author Davide Brunato <brunato@sissa.it>
##

__author__ = "Davide Brunato"
__copyright__ = "Copyright 2011-2014, SISSA"
__credits__ = ["Davide Brunato"]
__license__ = "GPLv2+"
__version__ = "1.0"
__maintainer__ = "Davide Brunato"
__email__ = "brunato@sissa.it"
__status__ = "Production"
__description__ = ("Command-line utility for searching into log files. "
                   "Produces matching outputs and reports.")
LONG_DESCRIPTION =\
"""Lograptor is a tool which provides a command-line interface for system logs processing.

Pattern matching's searches can be performed together with filtering
rules and scope delimitation options. Each run can produce
a report that can be easily sent by e-mail or saved into a file system
directory.
The program can parse logs written in RFC 3164 and RFC 5424 formats.
Lograptor require Python >= 2.6, and is provided with a base configuration for a set
of well known applications. You can easily extend this set adding new applications
with specific pattern search rules.
"""
