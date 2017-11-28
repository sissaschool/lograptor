# -*- coding: utf-8 -*-
"""
Command line tools for lograptor package.
"""
#
# Copyright (C), 2011-2017, by SISSA - International School for Advanced Studies.
#
# This file is part of lograptor.
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
# along with lograptor; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# See the file 'LICENSE' in the root directory of the present
# distribution for more details.
#
# @Author Davide Brunato <brunato@sissa.it>
#
from .core import LogRaptor
from .exceptions import *
from .api import ruled_matcher, unruled_matcher, unparsed_matcher
