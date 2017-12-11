#!/usr/bin/env python
"""
Execute lograptor module as a script (see PEP-338).
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

if not __package__:
    # When this module is runned without loading the package then
    # __package__ is None or '' and the relative imports are disabled.
    # In this case import the package and set __package__.
    #
    # $ python lograptor --> __package__ == ''
    # $ python lograptor/__main__.py --> __package__ is None
    #
    # Refer to https://www.python.org/dev/peps/pep-0366/ for details.
    import os
    import sys
    pkg_search_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if sys.path[0] != pkg_search_path:
        sys.path.insert(0, pkg_search_path)
    import lograptor
    __package__ = lograptor.__name__

from .api import main
main()
