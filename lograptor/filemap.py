# -*- coding: utf-8 -*-
"""
This module contains classes to handle iteration over log files.
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
import logging
import fnmatch
import ntpath
import glob
import os
import platform
from datetime import datetime
from collections import MutableMapping
from .timedate import strftimegen

logger = logging.getLogger(__name__)


class GlobDict(MutableMapping):
    """
    A dictionary that use pathnames patterns as keys.
    Include two additional methods glob and iglob to iterate
    once over dictionary pathnames, returning a couple with filename
    and a list of values, corresponding to the values of dictionary
    keys that matches the filename.
    """
    def __init__(self, recursive=False, followlinks=False, include=None,
                 exclude=None, exclude_dir=None, *args, **kwargs):
        self._data = dict()
        self._pathnames = []
        self.update(*args, **kwargs)
        self.recursive = recursive
        self.followlinks = followlinks
        self.include = include or []
        self.exclude = exclude or []
        self.exclude_dir = exclude_dir or []

    def __getitem__(self, path):
        if not isinstance(path, str):
            raise TypeError("path must be a string")
        return self._data[path]

    def __setitem__(self, path, value):
        if not isinstance(path, str):
            raise TypeError("path must be a string")
        if path not in self._data:
            # Update _globs paths
            items = set()
            for pathname in self._pathnames:
                if fnmatch.fnmatch(path, pathname):
                    break
                if fnmatch.fnmatch(pathname, path):
                    items.add(pathname)
            else:
                self._pathnames.append(path)
            if items:
                self._pathnames = [i for i in self._pathnames if i not in items]
        self._data[path] = value

    def __delitem__(self, path):
        for pathname in self._pathnames:
            if fnmatch.fnmatch(path, pathname):
                break
        del self._data[path]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def is_included(self, path):
        basename = ntpath.basename(path)
        dirname = ntpath.dirname(path)
        if any([fnmatch.fnmatch(dirname, pat) for pat in self.exclude_dir]):
            return False
        elif any([fnmatch.fnmatch(basename, pat) for pat in self.exclude]):
            return False
        elif any([fnmatch.fnmatch(basename, pat) for pat in self.include]):
            return True
        else:
            return not self.include

    def iglob(self, path):
        for filename in glob.iglob(path):
            if self.is_included(filename):
                values = [v for k, v in self._data.items() if fnmatch.fnmatch(filename, k)]
                yield filename, values

    def glob(self, path):
        return list(self.iglob(path))

    def iter_paths(self, pathnames=None, mapfunc=None):
        pathnames = pathnames or self._pathnames
        if self.recursive and not pathnames:
            pathnames = ['.']
        elif not pathnames:
            yield []

        if mapfunc is not None:
            for pathgen in map(mapfunc, pathnames):
                for path in pathgen:
                    if self.recursive and (os.path.isdir(path) or os.path.islink(path)):
                        for t in os.walk(path, followlinks=self.followlinks):
                            for filename, values in self.iglob(os.path.join(t[0], '*')):
                                yield filename, values
                    else:
                        for filename, values in self.iglob(path):
                            yield filename, values
        else:
            for path in pathnames:
                if self.recursive and (os.path.isdir(path) or os.path.islink(path)):
                    for t in os.walk(path, followlinks=self.followlinks):
                        for filename, values in self.iglob(os.path.join(t[0], '*')):
                            yield filename, values
                else:
                    for filename, values in self.iglob(path):
                        yield filename, values


class FileMap(object):
    """
    A class for building collections of files and for iterating over them.
    """
    def __init__(self, time_range=None, *args, **kwargs):
        """
        :param start_dt: End datetime for filtering the iteration over files.
        When is None no date filter is applied to selected files.
        :param end_dt: End datetime for filtering the iteration over files.
        If it is None no filter is applied.
        :param include: list of include patterns

        """
        start_dt, end_dt = time_range or (None, None)
        if start_dt is not None and start_dt > end_dt:
            ValueError("start datetime mustn't be after the end datetime")
        self._filemap = GlobDict(*args, **kwargs)
        self._priority = {}
        self.start_dt = start_dt
        self.end_dt = end_dt

    def __iter__(self):
        """
        Iterate into the file map, with filename glob expansion.
        """
        if self.start_dt is None:
            for filename, items in self._filemap.iter_paths():
                items = [i for sublist in items for i in sublist]
                yield filename, sorted(items, key=lambda x: self._priority[x])
        else:
            for filename, items in self._filemap.iter_paths(mapfunc=strftimegen(self.start_dt, self.end_dt)):
                items = [i for sublist in items for i in sublist]
                if self.check_stat(filename):
                    yield filename, sorted(items, key=lambda x: self._priority[x])

    def __len__(self):
        return len(list(self.__iter__()))

    def check_stat(self, path):
        """
        Checks logfile stat information for excluding files not in datetime period.
        On Linux it's possible to checks only modification time, because file creation info
        are not available, so it's possible to exclude only older files.
        In Unix BSD systems and windows informations about file creation date and times are available,
        so is possible to exclude too newer files.
        """
        statinfo = os.stat(path)
        st_mtime = datetime.fromtimestamp(statinfo.st_mtime)
        if platform.system() == 'Linux':
            check = st_mtime >= self.start_dt
        else:
            st_ctime = datetime.fromtimestamp(statinfo.st_ctime)
            check = st_mtime >= self.start_dt and st_ctime <= self.end_dt

        if not check:
            logger.warning("file %r not in datetime period!", path)
        return check
             
    def add(self, fileset, name='*', priority=0):
        """
        Add a list of files with a reference to a name and a priority.
        """
        self._priority[name] = priority
        if isinstance(fileset, str):
            fileset = iter([fileset])
        for pathname in fileset:
            try:
                values = self._filemap[pathname]
            except KeyError:
                self._filemap[pathname] = [name]
            else:
                values.append(name)
