"""
This module defines classes to handle iteration over log files.
"""
#
# Copyright (C), 2011-2026, by SISSA - International School for Advanced Studies.
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
import fnmatch
import ntpath
import glob
import os
import platform
from datetime import datetime
from collections.abc import MutableMapping, Iterable
from functools import partial
from typing import Any

from lograptor.timedate import generate_datetime_formats

logger = logging.getLogger(__name__)


class GlobDict(MutableMapping[str, Any]):
    """
    A dictionary that uses glob patterns as keys. Includes two additional methods
    glob and iglob to iterate once over dictionary glob patterns, returning couples
    with a path and a list of values.
    """
    __slots__ = ('_data', '_paths', 'recursive', 'follow_symlinks',
                 'include', 'exclude', 'exclude_dir')

    def __init__(self,
                 recursive: bool = False,
                 follow_symlinks: bool = False,
                 include: list[str] | None = None,
                 exclude: list[str] | None = None,
                 exclude_dir: list[str] | None = None):

        self._data = {}
        self._paths = []
        self.recursive = recursive
        self.follow_symlinks = follow_symlinks
        self.include = include or []
        self.exclude = exclude or []
        self.exclude_dir = exclude_dir or []

    def __getitem__(self, path: str):
        if not isinstance(path, str):
            raise TypeError("path must be a string")
        return self._data[path]

    def __setitem__(self, path: str, value):
        if not isinstance(path, str):
            raise TypeError("path must be a string")
        if path not in self._data:
            # Update _globs paths
            items = set()
            for pathname in self._paths:
                if fnmatch.fnmatch(path, pathname):
                    break
                if fnmatch.fnmatch(pathname, path):
                    items.add(pathname)
            else:
                self._paths.append(path)
            if items:
                self._paths = [i for i in self._paths if i not in items]
        self._data[path] = value

    def __delitem__(self, path: str):
        for pathname in self._paths:
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
                values = {app for k, v in self._data.items()
                          if fnmatch.fnmatch(filename, k) for app in v}
                yield filename, list(values)

    def glob(self, path):
        return list(self.iglob(path))

    def iter_paths(self, paths: Iterable[str] | None = None,
                   mapper=None):
        """
        Special iteration on paths. Yields couples of path and items. If an expanded path
        doesn't match with any files a couple with path and `None` is returned.

        :param paths: Iterable with a set of filepaths. If is `None` uses the all \
        the stored paths.
        :param mapper: A mapping function for building the effective path from various \
        wildcards (e.g. time spec wildcards).
        :return: Yields 2-tuples.
        """
        paths = paths or self._paths
        if self.recursive and not paths:
            paths = ['.']
        elif not paths:
            yield []

        if mapper is not None:
            for mapped_paths in map(mapper, paths):
                for path in mapped_paths:
                    if self.recursive and (os.path.isdir(path) or os.path.islink(path)):
                        for t in os.walk(path, followlinks=self.follow_symlinks):
                            for filename, values in self.iglob(os.path.join(t[0], '*')):
                                yield filename, values
                    else:
                        empty_glob = True
                        for filename, values in self.iglob(path):
                            yield filename, values
                            empty_glob = False
                        if empty_glob:
                            yield path, None
        else:
            for path in paths:
                if self.recursive and (os.path.isdir(path) or os.path.islink(path)):
                    for t in os.walk(path, followlinks=self.follow_symlinks):
                        for filename, values in self.iglob(os.path.join(t[0], '*')):
                            yield filename, values
                else:
                    empty_glob = True
                    for filename, values in self.iglob(path):
                        yield filename, values
                        empty_glob = False
                    if empty_glob:
                        yield path, None


class FileMap:
    """A class for building collections of files and iterating over them."""

    __slots__ = ('_filemap', 'start_dt', 'end_dt')

    def __init__(self,
                 time_period: tuple[datetime | None, datetime | None] | None =None,
                 recursive: bool = False,
                 follow_symlinks: bool = False,
                 include: list[str] | None = None,
                 exclude: list[str] | None = None,
                 exclude_dir: list[str] | None = None):
        """
        :param time_period: Time period for filtering the iteration over files. \
        When is `(None, None)` no filter is applied to selected files.
        """
        start_dt, end_dt = time_period or (None, None)
        if start_dt is not None and end_dt is not None and start_dt > end_dt:
            ValueError("start datetime must not be after the end datetime")
        self._filemap = GlobDict(
            recursive=recursive,
            follow_symlinks=follow_symlinks,
            include=include,
            exclude=exclude,
            exclude_dir=exclude_dir
        )
        self.start_dt = start_dt
        self.end_dt = end_dt

    def __iter__(self):
        """
        Iterate into the file map, with filename glob expansion.
        """
        if self.start_dt is None:
            for path, items in self._filemap.iter_paths():
                yield path, items
        else:
            func = partial(generate_datetime_formats, start_dt=self.start_dt, end_dt=self.end_dt)
            for path, items in self._filemap.iter_paths(mapper=func):
                if items is None:
                    yield path, items
                elif self.check_stat(path):
                    yield path, items

    def __len__(self):
        return len(list(self.__iter__()))

    def check_stat(self, path: str):
        """
        Checks logfile stat information for excluding files not in datetime
        period. On Linux it's possible to checks only modification time,
        because file creation info are not available, so it's possible to
        exclude only older files. In Unix BSD systems and windows information
        about file creation date and times are available, so is possible to
        exclude too newer files.
        """
        st_info = os.stat(path)
        st_mtime = datetime.fromtimestamp(st_info.st_mtime)
        if platform.system() == 'Linux':
            check = st_mtime >= self.start_dt
        else:
            st_ctime = datetime.fromtimestamp(st_info.st_ctime)
            check = st_mtime >= self.start_dt and st_ctime <= self.end_dt

        if not check:
            logger.info("file %r not in datetime period!", path)
        return check

    def add(self, files, items):
        """
        Add a list of files with a reference to a list of objects.
        """
        if isinstance(files, (str, bytes)):
            files = iter([files])
        for pathname in files:
            try:
                values = self._filemap[pathname]
            except KeyError:
                self._filemap[pathname] = items
            else:
                values.extend(items)
