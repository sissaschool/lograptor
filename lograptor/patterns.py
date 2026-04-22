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
import re
import socket
import string
import pwd
from argparse import Namespace
from collections import namedtuple
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from itertools import chain, pairwise
from typing import Any

_sentinel_dict = {}

class PatternTemplate(string.Template):
    """Provides a template class that uses '%' as the delimiter for pattern substitutions."""
    delimiter = '%'
    # idpattern = None
    #braceidpattern = r'(?a:[_a-z][_a-z0-9]*)'
    #flags = 0

    def safe_expand(self, substitution_map: dict[str, str]) -> str:
        """
        Safe string template expansion performing multiple substitution until there
        are no changes, taking the length of the substitution maps as the limit for
        stopping the substitution and raising an error.
        """
        _template = self.template
        try:
            for _ in range(len(substitution_map) + 1):
                template = self.safe_substitute(substitution_map)
                if template == self.template:
                    return template
                self.template = template
            else:
                raise RuntimeError("substitution map has circularity!")
        finally:
            self.template = _template


@cache
def get_pattern(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


@dataclass
class FieldInfo:
    pattern: str
    field: str
    datatype: type[str | int | float | bool] = str

    @classmethod
    def from_spec(cls, spec: str) -> 'PatternInfo':
        parts = spec.split(':')
        if any(not p.isidentifier() for p in parts) or len(parts) > 3 or len(parts) < 2 \
                or not parts[0].isupper() or not parts[1].islower():
            raise ValueError(f"invalid pattern specification: {spec!r}")

        if len(parts) == 2:
            return cls(parts[0], parts[1])

        match parts[2]:
            case 'str':
                return cls(parts[0], parts[1], str)
            case 'int':
                return cls(parts[0], parts[1], int)
            case 'float':
                return cls(parts[0], parts[1], float)
            case 'bool':
                return cls(parts[0], parts[1], bool)
            case _:
                raise ValueError(f"invalid pattern specification: {spec!r}")


def get_raw_pattern(pattern: str) -> str:
    """Translate a pattern string that contains %{...} rules to a raw pattern string."""
    pattern  = pattern.replace('\n', '')
    if not '%{' in pattern:
        return pattern  # Nothing to do

    chunks = pattern.split('%{')
    for left, right in pairwise(range(len(chunks))):
        i = 1
        while i < len(chunks[left]) and chunks[left][-i] == '%':
            i += 1

        if (i - 1) % 2:
            chunks[left] = chunks[left] + '%{'
            continue

        if '}' not in chunks[right]:
            chunks[left] = chunks[left] + '%{'
            continue

        pos = chunks[right].index('}')
        spec = chunks[right][:pos]
        if ':' in spec:
            try:
                field_info = FieldInfo.from_spec(spec)
            except ValueError:
                pass
            else:
                chunks[left] += f"(?P<{field_info.field}>%{{{field_info.pattern}}})"
                chunks[right] = chunks[right][pos + 1:]
                continue

        chunks[left] = chunks[left] + '%{'

    return ''.join(chunks).replace('%%', '%')
