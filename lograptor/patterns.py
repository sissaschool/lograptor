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
import string
from dataclasses import dataclass
from functools import cache, cached_property
from itertools import pairwise


class PatternTemplate(string.Template):
    """Provides a template class that uses '%' as the delimiter for pattern substitutions."""
    delimiter = '%'
    # flags = 0

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


@dataclass(slots=True)
class PatternField:
    name: str
    pattern: str
    datatype: type[str | int | float | bool] = str

    @classmethod
    def from_spec(cls, spec: str) -> 'PatternField':
        parts = spec.split(':')
        if spec == 'POSINT:reason>':
            breakpoint()
        if any(not p.isidentifier() for p in parts) or len(parts) > 3 \
               or not parts[0].isupper() or len(parts) > 1 and not parts[1].islower():
            raise ValueError(f"invalid pattern specification: {spec!r}")

        if len(parts) == 1:
            return cls('_', parts[0], str)
        if len(parts) == 2:
            return cls(parts[1], parts[0], str)

        match parts[2]:
            case 'int' | 'long':
                return cls(parts[1], parts[0], int)
            case 'float' | 'double':
                return cls(parts[1], parts[0], float)
            case 'boolean':
                return cls(parts[1], parts[0], bool)
            case _:
                raise ValueError(f"invalid pattern specification: {spec!r}")


class RegexPattern:
    """
    A pattern that is in REGEX format. Not usable for expanding GrokPatterns/RulePatterns.
    The pattern is parsed for extracting the named groups, if any. If a GROK pattern is
    found in the pattern, a TypeError is raised.
    """
    __slots__ = ('pattern', '_pattern', 'fields')

    def __init__(self, pattern: str):
        self.pattern = pattern
        self._pattern, self.fields = self.parse_pattern(pattern)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.pattern!r}>"

    @classmethod
    def parse_pattern(cls, pattern: str) -> tuple[str, dict[str, PatternField]]:
        fields: dict[str, PatternField] = {}

        if '(?P<' in pattern:
            if issubclass(cls, GrokPattern):
                raise TypeError(f"{cls!r} doesn't allow REGEX named groups in pattern")

            # The rule pattern string is already in REGEX like format
            # Don't change the pattern, just extract the named groups.

            chunks = pattern.split('(?P<')
            for left, right in pairwise(range(len(chunks))):
                name, _, pattern = chunks[right].partition('>')[0]
                if name.isidentifier():
                    if name in fields:
                        raise ValueError(f"duplicated named group {name!r}")
                    if pattern.startswith('%{'):
                        if not issubclass(cls, RulePattern):
                            raise TypeError(f"{cls!r} doesn't allow GROK patterns in pattern")

                        spec = pattern[2:].partition('}')[0]
                        if ':' in spec:
                            raise ValueError(f"invalid pattern {pattern!r}: "
                                             f"cannot mix GROK patterns and REGEX named groups")
                        fields[name] = PatternField.from_spec(f'{spec}:{name}')
                    else:
                        fields[name] = PatternField(name, '')

            return pattern, fields

        # Extract and modify the GROK patterns fields from the origin pattern
        # the other named groups will be extract by Python regex parser.
        unnamed_index = 0
        chunks = pattern.split('%{')
        for left, right in pairwise(range(len(chunks))):

            # Check if the '%' is escaped
            i = 1
            while i < len(chunks[left]) and chunks[left][-i] == '%':
                i += 1
            if (i - 1) % 2:
                chunks[left] = chunks[left] + '%{'
                continue

            pos = chunks[right].index('}')
            spec = chunks[right][:pos]
            field = PatternField.from_spec(spec)

            if field.name in fields:
                raise ValueError(f"duplicate field name {field.name!r}")
            elif field.name == '_':
                if not issubclass(cls, RulePattern):
                    # Don't expand to an unnamed group if the pattern is not a rule pattern
                    chunks[left] = chunks[left] + '%{'
                    continue

                field.name = f'_{unnamed_index}'
                unnamed_index += 1
            elif not issubclass(cls, RulePattern):
                raise TypeError(f"{cls!r} doesn't allow named GROK fields")

            chunks[left] += f"(?P<{field.name}>%{{{field.pattern}}})"
            chunks[right] = chunks[right][pos + 1:]
            fields[field.name] = field

        return ''.join(chunks), fields


class GrokPattern(RegexPattern):
    """
    A pattern that is in REGEX format or simple GROK format (e.g., %{GROK_PATTERN}). Usable for
    expanding other GrokPatterns/RulePatterns. If a named GROK pattern (e.g., %{GROK_PATTERN:ID})
    is found in the given pattern, a TypeError is raised.
    """
    __slots__ = ()

    def expand(self, mapping: dict[str, str]) -> str:
        return PatternTemplate(self._pattern).safe_expand(mapping)


class RulePattern(GrokPattern):
    """
    A pattern for expanding application rules. The pattern argument can be in REGEX format
    or GROK format. Unnamed GROK patterns are expanded to "_%d" named groups. The parsed
    pattern is expanded at init, checking that the resulting pattern is fully expanded.
    """
    __slots__ = ('regex_pattern',)

    def __init__(self, pattern: str, mapping: dict[str, str], full: bool = True):
        super().__init__(pattern)
        self.regex_pattern = PatternTemplate(self._pattern).safe_expand(mapping)

        if full:
            missing = []
            for s in self.regex_pattern.split('%{')[1:]:
                name = s.partition('}')[0].partition(':')[0]
                if name.isidentifier():
                    missing.append(name)
            if missing:
                raise ValueError(f"{self!r}: missing fields {missing!r} in provided mapping")

    @property
    def compiled(self) -> re.Pattern[str]:
        return get_pattern(self._pattern)


