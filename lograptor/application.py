"""
Module to manage lograptor applications
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
import re
import string
import configparser
from collections import Counter
from collections.abc import Sequence, Mapping
from functools import cached_property
from typing import Any, TYPE_CHECKING

from lograptor.logparsers import LogData
from lograptor.exceptions import LogRaptorConfigError, RuleMissingError, LogRaptorOptionError
from lograptor.confparsers import AppConfig
from lograptor.report import Report, ReportData
from lograptor.utils import field_multisub, exact_sub
from lograptor.patterns import RulePattern

if TYPE_CHECKING:
    from lograptor.runner import LogRaptor

logger = logging.getLogger(__package__)


class AppRule:
    """
    Class to manage application rules. The rules are used to
    parse the log lines and to store matching results.

    Attributes:
        - name: the rule option name in the app configuration file
        - pattern : the compiled regex pattern of the rule
        - results : dictionary of rule results
        - filter_keys: the filtering keys (all regex groups connected
            to those keys must be not Non to matching a rule)
        - full_match: determine if a rule match represents a full matching
                      for the line (needed for thread matching mode)
        - used_by_report : True if is used by a report rule
        - key_gids : map from gid to result key tuple index
    """
    __slots__ = ('name', '_pattern', 'pattern', 'app', 'key_gids', 'results', 'filter_keys',
                 'full_match', 'used_by_report', '_last_idx')

    key_gids: Sequence[str] | tuple[str, ...]
    results: Counter[Any]
    _last_idx: tuple[str, ...] | None

    def __init__(self, name: str,
                 pattern: RulePattern,
                 app: 'AppLogParser',
                 filter_keys: list[str] | None = None):
        """
        :param name: the option name in the rule section of the app configuration file
        :param pattern: the regex pattern of the rule to compile
        :param app: the application in which the rule is defined
        :param filter_keys: the filtering keys dictionary if the rule is a filter
        """

        try:
            if not pattern:
                raise LogRaptorConfigError('empty rule %r' % name)
            self.pattern = pattern.compiled
        except re.error as err:
            msg = "invalid pattern for app\'s rule {!r}: {}"
            raise LogRaptorConfigError(msg.format(name, str(err)))

        key_gids = ['host']
        for gid in self.pattern.groupindex:
            if gid != 'host':
                key_gids.append(gid)

        if not key_gids:
            raise LogRaptorConfigError("key gids set of the rule {!r} is empty!".format(name))
        self.key_gids = tuple(key_gids)

        self.name = name
        self.app = app

        self.filter_keys = filter_keys or []
        self.full_match = filter_keys is not None
        self.used_by_report = False
        self.results = Counter()
        self._last_idx = None

    def __repr__(self):
        return "%s(name=%r, app=%r)" % (self.__class__.__name__, self.name, self.app.name)

    def add_result(self, values: dict[str, str]):
        """
        Add a tuple or increment the value of an existing one
        in the rule results dictionary.
        """
        self._last_idx = tuple(values[gid] for gid in self.key_gids)
        self.results[self._last_idx] += 1

    def increase_last(self, n: int):
        """Increase the last result by a positive number."""
        if not isinstance(n, int) or n < 0:
            raise TypeError("argument must be a non-negative integer")
        if self._last_idx is not None:
            self.results[self._last_idx] += n

    def total_events(self, condition: str, value_field: str | None = None) -> int:
        """
        Returns total number of events in the rule's result set. The *condition* selects
        the events to count. If also a *value field* is provided the function computes
        the sum taking the product of each value times the correspondent event counter.
        """
        if condition == "*" and value_field is None:
            return sum(self.results.values())

        val = self.key_gids.index(value_field) if value_field is not None else None

        if condition == "*":
            tot = 0
            for key in self.results:
                tot += self.results[key] * int(key[val])
            return tot

        match = re.search(r'(\w+)(!=|==)\"([^\"]*)\"', condition)
        if match is None:
            return 0

        condition_index = self.key_gids.index(match.group(1))
        invert = (match.group(2) == '!=')
        condition_pattern = re.compile(match.group(3))

        tot = 0
        for key in self.results:
            match = condition_pattern.search(key[condition_index])
            if (not invert and match is not None) or (invert and match is None):
                if value_field is None:
                    tot += self.results[key]
                else:
                    tot += self.results[key] * int(key[val])
        return tot

    def top_events(self, num: int, value_field: str, usemax: bool, gid: str) \
            -> list[list[int | list[str]] | None]:
        """
        Returns a list with the top *num* list of events. Each element
        contains a value, indicating the number of events, and a list of
        matching gid values (usernames, email addresses, clients).
        Instead of calculating the top sum of occurrences a *value_field*
        should be provided to compute the max of a numeric value field or
        the sum of product of value field with events.
        """
        def classify():
            if value is None:
                return

            for j in range(num):
                if top[j] is None:
                    top[j] = [tot, [value]]
                    break
                elif tot == top[j][0]:
                    top[j][1].append(value)
                    break
                elif tot > top[j][0]:
                    top.insert(j, [tot, [value]])
                    break

        if not self.results:
            return []

        results = self.results
        top: list[list[int | list[str]] | None] = [None] * num
        pos = self.key_gids.index(gid)
        val = None

        # Compute top(max) if a value fld is provided
        if value_field is not None:
            val = self.key_gids.index(value_field)
            if usemax:
                i = 0
                for key in sorted(results.keys(), key=lambda x: (int(x[val]), x[pos]),
                                  reverse=True)[:num]:
                    top[i] = [int(key[val]), [key[pos]]]
                    i += 1
                return [res for res in top if res is not None]

        value = None
        tot = 0
        for key in sorted(results.keys(), key=lambda x: (x[pos])):
            if value is None or value != key[pos]:
                classify()
                value = key[pos]
                tot = results[key] if value_field is None else results[key] * int(key[val])
                continue
            tot += results[key] if value_field is None else results[key] * int(key[val])
        else:
            classify()

        del top[num:]
        return [res for res in top if res is not None]

    def list_events(self, condition: str, cols: int, fields: Mapping[Any, str]):
        """
        Return the list of events, with a specific order and filtered by a condition.
        An element of the list is a tuple with three items. The first is the main
        attribute (first field). The second field/label, usually a string that identifies
        the service. The third is a dictionary with a key-tuple composed by all other
        fields and values indicating the number of events associated.
        """
        def insert_row():
            """
            Internal function to flush results for a single tabkey to result list.
            """
            row = list(row_template)
            j = 0
            for n in range(cols):
                if row[n] is None:
                    if j == keylen:
                        row[n] = tabvalues
                    else:
                        row[n] = tabkey[j]
                    j += 1
            result_list.append(row)

        if not self.results:
            return []

        # Set local variables
        results = self.results
        pos = [self.key_gids.index(gid) for gid in fields if gid[0] != '"']
        has_cond = condition != "*"

        # If a condition is satisfied, then compile a pattern matching object
        if has_cond and (match := re.search(r'(\w+)(!=|==)\"([^\"]*)\"', condition)) is not None:
            condpos = self.key_gids.index(match.group(1))
            invert = (match.group(2) == '!=')
            recond = re.compile(match.group(3))
        else:
            condpos = None
            invert = None
            recond = None

        # Define the row template with places for values and fixed strings
        row_template: list[str | None] = []
        for i in range(cols):
            if fields[i][0] == '"':
                row_template.append(fields[i].strip('"'))
            else:
                row_template.append(None)

        # Set the processing table and reduced key length
        keylen: int = len(pos) - (len(fields) - cols) - 1
        tabvalues: dict[tuple[str, ...], int] = {}
        tabkey = None

        result_list: list[list[str | int]] = []

        for key in sorted(results, key=lambda x: x[pos[0]]):
            # Skip results that don't satisfy the condition
            if has_cond and recond is not None:
                try:
                    match = recond.search(key[condpos])
                except TypeError:
                    continue
                if (not invert and match is None) or (invert and match is not None):
                    continue

            new_tabkey = [key[pos[i]] for i in range(keylen)]
            if tabkey is None:
                tabkey = new_tabkey
            elif tabkey != new_tabkey:
                insert_row()
                tabvalues = dict()
                tabkey = [key[pos[i]] for i in range(keylen)]

            value = tuple([key[k] for k in pos[keylen:]])
            if value in tabvalues:
                tabvalues[value] += results[key]
            else:
                tabvalues[value] = results[key]

        if tabvalues:
            insert_row()
        return result_list


class AppLogParser:
    """
    Class for parsing application log rules and results.
    """
    __slots__ = ('__dict__', 'filters', 'name_cache', 'rules', 'filter_rules',
                 '_thread', 'matches', 'unparsed', '_last_rule', '_last_idx')

    _last_rule: AppRule | None

    def __init__(self, name: str,
                 cfgfile: str,
                 runner: 'LogRaptor'):
        """
        :param name: application name
        :param cfgfile: application config file
        :param runner: runner instance, that controls the parsing.
        """
        logger.debug('initialize app %r', name)

        self.name = name            # Application name
        self.cfgfile = cfgfile      # App configuration file
        self.runner = runner
        self.args = runner.args
        self.filters = runner.filters
        self.name_cache = runner.name_cache

        # Set instance internal variables for process phase
        self._report = runner.report
        self._thread = runner.args.thread
        self.matches = 0            # Parsed lines counter
        self.unparsed = 0           # Unparsed lines counter
        self._last_rule = None      # Last matched rule
        self._last_idx = None       # Last index matched

        self.config = AppConfig(cfgfiles=cfgfile, appname=name, logdir=runner.logdir)

        if logger.level <= logging.DEBUG:
            logger.debug('app %r run tags: %r', name, self.tags)
            logger.debug('app %r run files: %r', name, self.files)
            logger.debug('app %r: enabled=%r, priority=%s', name, self.enabled, self.priority)

        rules = self.parse_rules()
        self.filter_rules = [rule for rule in rules if rule.filter_keys]

        if self.filter_rules:
            # If the app has filters, reorder rules putting the filters first.
            self.rules = sorted(rules, key=lambda x: x.filter_keys)
            if logger.level <= logging.DEBUG:
                logger.debug('number or filter rules of app %r: %d', name, len(self.filter_rules))
                logger.debug('other rules of app %r: %d', name, len(self.rules) - len(self.filters))
        else:
            self.rules = rules
            for rule in rules:
                rule.full_match = True

        logger.info('initialized app %r with %d pattern rules', name, len(self.rules))

    def __repr__(self):
        return "%s(name=%r)" % (self.__class__.__name__, self.name)

    @cached_property
    def description(self) -> str:
        return self.config.get('main', 'description')

    @cached_property
    def tags(self) -> list[str]:
        return list(set(re.split(r'\s*,\s*', self.config.get('main', 'tags'))))

    @cached_property
    def enabled(self) -> bool:
        return self.config.getboolean('main', 'enabled')

    @cached_property
    def priority(self) -> int:
        return self.config.getint('main', 'priority')

    @cached_property
    def files(self) -> list[str]:
        files = list(set(re.split(r'\s*,\s*', self.config.get('main', 'files'))))
        return field_multisub(files, 'host', self.args.hosts or ['*'])

    @cached_property
    def has_filters(self) -> bool:
        return len(self.filter_rules) > 0

    @cached_property
    def report_data(self) -> list[ReportData]:
        if not isinstance(self._report, Report):
            return []

        subreports = [sr.name for sr in self._report.subreports]
        report_data = []
        for section in filter(lambda x: x not in ['main', 'rules'], self.config.sections()):
            options = self.config.items(section)
            try:
                data_item = ReportData(section, options, self.rules)
            except RuleMissingError as msg:
                logger.debug(msg)
            except LogRaptorOptionError as err:
                logger.error('skip report data %r for app %r: %s', section, self.name, err)
            else:
                report_data.append(data_item)

        return [e for e in report_data if e.subreport in subreports]

    def parse_rules(self) -> list[AppRule]:
        """
        Add a set of rules to the app, dividing between filter and other rule set
        """
        # Load patterns: an app is removed when has no defined patterns.
        try:
            rule_options = self.config.items('rules')
        except configparser.NoSectionError:
            raise LogRaptorConfigError("the app %r has no defined rules!" % self.name)

        rules = []
        mapping = self.runner.patterns_mapping
        for option, value in rule_options:
            value = value.replace('\n', '')
            pattern = RulePattern(value, mapping)

            if not self.args.filters:
                # No filters case: substitute the filter fields with the corresponding patterns.
                rules.append(AppRule(option, pattern, self))
            else:
                filter_keys = [s for s in self.args.filters if s in pattern.fields]
                if filter_keys:
                    rules.append(AppRule(option, pattern, self, filter_keys))
                else:
                    rules.append(AppRule(option, pattern, self))
        return rules

    def increase_last(self, n: int) -> None:
        """Increase the counter of the last matched rule by an integer value."""
        if self._last_rule is None:
            return
        try:
            self._last_rule.increase_last(n)
        except AttributeError:
            pass

    def match_rules(self, log_data: LogData) \
            -> tuple[bool, bool | None, str | None, dict[str, str] | None]:
        """
        Process a log line data message with app's pattern rules.
        Return a tuple with this data:

            Element #0 (app_matched): True if a rule match, False otherwise;
            Element #1 (has_full_match): True if a rule match and is a filter or the
                app has not filters; False if a rule match but is not a filter;
                None otherwise;
            Element #2 (app_thread): Thread value if a rule match, and it has a "thread"
                group, None otherwise;
            Element #3 (output_data): Mapping dictionary if a rule match and a map
                of output is requested (--anonymize/--ip/--uid options).
        """
        for rule in self.rules:
            match = rule.pattern.search(log_data.message)
            if match is not None:
                gids = rule.pattern.groupindex
                self._last_rule = rule
                if self.name_cache is not None:
                    values = self.name_cache.match_to_dict(match, rule.key_gids)
                    values['host'] = self.name_cache.map_value(log_data.host, 'host')
                    output_data = {
                        'host': values['host'],
                        'message': self.name_cache.match_to_string(match, gids, values),
                    }
                else:
                    values = {'host': log_data.host}
                    for gid in gids:
                        values[gid] = match.group(gid)
                    output_data = None

                if self._thread and 'thread' in rule.pattern.groupindex:
                    thread = match.group('thread')
                    if rule.filter_keys is not None and \
                            any([values[key] is None for key in rule.filter_keys]):
                        return False, None, None, None
                    if self._report:
                        rule.add_result(values)
                    return True, rule.full_match, thread, output_data
                else:
                    if rule.filter_keys is not None and \
                            any([values[key] is None for key in rule.filter_keys]):
                        return False, None, None, None
                    elif self._report or (rule.filter_keys is not None or not self.filter_rules):
                        rule.add_result(values)
                    return True, rule.full_match, None, output_data

        # No rule match: the application log message is not parsable with enabled rules.
        self._last_rule = None
        return False, None, None, None
