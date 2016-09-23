# -*- coding: utf-8 -*-
"""
Module to manage Lograptor applications
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
import logging
import re
import string
from sre_constants import error as RegexpCompileError

try:
    import configparser
except ImportError:
    # Fall back for Python 2.x
    import ConfigParser as configparser

try:
    import pwd
except ImportError:
    pwd = None

from .exceptions import LograptorConfigError, RuleMissingError
from .configmap import ConfigMap
from .report import ReportItem
from .cache import LineCache
from .utils import field_multisub, exact_sub


logger = logging.getLogger(__name__)


class AppRule(object):
    """
    Class to manage application rules. The rules are used to
    parse the log lines and to store matching results.

    Attributes:
        - name: the rule option name in the app configuration file
        - regexp : re.compile object for rule pattern
        - results : dictionary of rule results
        - filter_keys: the filtering keys (all regex groups connected
            to those keys must be not Non to matching a rule)
        - full_match: determine if a rule match represents a full matching
                      for the line (needed for thread matching mode)
        - used_by_report : True if is used by a report rule
        - key_gids : map from gid to result key tuple index
    """

    def __init__(self, name, pattern, args, filter_keys=None):
        """
        Initialize AppRule. Arguments passed include:

        :param name: the configuration option name
        :param pattern: the option value that rapresent the search pattern
        :param filter_keys: the filtering keys dictionary if the rule is a filter
        """
        try:
            if not pattern:
                raise LograptorConfigError('empty rule %r' % name)
            self.regexp = re.compile(pattern)
        except RegexpCompileError:
            raise LograptorConfigError("illegal regex pattern for app\'rule: %r" % name)

        self.name = name
        self.args = args
        self.filter_keys = filter_keys or {}
        self.full_match = filter_keys is not None
        self.used_by_report = False
        self.results = dict()

        key_gids = ['host']
        for gid in self.regexp.groupindex:
            if gid != 'host':
                key_gids.append(gid)
        self.key_gids = tuple(key_gids)

        if not self.key_gids:
            raise LograptorConfigError("rule gids set empty!")

        self._last_idx = None

    def add_result(self, values):
        """
        Add a tuple or increment the value of an existing one
        in the rule results dictionary.
        """

        idx = [values['host']]
        for gid in self.key_gids[1:]:
            idx.append(values[gid])
        idx = tuple(idx)

        try:
            self.results[idx] += 1
        except KeyError:
            self.results[idx] = 1
        self._last_idx = idx

    def increase_last(self, k):
        """
        Increase the last result by k.
        """
        idx = self._last_idx
        if idx is not None:
            self.results[idx] += k

    def is_used(self):
        return (
            True or
            not self.args.filters or self.filter_keys or
            self.args.thread and 'thread' in self.regexp.groupindex or
            self.used_by_report or self.args.unparsed
        )

    def has_results(self):
        """
        Returns true if the rule has results.
        """
        return self.results

    def total_events(self, cond, valfld=None):
        """
        Return total number of events in the rule'result set. A condition
        could be provided to select the events to count. If value field (valfld)
        is passed the function compute the sum taking the product of each value with
        correspondent event counter.
        """
        results = self.results

        if cond == "*" and valfld is None:
            return sum(results.values())
        val = self.key_gids.index(valfld) if valfld is not None else None

        if cond == "*":
            tot = 0
            for key in results:
                tot += results[key] * int(key[val])
            return tot
            
        match = re.search("(\w+)(!=|==)\"([^\"]*)\"", cond)
        condpos = self.key_gids.index(match.group(1))
        invert = (match.group(2) == '!=')
        recond = re.compile(match.group(3))

        tot = 0
        for key in results:
            match = recond.search(key[condpos])
            if (not invert and match is not None) or (invert and match is None):
                if valfld is None:
                    tot += results[key]
                else:
                    tot += results[key] * int(key[val])
        return tot

    def top_events(self, num, valfld, usemax, gid):
        """
        Return a list with the top NUM list of events. Each list element
        contain a value, indicating the number of events, and a list of
        correspondind gid values (usernames, email addresses, clients).
        Instead of calculating the top sum of occurrences a value field
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
        top = [None] * num
        pos = self.key_gids.index(gid)

        # Compute top(max) if a value fld is provided
        if valfld is not None:
            val = self.key_gids.index(valfld)
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
                tot = results[key] if valfld is None else results[key] * int(key[val])
                continue
            tot += results[key] if valfld is None else results[key] * int(key[val])
        else:
            classify()

        del top[num:]
        return [res for res in top if res is not None]

    def list_events(self, cond, cols, fields):
        """
        Return the list of events, with a specific order and filtered by a condition.
        An element of the list is a tuple with three component. The first is the main
        attribute (first field). The second the second field/label, usually a string
        that identify the service. The third is a dictionary with a key-tuple composed
        byall other fields and values indicating the number of events associated.
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
            reslist.append(row)

        if not self.results:
            return []

        # Set local variables
        results = self.results
        pos = [self.key_gids.index(gid) for gid in fields if gid[0] != '"']
        has_cond = cond != "*"

        # If a condition is passed then compile a pattern matching object
        if has_cond:
            match = re.search("(\w+)(!=|==)\"([^\"]*)\"", cond)
            condpos = self.key_gids.index(match.group(1))
            invert = (match.group(2) == '!=')
            recond = re.compile(match.group(3))
        else:
            recond = condpos = None

        # Define the row template with places for values and fixed strings
        row_template = []
        for i in range(cols):
            if fields[i][0] == '"':
                row_template.append(fields[i].strip('"'))
            else:
                row_template.append(None)

        # Set the processing table and reduced key length
        keylen = len(pos) - (len(fields) - cols) - 1
        tabvalues = dict()
        tabkey = None

        reslist = []
        for key in sorted(results, key=lambda x: x[pos[0]]):
            # Skip results that don't satisfy the condition
            if has_cond:
                try:
                    match = recond.search(key[condpos])
                except TypeError:
                    continue
                if ((match is None) and not invert) or ((match is not None) and invert):
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
        return reslist


class AppLogParser(object):
    """
    Class to manage application log rules and results
    """
    # Default values for application config files
    DEFAULT_CONFIG = {
        'main': {
            'description': '${appname}',
            'tags': '${appname}',
            'files': '${logdir}/messages',
            'enabled': True,
            'priority': 1,
        }
    }

    def __init__(self, name, cfgfile, args, config, outmap):
        """
        :param name: application name
        :param cfgfile: application config file
        :param args: cli arguments
        :param config: program configuration
        """
        logger.info('initialize app %r', name)

        self.name = name            # Application name
        self.cfgfile = cfgfile      # App configuration file
        self.args = args
        self.config = config
        self.outmap = outmap
        self.fields = dict(config.items('fields'))

        # Setting instance internal variables for process phase
        self._report = args.report
        self._thread = args.thread
        self.counter = 0            # Parsed lines counter
        self.unparsed_counter = 0   # Unparsed lines counter
        self._last_rule = None      # Last matched rule
        self._last_idx = None       # Last index matched

        self.appconfig = ConfigMap(
            cfgfile, self.DEFAULT_CONFIG,
            logdir=config.getstr('main', 'logdir'),
            appname=name, host=args.hostnames
        )

        self.description = self.appconfig.getstr('main', 'description')
        self.tags = list(set(re.split('\s*,\s*', self.appconfig.getstr('main', 'tags'))))
        self._files = list(set(re.split('\s*,\s*', self.appconfig.getstr('main', 'files'))))
        self.enabled = self.appconfig.getbool('main', 'enabled')
        self.priority = self.appconfig.getint('main', 'priority')
        self.files = field_multisub(self._files, 'host', args.hostnames or ['*'])
        if self._thread:
            self.cache = LineCache()

        logger.info('app %r run tags: %r', name, self.tags)
        logger.info('app %r run files: %r', name, self.files)
        logger.info('app %r: enabled=%r, priority=%s', name, self.enabled, self.priority)

        # Load rules: an app is removed when has no rules.
        try:
            rule_options = self.appconfig.items('rules')
        except configparser.NoSectionError:
            raise LograptorConfigError("the app %r has no defined rules!" % name)
        else:
            rules = self.create_rules(rule_options)

        if args.report is not None:
            # Add report items
            self.repitems = []
            sections = self.appconfig.base_sections()
            for sect in filter(lambda x: x.startswith('report.'), sections):
                _sect = sect.split('.', 1)[1]
                options = self.appconfig.items(sect)
                subreports = config.options('subreports')
                try:
                    self.repitems.append(
                        ReportItem(_sect, options, subreports, rules)
                    )
                except RuleMissingError as msg:
                    logger.error(msg)

        if False and any([rule for rule in rules if not rule.is_used()]):
            self.rules = [rule for rule in rules if rule.is_used()]
            logger.info("purged %d unused rules" % (len(rules) - len(self.rules)))
        else:
            self.rules = rules

        self.has_filters = any([rule.filter_keys for rule in self.rules])
        if self.has_filters:
            # If the app has filters, reorder rules putting the filters first.
            self.rules = sorted(self.rules, key=lambda x: x.filter_keys)
            logger.info('filter rules for app %r: %d', name, len(self.filters))
            logger.info('simple rules for app %r: %d', name, len(self.rules) - len(self.filters))
        else:
            for rule in self.rules:
                rule.full_match = True
            logger.info('created %d rules for app %r', len(self.rules), name)

    def __repr__(self):
        return u"<%s '%s' at %#x>" % (self.__class__.__name__, self.name, id(self))

    @property
    def filters(self):
        return [rule for rule in self.rules if rule.filter_keys]

    def create_rules(self, rule_options):
        """
        Add a set of rules to the app, dividing between filter and other rule set
        """
        rules = []
        for option, value in rule_options:
            pattern = value.replace('\n', '')  # Strip newlines for multiline declarations

            if not self.args.filters:
                # No filters case: substitute the filter fields with the corresponding patterns.
                pattern = string.Template(pattern).safe_substitute(self.fields)
                rules.append(AppRule(option, pattern, self.args))
                continue

            for filter_group in self.args.filters:
                pattern, filter_keys = exact_sub(pattern, filter_group)
                pattern = string.Template(pattern).safe_substitute(self.fields)
                if len(filter_keys) >= len(filter_group):
                    rules.append(AppRule(option, pattern, self.args, filter_keys))
                elif self._thread:
                    rules.append(AppRule(option, pattern, self.args))

        return rules

    def purge_threads(self, event_time=0):
        """
        Purge the old unmatched threads from application's results.
        """
        cache = self.cache.data
        for rule in self.rules:
            try:
                pos = rule.key_gids.index('thread')
            except ValueError:
                continue

            purge_list = []
            for idx in rule.results:
                thread = idx[pos]
                if thread in cache:
                    if not (cache[thread].pattern_match and cache[thread].full_match) and \
                            (abs(event_time - cache[thread].end_time) > 3600):
                        purge_list.append(idx)

            for idx in purge_list:
                del rule.results[idx]

    def increase_last(self, k):
        """
        Increase the counter of the last mached rule by k.
        """
        rule = self._last_rule
        if rule is not None:
            rule.increase_last(k)

    def process(self, logdata):
        """
        Process a log line data message with app's regex rules.
        Return a tuple with this data:

            Element #0 (rule_match): True if a rule match, False otherwise;
            Element #1 (full_match): True if a rule match and is a filter or the app
                has not filters; False if a rule match but is not a filter;
                None otherwise;
            Element #2 (app_thread): Thread value if a rule match and it has a "thread"
                group, None otherwise;
            Element #3 (map_dict): Mapping dictionary if a rule match and a map
                of output is requested (--anonymize/--ip/--uid options).
        """
        for rule in self.rules:
            match = rule.regexp.search(logdata.message)
            if match is not None:
                logger.debug('Rule %r match', rule.name)
                gids = rule.regexp.groupindex
                self._last_rule = rule

                if self.outmap is not None:
                    outmap = self.outmap
                    values = outmap.map2dict(rule.key_gids, match)
                    values['host'] = outmap.map_value('host', logdata.host)
                    map_dict = {
                        'host': values['host'],
                        'message': outmap.map2str(gids, match, values),
                    }
                else:
                    values = {'host': logdata.host}
                    for gid in gids:
                        values[gid] = match.group(gid)
                    map_dict = None

                if self._thread and 'thread' in rule.regexp.groupindex:
                    thread = match.group('thread')
                    if rule.filter_keys is not None and \
                            any([values[key] is None for key in rule.filter_keys]):
                        return False, None, None, None
                    if self._report:
                        rule.add_result(values)
                    return True, rule.full_match, thread, map_dict
                else:
                    if rule.filter_keys is not None and \
                            any([values[key] is None for key in rule.filter_keys]):
                        return False, None, None, None
                    elif self._report or (rule.filter_keys is not None or not self.has_filters):
                        rule.add_result(values)
                    return True, rule.full_match, None, map_dict

        # No rule match: the application log message is unparsable
        # by enabled rules.
        self._last_rule = None
        if not self.has_filters:
            self.unparsed_counter += 1
        return False, None, None, None
