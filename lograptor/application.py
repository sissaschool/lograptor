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

import copy
import os
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

import lograptor.report
import lograptor.linecache
import lograptor.configmap

logger = logging.getLogger("lograptor")


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

    def __init__(self, name, pattern, filter_keys=None):
        """
        Initialize AppRule. Arguments passed include:

        :param name: the configuration option name
        :param pattern: the option value that rapresent the search pattern
        :param filter_keys: the filtering keys dictionary if the rule is a filter
        """
        try:
            self.regexp = re.compile(pattern)
        except RegexpCompileError:
            msg = 'Illegal pattern for app\'rule: "{0}"'.format(name)
            raise lograptor.LograptorConfigError(msg)

        self.name = name
        self.results = dict()
        self.filter_keys = filter_keys
        self.full_match = filter_keys is not None
        self.used_by_report = False
        
        key_gids = ['host']
        for gid in self.regexp.groupindex:
            if gid != 'host':
                key_gids.append(gid)
        self.key_gids = tuple(key_gids)

        if not self.key_gids:
            raise lograptor.LograptorConfigError("Rule gids set empty!")

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

    # Class internal processing attributes
    _filters = None         # Program instance filter options
    _filter_options = None  # Admitted filter options
    _report = None          # Report flag
    _thread = None          # Thread flag
    outmap = None           # Output mapping

    # Default values for application config files
    DEFAULT_CONFIG = {
        'main': {
            'desc': u'${appname}',
            'tags': u'${appname}',
            'files': u'${logdir}/messages',
            'enabled': True,
            'priority': 1,
        }
    }

    @staticmethod
    def set_options(args, config, filters, outmap):
        """
        Set class variables with runtime options. First check
        pattern rules related to provided filter options.
        """
        filter_names = set()
        for filter_group in filters:
            for name, pattern in filter_group.items():
                try:
                    re.compile(pattern)
                except RegexpCompileError:
                    msg = 'Wrong pattern specification in filter!: %s=%s'
                    raise lograptor.OptionError("-F", msg % (name, pattern))
                filter_names.add(name)

        AppLogParser.outmap = outmap
        AppLogParser._filters = copy.deepcopy(filters)
        AppLogParser._filter_options = tuple([
            key for key in config.options('fields')
        ])
        AppLogParser._report = args.report
        AppLogParser._thread = args.thread

    def __init__(self, name, cfgfile, args, config):
        """
        Create a app object reading the configuration from file
        """
        logger.info('Initializing app %r from configuration file %r.', name, cfgfile)

        # Check if class variables are initialized
        if self._filters is None:
            raise Exception
        
        # Setting class instance variables
        self.name = name            # Application name
        self.cfgfile = cfgfile   # Complete path to app config file
        self.rules = []             # Regexp rules for the app
        self.has_filters = False    # True if the app has filters 
        self.repitems = []          # Report items read from configuration
        self.counter = 0            # Parsed lines counter
        self.unparsed_counter = 0   # Unparsed lines counter

        # Setting other instance internal variables for process phase
        self._last_rule = self._last_idx = None

        extra_options = {'appname': self.name, 'logdir': config['logdir']}
        hostnames = list(set(args.hostnames))
        if len(hostnames) == 1:
            extra_options.update({'host': hostnames[0]})

        appconfig = lograptor.configmap.ConfigMap(cfgfile, self.DEFAULT_CONFIG, extra_options)

        self.desc = appconfig['desc']
        self.tags = appconfig['tags']
        self.files = list(set(re.split('\s*,\s*', appconfig['files'])))
        self.enabled = appconfig['enabled']
        self.priority = appconfig['priority']

        # Expand application's fileset if many hostsnames are provided
        if len(hostnames) > 1:
            filelist = set()
            for filename in self.files:
                for host in hostnames:
                    filelist.add(string.Template(filename)
                                 .safe_substitute({'host': host}))
            self.files = list(filelist)

        logger.info('App %r run fileset: %r', self.name, self.files)

        # Read app rules from configuration file. An app is disabled
        # when it doesn't have almost a rule.
        logger.debug('Load rules for app %r', self.name)
        try:
            rules = appconfig.parser.items('rules')
        except configparser.NoSectionError:
            raise lograptor.LograptorConfigError('No section [rules] in config file of app "{0}"'.format(self.name))
        if not rules:
            msg = 'an application must have at least a rule!'
            raise lograptor.LograptorConfigError(msg.format(self.name))
        
        self.add_rules(rules, config)
        
        # Read report items, used to manage
        # report composition from results.
        sections = appconfig.parser.sections()
        sections.remove('main')
        sections.remove('rules')
        
        for sect in filter(lambda x: x.startswith('report.'), sections):
            _sect = sect.partition('.')[2]
            try:
                repitem = lograptor.report.ReportItem(_sect, appconfig.parser.items(sect),
                                                      config.options('subreports'), self.rules)
            except lograptor.OptionError as msg:
                raise lograptor.LograptorConfigError('section "{0}" of "{1}": {2}'
                                                     .format(sect, os.path.basename(cfgfile), msg))
            except configparser.NoOptionError as msg:
                raise lograptor.LograptorConfigError('No option "{0}" in section "{1}" of configuration '
                                            'file "{1}"'.format(msg, sect, cfgfile))
            except lograptor.RuleMissingError as msg:
                logger.info(msg)
                continue

            self.repitems.append(repitem)

        # If 'unparsed' matching is disabled and there are filter rules then restrict
        # the set of rules to the minimal set useful for processing.
        if not args.unparsed and self.has_filters:
            logger.debug('Purge unused rules for %r app.', self.name)
            self.rules = [
                rule for rule in self.rules
                if rule.filter_keys is not None or rule.used_by_report or
                (self._thread and 'thread' in rule.regexp.groupindex)
            ]

        # If the app has filters, reorder rules putting filters first.
        if self.has_filters:
            self.rules = sorted(self.rules, key=lambda x: x.filter_keys is None)
        else:
            for rule in self.rules:
                rule.full_match = True

        logger.info('Valid filters for app %r: %d', self.name,
                    len([rule.name for rule in self.rules if rule.filter_keys is not None]))
        logger.info('Base rule set for app %r: %d', self.name,
                    [rule.name for rule in self.rules if rule.filter_keys is None])

        # Set threads cache using finally rules list
        if self._thread:
            self.cache = lograptor.linecache.LineCache()

    def add_rules(self, rules, config):
        """
        Add a set of rules to the app, dividing between filter and other rule set
        """
        for option, pattern in rules:
            # Strip optional string quotes and remove newlines
            pattern = pattern.replace('\n', '')

            if len(pattern) == 0:
                logger.debug('Rule %r is empty', option)
                raise lograptor.LograptorConfigError('Error in app "{0}" configuration: '
                                            'empty rules not admitted!'.format(option))

            # There are no filters, then adds each rule once substituting
            # the filter keys with the corresponding patterns.
            if not self._filters:
                for opt in self._filter_options:
                    pattern = string.Template(pattern).safe_substitute({opt: config[opt]})
                self.rules.append(AppRule(option, pattern))
                logger.debug('Add rule %r: %d', option, pattern)
                logger.debug('Rule %r gids : %r', option, self.rules[-1].key_gids)
                continue

            # Iterate over filter list. Each item is a set of filtering rules
            # to be applied with AND logical operator.
            for filter_group in self._filters:
                new_pattern = pattern
                filter_keys = list()
                for fltname, fltpat in filter_group.items():
                    next_pattern = string.Template(new_pattern).safe_substitute({fltname: fltpat})
                    if next_pattern != new_pattern:
                        filter_keys.append(fltname)
                    new_pattern = next_pattern

                # Substitute not used filters with default pattern matching string
                for opt in self._filter_options:
                    new_pattern = string.Template(new_pattern).safe_substitute({opt: config[opt]})

                # Exclude rule if not related to all filters of the group
                if len(filter_keys) < len(filter_group):
                    if self._thread:
                        self.rules.append(AppRule(option, new_pattern))
                        logger.debug('Add rule %r: %r', option, pattern)
                        logger.debug('Rule %r gids : %r', option, self.rules[-1].key_gids)
                    continue

                # Adding to app rules
                self.rules.append(AppRule(option, new_pattern, filter_keys))
                self.has_filters = True
                logger.debug('Add filter rule %r (%r): %r', option, u', '.join(filter_keys), new_pattern)
                logger.debug('Rule %r gids : %r', option, self.rules[-1].key_gids)

    def purge_unmatched_threads(self, event_time=0):
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
        Increase the last rule result by k.
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
