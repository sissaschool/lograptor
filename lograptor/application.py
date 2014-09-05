#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Module to manage Lograptor applications
"""
##
# Copyright (C) 2012 by SISSA
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# @Author Davide Brunato <brunato@sissa.it>
##

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
    from collections import OrderedDict
except ImportError:
    # Backport for Python 2.4-2.6 (from PyPI)
    from lograptor.backports.ordereddict import OrderedDict

try:
    import pwd
except ImportError:
    pwd = None

import lograptor.report
import lograptor.linecache
import lograptor.configmap

logger = logging.getLogger("lograptor")


class AppRule:
    """
    Class to manage application rules. The rules are used to
    parse the log lines and to store matching results.

    Attributes:
        - name: the rule option name in the app configuration file
        - regexp : re.compile object for rule pattern
        - results : dictionary of rule results
        - is_filter : True if the rule is connected to a filter option
        - used_by_report : True if is used by a report rule
        - key_gids : map from gid to result key tuple index
    """

    # Address and username traslation dictionaries
    # Address and username traslation dictionaries
    _ip_lookup = False
    _uid_lookup = False

    def __init__(self, name, pattern, is_filter, outmap):
        """
        Initialize AppRule. Arguments passed include:

            - name: the configuration option name
            - pattern: the option value that rapresent the search pattern
            - is_filter: a flag that indicate if the rule is a filter
            - thread_matching: indicate when thread matching is active

        """
        try:
            self.regexp = re.compile(pattern)
        except RegexpCompileError:
            msg = 'Wrong pattern in configuration: "{0}"'.format(pattern)
            raise lograptor.ConfigError(msg)

        self.name = name
        self.results = dict()
        self.is_filter = is_filter
        self.used_by_report = False
        self.outmap = outmap
        
        key_gids = ['hostname']
        for gid in self.regexp.groupindex:
            if gid != 'hostname':
                key_gids.append(gid)
        self.key_gids = tuple(key_gids)

        if not self.key_gids:
            raise lograptor.ConfigError("Rule gids set empty!")

    @staticmethod
    def set_ip_lookup(value):
        """
        Set the flag for IP addresses lookup of 'client' and 'ipaddr' gid values
        """
        AppRule._ip_lookup = bool(value)

    @staticmethod
    def set_uid_lookup(value):
        """
        Set the flag for uid lookup of 'user' and 'uid' gid values
        """
        AppRule._uid_lookup = bool(value)

    def add_result2(self, hostname, match):
        """
        Add a tuple or increment the value of existing one
        in the rule results dictionary
        """
        idx = [hostname]
        ip_lookup = self._ip_lookup
        uid_lookup = self._uid_lookup
        for gid in self.key_gids[1:]:
            if ip_lookup and (gid == 'client' or gid == 'ipaddr'):
                idx.append(self.gethost(match.group(gid)))
            elif uid_lookup and (gid == 'user' or gid == 'uid'):
                idx.append(self.getuname(match.group(gid)))
            else:
                idx.append(match.group(gid))
            
        idx = tuple(idx)
        results = self.results        

        try:
            results[idx] += 1
        except KeyError:
            results[idx] = 1
        ##Alternative: results[idx] = get(results, 0) + 1

        return idx

    def add_result(self, hostname, match):
        """
        Add a tuple or increment the value of existing one
        in the rule results dictionary
        """
        idx = [self.outmap.map_value('host', hostname)]
        for gid in self.key_gids[1:]:
            print("Value: ", gid, match.group(gid))
            idx.append(self.outmap.map_value(gid, match.group(gid)))
        idx = tuple(idx)
        print(idx)
        results = self.results

        try:
            results[idx] += 1
        except KeyError:
            results[idx] = 1
        ##Alternative: results[idx] = get(results, 0) + 1

        return idx

    def has_results(self):
        """
        Returns true if the rule has results.
        """
        return self.results

    def total_events(self, cond, valfld):
        """
        Return total events of a rule result set. A condition
        could be provided to select the events to count.
        Intead of simply counting events a value field could
        be provided to sum product of values with events.
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
        that identify the service. The third is a list of all other fields and the
        value indicating the number of events associated. 
        """
        def insert_row():
            row = list(def_row)
            
            j = 0
            for n in range(cols):
                if row[n] is None:
                    if j == kl:                        
                        row[n] = tabvalues
                    else:
                        row[n] = tabkey[j]
                    j += 1
            events.append(row)
            
        if not self.results:
            return []
        
        results = self.results
        events = []
        pos = [self.key_gids.index(gid) for gid in fields if gid[0] != '"']
        has_cond = cond != "*"

        if has_cond:
            match = re.search("(\w+)(!=|==)\"([^\"]*)\"", cond)
            condpos = self.key_gids.index(match.group(1))
            invert = (match.group(2) == '!=')
            recond = re.compile(match.group(3))
        else:
            recond = condpos = None

        kl = len(pos) - (len(fields) - cols) - 1
        
        def_row = []
        for i in range(cols):
            if fields[i][0] == '"':
                def_row.append(fields[i].strip('"'))
            else:
                def_row.append(None)

        tabkey = None
        tabvalues = []
        for key in sorted(results, key=lambda x: x[pos[0]]):
            if has_cond:
                match = recond.search(key[condpos])
                if ((match is None) and not invert) or ((match is not None) and invert):
                    continue

            if tabkey is None or tabkey != [key[pos[i]] for i in range(kl)]:
                if tabkey is not None:
                    insert_row()
                tabkey = [key[pos[i]] for i in range(kl)]

            value = [key[k] for k in pos[kl:]]
            value.append(results[key])
            tabvalues.append(tuple(value))
        else:
            if tabkey is not None:
                insert_row()

        return events
    

class AppLogParser:
    """
    Class to manage application log rules and results
    """

    # Class internal processing attributes
    _filters = None
    _filter_keys = None     # Passed filter options
    _no_filter_keys = None  # Filter options not passed
    _report = None          # Report flag
    _thread = None          # Thread flag
    outmap = None          # Output mapping

    # Default values for application config files
    default_config = {
        'main': {
        'desc': u'${appname}',
        'tags': u'${appname}',
        'files': u'${logdir}/messages',
        'enabled': True,
        'priority': 1,
        }
    }

    @staticmethod
    def set_options(config, filters, outmap):
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
        AppLogParser._filter_keys = tuple(filter_names)         
        AppLogParser._no_filter_keys = tuple([
            key for key in config.options('filters')
            if key not in AppLogParser._filter_keys
        ])
        AppLogParser._report = config['report']
        AppLogParser._thread = config['thread']
        AppRule.set_ip_lookup(config['ip_lookup'])
        AppRule.set_uid_lookup(config['uid_lookup'])

    def __init__(self, name, appcfgfile, config):
        """
        Create a app object reading the configuration from file
        """
        logger.info('Initializing app "{0}" from configuration file {1}'
                    .format(name, appcfgfile))

        # Check if class variables are initialized
        if self._filters is None:
            raise Exception
        
        # Setting class instance variables
        self.name = name            # Application name
        self.cfgfile = appcfgfile   # Complete path to app config file
        self.rules = []             # Regexp rules for the app
        self.has_filters = False    # True if the app has filters 
        self.repitems = []          # Report items read from configuration
        self.counter = 0            # Parsed lines counter
        self.unparsed_counter = 0   # Unparsed lines counter

        # Setting other instance internal variables for process phase
        self._last_rule = self._last_idx = None

        extra_options = {'appname': self.name, 'logdir': config['logdir']}
        hostnames = list(set(re.split('\s*,\s*', config['hosts'].strip())))
        if len(hostnames) == 1:
            extra_options.update({'hostname': hostnames[0]})

        appconfig = lograptor.configmap.ConfigMap(appcfgfile, self.default_config, extra_options)

        self.desc = appconfig['desc']
        self.tags = appconfig['tags']
        self.files = list(set(re.split('\s*,\s*', appconfig['files'])))
        self.enabled = appconfig['enabled']
        self.priority = appconfig['priority']

        # Check if application is explicitly enabled or enabled by 'apps' option.
        # Exit if the application is not enabled at the end of checks.
        if not self.enabled:
            if config['apps'] != '':
                self.enabled = True
                logger.debug('App "{0}" is enabled by option'.format(self.name))
            else:
                logger.debug('App "{0}" is not enabled: ignore.'.format(self.name))
                return

        # Expand application's fileset if many hostsnames are provided
        if len(hostnames) > 1:
            filelist = set()
            for filename in self.files:
                for host in hostnames:
                    filelist.add(string.Template(filename)
                                 .safe_substitute({'hostname': host}))
            self.files = list(filelist)

        logger.info('App "{0}" run fileset: {1}'.format(self.name, self.files))

        # Read app rules from configuration file. An app is disabled
        # when it doesn't have almost a rule.
        logger.debug('Load rules for app "{0}"'.format(self.name))
        try:
            rules = appconfig.parser.items('rules')
        except configparser.NoSectionError:
            raise lograptor.ConfigError('No section [rules] in config file of app "{0}"'.format(self.name))
        if not rules:
            msg = 'No rules for app "{0}": application must have at least a rule!'
            raise lograptor.ConfigError(msg.format(self.name))
        
        self.add_rules(rules, config)
        
        # Read report items, used to manage
        # report composition from results.
        sections = appconfig.parser.sections()
        sections.remove('main')
        sections.remove('rules')
        
        for sect in sections:
            try:
                repitem = lograptor.report.ReportItem(sect, appconfig.parser.items(sect),
                                                      config.options('subreports'), self.rules)
            except lograptor.OptionError as msg:
                raise lograptor.ConfigError('section "{0}" of "{1}": {2}'
                                            .format(sect, os.path.basename(appcfgfile), msg))
            except configparser.NoOptionError as msg:
                raise lograptor.ConfigError('No option "{0}" in section "{1}" of configuration '
                                            'file "{1}"'.format(msg, sect, appcfgfile))
            self.repitems.append(repitem)

        # If 'unparsed' matching is disabled then restrict the set of rules to
        # the minimal set useful for processing.
        if False: #not config['unparsed']:
            logger.debug('Purge unused rules for "{0}" app.'.format(self.name))
            self.rules = [
                rule for rule in self.rules
                if rule.is_filter or rule.used_by_report or
                (self._thread and 'thread' in rule.regexp.groupindex)
            ]
        
        # If the app has filters, reorder rules putting filters first.
        if self.has_filters:
            self.rules = sorted(self.rules, key=lambda x: not x.is_filter)

        logger.info('Valid filters for app "{0}": {1}'
                    .format(self.name, len([rule.name for rule in self.rules if rule.is_filter])))
        logger.info('Base rule set for app "{0}": {1}'
                    .format(self.name, [rule.name for rule in self.rules if not rule.is_filter]))

        # Set threads cache using finally rules list
        if self._thread:
            self.cache = lograptor.linecache.LineCache()
        
    def add_rules(self, rules, config):
        """
        Add a set of rules to the app, dividing between filter and other rule set
        """
        for option, pattern in rules:
            # Strip optional string quotes and remove newlines
            pattern = pattern.strip('\'"').replace('\n', '')

            if len(pattern) == 0:
                logger.debug('Rule "{0}" is empty'.format(option))
                raise lograptor.ConfigError('Error in app "{0}" configuration: '
                                            'empty rules not admitted!'.format(option))

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

                # Exclude rule if not related to all filters of the group
                if len(filter_keys) < len(filter_group):
                    continue

                # Substitute not used filters with default pattern matching string
                for opt in self._filter_keys:
                    if opt not in filter_group:
                        new_pattern = string.Template(new_pattern).safe_substitute({opt: config[opt]})

                # Adding to app rules
                self.rules.append(AppRule(option, new_pattern, True, self.outmap))
                self.has_filters = True
                logger.debug('Add filter rule "{0}" ({1}): {2}'
                             .format(option, u', '.join(filter_keys), new_pattern))
                logger.debug('Rule "{0}" gids : {1}'.format(option, self.rules[-1].key_gids))

            # Add once at the end the no filtering version of the rule
            for opt in self._no_filter_keys:
                pattern = string.Template(pattern).safe_substitute({opt: config[opt]})
            self.rules.append(AppRule(option, pattern, False, self.outmap))
            logger.debug('Add rule "{0}": {1}'.format(option, pattern))
            logger.debug('Rule "{0}" gids : {1}'.format(option, self.rules[-1].key_gids))

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
                    if not (cache[thread].pattern_match and cache[thread].filter_match) and \
                            (abs(event_time - cache[thread].end_time) > 3600):
                        purge_list.append(idx)
                
            for idx in purge_list:
                del rule.results[idx]

    def increase_last(self, k):
        """
        Increase the last rule result by k.
        """
        idx = self._last_idx
        if idx is not None:
            self._last_rule.results[idx] += k
        
    def process(self, hostname, datamsg, debug):
        """
        Process a log line data message (or entire line) with filters.
        If requested buffer lines for threads/transactions matching.
        The function return False if no filter match. If a filter or rule
        match the function return True. Otherwise return None (no filter
        is specified and no rule matched, meaning the line is unparsable).

        Return values (result, appthread):
        
        result == None  <==> if the log line is unparsable by filter/rule
        result == True  <==> if a rule filter match, or a rule match and
                             there are not filter rules in the application,
                             or the application has no rules
        result == False <==> if no rule filter match

        The appthread is returned with the value of thread named group of
        the rule. If the rule doesn't have a thread group, a None is returned.
        """
        for rule in self.rules:
            match = rule.regexp.search(datamsg)
            if match is not None:
                if debug:
                    logger.debug('Rule "{0}" match'.format(rule.name))
                self._last_rule = rule
                if self._thread and 'thread' in rule.regexp.groupindex:
                    thread = match.group('thread')
                    if self._report:
                        self._last_idx = rule.add_result(hostname, match)
                    return (True, rule.is_filter, thread,
                            None if self.outmap is None else self.outmap.map_message(match))
                else:
                    if self._report or (rule.is_filter or not self.has_filters):
                        self._last_idx = rule.add_result(hostname, match)
                    return (True, rule.is_filter, None,
                            None if self.outmap is None else self.outmap.map_message(match) )

        # No rule match: the application log message is unparsable
        # by enabled rules.
        self._last_rule = self._last_idx = None
        self.unparsed_counter += 1
        return False, None, None, None
