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

import os
import re
import logging
import string
import socket

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
    pass

import lograptor.report
import lograptor.linecache

logger = logging.getLogger("lograptor")


class AppRule:
    """
    Class to manage application rules. The rules are used to
    parse the log lines and to store matching results.
    """

    # Address and username traslation dictionaries
    # Address and username traslation dictionaries
    _ip_lookup = False
    _uid_lookup = False
    _known_hosts = {}
    _known_uids = {}

    def __init__(self, pattern, has_filters, thread_opt):
        """
        AppRule attributes:
            - regexp : re.compile object for rule pattern
            - results : dictionary of rule results
            - is_filter : True if the rule is connected to a filter option
            - is_useful : True if the rule is a filter or thread useful or used by a report rule
            - key_gids : map from gid to result key tuple index
            - _ip_lookup = Address translation
            - _uid_lookup = UID translation
        """
        try:
            self.regexp = re.compile(pattern)
        except:
            if not has_filters:
                msg = 'Wrong pattern in configuration: "{0}"'.format(pattern)
                raise lograptor.ConfigError(msg)
            else:
                msg = 'Wrong pattern specification in filters!'
                raise lograptor.OptionError(has_filters, msg)
            
        self.results = dict()
        self.filters = has_filters
        self.is_filter = len(has_filters)>0
        self.is_useful = self.is_filter or \
                         (thread_opt and 'thread' in self.regexp.groupindex)
        
        self.key_gids = [ 'hostname' ]
        for gid in self.regexp.groupindex:
            if gid != 'hostname':
                self.key_gids.append(gid)
        self.key_gids = tuple(self.key_gids)

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
                
    def add_result(self, hostname, match):
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
            elif uid_lookup and (gid == 'user' or gid== 'uid'):
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

    def gethost(self, ip_addr):
        """
        Do reverse lookup on an ip address
        """
        # Handle silly fake ipv6 addresses
        try:
            if ip_addr[:7] == '::ffff:': ip_addr = ip_addr[7:]
        except:
            pass

        if ip_addr[0] in string.letters:
            return ip_addr
        
        try:
            return self._known_hosts[ip_addr]
        except KeyError:
            pass

        try:
            name = socket.gethostbyaddr(ip_addr)[0]
        except socket.error:
            name = ip_addr

        self._known_hosts[ip_addr] = name
        return name

    def getuname(self, uid):
        """
        Get username for a given uid
        """
        uid = int(uid)
        try:
            return self._known_uids[uid]
        except KeyError:
            pass

        try:
            name = pwd.getpwuid(uid)[0]
        except KeyError:
            name = "uid=%d" % uid

        self._known_uids[uid] = name
        return name

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

        if valfld is not None:
            val = self.key_gids.index(valfld)
        
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

            for i in range(num):
                if top[i] is None:
                    top[i] = [tot, [value]]
                    break
                elif tot == top[i][0]:
                    top[i][1].append(value)
                    break
                elif tot > top[i][0]:
                    top.insert(i,[tot, [value]])
                    break

        if not self.results:
            return []

        results = self.results        
        top = [None for i in range(num)]
        pos = self.key_gids.index(gid)

        # Compute top(max) if a value fld is provided
        if valfld is not None:
            val = self.key_gids.index(valfld)
            if usemax:
                i = 0 
                for key in sorted(results.keys(), key=lambda x:(int(x[val]),x[pos]),\
                                  reverse=True)[:num]:
                    top[i] = [int(key[val]),[key[pos]]]
                    i += 1
                return [res for res in top if res is not None]
                
        value = None
        for key in sorted(results.keys(), key=lambda x:(x[pos])):
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
            for i in range(cols):
                if row[i] is None:
                    if j == kl:                        
                        row[i] = tabvalues
                    else:
                        row[i] = tabkey[j]
                    j += 1
            events.append(row)
            
        if not self.results:
            return []
        
        results = self.results
        events = []
        pos = [self.key_gids.index(gid) for gid in fields if gid[0] != '"']

        if cond != "*":
            match = re.search("(\w+)(!=|==)\"([^\"]*)\"", cond)
            condpos = self.key_gids.index(match.group(1))
            invert = (match.group(2) == '!=')
            recond = re.compile(match.group(3))
                        
        kl = len(pos) - (len(fields) - cols) - 1
        
        def_row = []
        for i in range(cols):
            if fields[i][0] == '"':
                def_row.append(fields[i].strip('"'))
            else:
                def_row.append(None)

        tabkey = None
        
        for key in sorted(results, key=lambda x:x[pos[0]]):
            if cond != "*":
                match = recond.search(key[condpos])
                if ((match is None) and not invert) or ((match is not None) and invert):
                    continue

            if tabkey is None or tabkey != [key[pos[i]] for i in range(kl)]:
                if tabkey is not None:
                    insert_row()
                tabkey = [key[pos[i]] for i in range(kl)]
                tabvalues = []

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
    _and_filters = None     # Process filters with logical AND
    _filter_keys = None     # Passed filter options
    _no_filter_keys = None  # Filter options not passed
    _report = None          # Report flag
    _thread = None          # Thread flag
    _unparsed = None        # Unparsed flag

    @staticmethod
    def set_options(config, filters):
        """
        Set class variables with runtime options. 
        """
        AppLogParser._filters = filters
        AppLogParser._filter_keys = tuple(filters.keys())
        AppLogParser._no_filter_keys = tuple([ key for key in lograptor.Lograptor.filter_options
                                               if key not in AppLogParser._filter_keys ])
        AppLogParser._and_filters = config['and_filters']
        AppLogParser._report = config['report']
        AppLogParser._thread = config['thread']
        AppLogParser._unparsed = config['unparsed']
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
        self.rules = dict()         # Regexp rules for the app
        self.has_filters = set()    # Set of the filters provided by the app 
        self.repitems = []

        # Setting other instance internal variables for process phase
        self._last_rule = self._last_idx = None
            
        # Parse app configuration file. 
        appconfig = configparser.RawConfigParser(dict_type=OrderedDict)
        
        try: 
            appconfig.read(self.cfgfile)
        except (configparser.ParsingError, configparser.DuplicateOptionError) as err:
            logger.error(err)
            raise lograptor.FormatError('Could not parse application config file "{0}"'.format(self.cfgfile))

        # Get the program options from section [main]. Each option is mandatory.
        # Unknown options in section [main] are ignored.
        try:
            self.desc = appconfig.get('main','desc')
            self.tags = appconfig.get('main','tags')
            self.files = appconfig.get('main', 'files')
            self.enabled = appconfig.getboolean('main','enabled')
            self.priority = appconfig.getint('main', 'priority')

            logger.debug('App "{0}" description: "{1}"'.format(self.name,self.desc))
            logger.debug('App "{0}" tags: {1}'.format(self.name, self.tags))
            logger.debug('App "{0}" files: {1}'.format(self.name, self.files))
            logger.debug('App "{0}" enabled: {1}'.format(self.name, self.enabled))
            logger.debug('App "{0}" priority: {1}'.format(self.name, self.priority))

        except configparser.NoSectionError:
            raise lograptor.ConfigError('No section [main] in the configuration file "{0}"'
                                        .format(self.cfgfile))        
        except configparser.NoOptionError as msg:
            raise lograptor.ConfigError('No option "{0}" in section [main] of configuration file "{1}"'
                                        .format(msg,self.cfgfile))

        # First check if the application is enabled. If disables skip parameter
        # or rules syntax checks.
        if not self.enabled:
            if config['applications'] is not None:
                self.enabled = True
                logger.debug('App "{0}" is enabled by option'.format(self.name))
            else:
                logger.debug('App "{0}" is not enabled: ignore.'.format(self.name))
                return

        # Expand application's fileset
        if config['hostnames'] == '*':
            subdict = {'logdir' : config['logdir'], 'hostname' : config['hostnames']}                 
            self.files = string.Template(self.files).safe_substitute(subdict)
            self.files = set(re.split('\s*,\s*', self.files))
        else:
            self.files = string.Template(self.files).safe_substitute({'logdir' : config['logdir']})
            self.files = set(re.split('\s*,\s*', self.files))

            filelist = []
            hostnames = set(re.split('\s*,\s*', config['hostnames'].strip()))
            for tmpl in self.files:
                for host in hostnames:
                    filename = string.Template(tmpl).safe_substitute({'hostname' : host})
                    filelist.append(filename)
                    if tmpl==filename:
                        break
            self.files = filelist
            
        logger.info('App "{0}" run fileset: {1}'.format(self.name, self.files))

        # Read app rules from configuration file. An app is disabled
        # when it doesn't have almost a rule.
        logger.debug('Load rules for app "{0}"'.format(self.name))
        try:
            rules = appconfig.items('rules')
        except configparser.NoSectionError as err:
            raise lograptor.ConfigError('No section [rules] in config file of app "{0}"'.format(self.name))
        if not rules:
            msg = 'No rules for app "{0}": application must have at least a rule!'
            raise lograptor.ConfigError(msg.format(self.name))
        
        self.add_rules(rules, config)
        
        # Read report sections, used to manage
        # results composition into the report.
        sections = appconfig.sections()
        sections.remove('main')
        sections.remove('rules')
        
        for sect in sections:
            try:
                repitem = lograptor.report.ReportItem(sect, appconfig.items(sect), 
                                                       config.options('subreports'), self.rules)
            except lograptor.OptionError as msg:
                raise lograptor.ConfigError('section "{0}" of "{1}": {2}'
                                            .format(sect, os.path.basename(self.cfgfile), msg))
            except configparser.NoOptionError as msg:
                raise lograptor.ConfigError('No option "{0}" in section "{1}" of configuration file "{1}"'
                                            .format(msg, sect, self.cfgfile))            
            self.repitems.append(repitem)

        # If 'unparsed' strings are not requested
        # remove rules not useful for processing
        if not config['unparsed']:
            self.purge_rules()

        # Define a list of rules items for processing.
        # Put rules with filters before the others.
        if self.has_filters:
            self._rules_list = sorted(self.rules.items(), key=lambda x:not x[1].is_filter)
        elif self._filter_keys:
            self.enabled = False
            msg1  = ''
            for key in self._filter_keys:
                msg1 = '{0}/--{1}'.format(msg1, key)
            if config['and_filters'] and not config['thread']:
                msg2 = "No single rule with all required filters"
            else:
                msg2 = "No rules for parsing filters"
            raise lograptor.OptionError(msg1[1:], msg2)
        else:
            self._rules_list = self.rules.items()
            
        logger.info('Rule set for app "{0}": {1}'
                    .format(self.name, [rule[0] for rule in self._rules_list]))

        # Set threads cache using finally rules list
        if self._thread:
            self.cache = lograptor.linecache.LineCache(config['and_filters'], len(self._filter_keys))
        
    def add_rules(self, rules, config):
        """
        Add a set of rules to the app, dividing between filter and other rule set
        """
        for key,pattern in rules:
            from lograptor.__init__ import Lograptor
            
            if ((pattern[0] == '"' and pattern[-1] == '"') or
                (pattern[0] == '\'' and pattern[-1] == '\'')):
                pattern = pattern[1:-1]
                
            if len(pattern) == 0:
                logger.debug('Rule "{0}" is empty'.format(key))
                raise lograptor.ConfigError('Error in app "{0}" configuration: '
                                            'empty rules not admitted!'.format(key))
                
            filter_keys = list()
            for opt in self._filter_keys:
                next_pattern = string.Template(pattern).safe_substitute({opt:config[opt]})
                if next_pattern!=pattern:
                    filter_keys.append(opt)                    
                pattern = next_pattern
                
            if self._and_filters and not self._thread:
                if len(filter_keys)>=len(self._filter_keys):
                    self.has_filters.update(filter_keys)
            else:
                self.has_filters.update(filter_keys)

            for opt in self._no_filter_keys:
                pattern = string.Template(pattern).safe_substitute({opt:config[opt]})     
            
            # Adding to app rules
            self.rules[key] = AppRule(pattern, filter_keys, config['thread'])
            logger.debug('Added regexp rule "{0}" (filters={1}): {2}'
                        .format(key, filter_keys, pattern))
            logger.debug('Rule "{0}" gids : {1}'.format(key, self.rules[key].key_gids))

        if self._and_filters:
            if len(self.has_filters)<len(self._filter_keys):
                self.has_filters = []

        for key in self.has_filters:
            self._filters[key] = True

    def purge_rules(self):
        """
        Remove rules unuseful for processing. Remove rules that are not
        filters and are not used by report rules. Also remove non filter
        rules if reporting is disabled.
        """
        logger.debug('Purge unuseful rules for "{0}" app.'.format(self.name))
        purge_list = []
        for key in self.rules:
            if not self.rules[key].is_useful:
                purge_list.append(key)
            elif (not self._report and
                  not self._thread and
                  not self.rules[key].is_filter):
                purge_list.append(key)

        for key in purge_list:
            logger.debug("Delete rule: {0}".format(key))
            del self.rules[key]

    def purge_unmatched_threads(self, event_time=0):
        """
        Purge the old unmatched threads from application's results.
        """
        cache = self.cache.data
        
        for key, rule in self._rules_list:
            try:
                pos = rule.key_gids.index('thread')
            except ValueError:
                continue

            purge_list = []
            for idx in rule.results:
                thread = idx[pos]
                if thread in cache:
                    if (not (cache[thread].pattern_match and cache[thread].filter_match) and
                        (abs(event_time - cache[thread].end_time) > 3600)):
                        
                        purge_list.append(idx)
                
            for idx in purge_list:
                del rule.results[idx]

    def increase_last(self, k):
        """
        Increase the last rule result by k.
        """
        idx = self._last_idx
        if idx is not None:
            self._last_rule.results[idx] += int(k)
        
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
        
        if not self._rules_list:
            return (True, None, None)

        for key,rule in self._rules_list:
            match = rule.regexp.search(datamsg)
            if match is not None:
                if debug: logger.debug('Rule "{0}" match'.format(key))
                self._last_rule = rule

                result = (rule.is_filter or not self.has_filters)
                if self._thread and 'thread' in rule.regexp.groupindex:
                    thread = match.group('thread')
                    if self._report:
                        self._last_idx = rule.add_result(hostname, match)
                    return (result, rule.filters, thread)
                else:
                    if result and self._report:
                        self._last_idx = rule.add_result(hostname, match)                                            
                    return (result, None, None)            

        # No rule match: the application log message is unparsable
        # by enabled rules.
        self._last_rule = self._last_idx = None
        if self._unparsed:
            return (None, None, None)
        else:
            return (not self.has_filters, None, None)
        
