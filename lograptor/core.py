# -*- coding: utf-8 -*-
"""
This module contain core classes and methods for Lograptor package.
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
from __future__ import print_function

import os
import time
import datetime
import re
import glob
import logging
import fileinput
import socket
import sys
import fnmatch
from sre_constants import error as RegexCompileError

from .application import AppLogParser
from .configmap import ConfigMap
from .exceptions import LograptorConfigError, FileMissingError, FormatError, OptionError, LograptorArgumentError
from .matcher import create_matcher_engine
from .filemap import FileMap
from .cache import RenameCache
from .report import Report
from .channels import TermChannel, MailChannel, FileChannel
from .timedate import get_interval
from .utils import set_logger, results_to_string, walk

logger = logging.getLogger(__name__)


# Cleans the thread caches every time you process a certain number of lines.
PURGE_THREADS_LIMIT = 1000

# Lograptor default configuration
DEFAULT_CONFIG = {
    'main': {
        'cfgdir': '/etc/lograptor/',
        'logdir': '/var/log/',
        'logfile': '/var/log/lograptor.log',
        'tmpdir': '/var/tmp/',
        'email_address': 'root@{0}'.format(socket.gethostname()),
        'smtp_server': '/usr/sbin/sendmail -t',
        'tsa_server': None,
        'mapexp': 4
    },
    'patterns': {
        'ascii_pattern': r'[\x01-\x7f]*',
        'dnsname_pattern': r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*'
                           r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\b',
        'ipv4_pattern': r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
        'ipv6_pattern': r'(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}'
                        r'(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}'
                        r'(?: (?<=::)|(?<!:)|(?<=:) (?<!::) :)|'
                        r'(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)'
                        r'(?: \.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})',
        'username_pattern': r'[A-Za-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&\'*+/=?^_`{|}~-]+)*',
        'email_pattern': r'(?:|${username_pattern}|"${ascii_pattern}")'
                         r'(?:|@(?:${dnsname_pattern}|\[(?:${ipv4_pattern}|${ipv6_pattern})\]))+',
        'id_pattern': r'[0-9]+',
    },
    'fields': {
        'user': r'(|${username_pattern})',
        'mail': r'${email_pattern}',
        'from': r'${email_pattern}',
        'rcpt': r'${email_pattern}',
        'client': r'(${dnsname_pattern}|${ipv4_pattern}|'
                  r'${dnsname_pattern}\[${ipv4_pattern}\])',
        'pid': r'${id_pattern}',
        'uid': r'${id_pattern}',
        'msgid': r'${ascii_pattern}',
    },
    'report.default': {
        'title': '${host} system events: $localtime',
        'template.html': '${cfgdir}/report_template.html',
        'template.text': '${cfgdir}/report_template.txt',
        'subreport.login_report': 'Logins',
        'subreport.mail_report': 'Mail report',
        'subreport.command_report': 'System commands',
        'subreport.query_report': 'Database lookups'
    },
    'channel.default': {
        'type': 'tty',
        'formats': 'text',

        # options for mail channel sections
        'mailto': 'root',
        'include_rawlogs': False,
        'rawlogs_limit': 200,
        'gpg_encrypt': False,
        'gpg_keyringdir': None,
        'gpg_recipients': None,

        # options for file channel sections
        'notify': '',
        'pubdir': '/var/www/lograptor',
        'dirmask': '%Y-%b-%d_%a',
        'filemask': '%H%M',
        'save_rawlogs': False,
        'expire_in': 7,
        'pubroot': 'http://localhost/lograptor'
    }
}


def exec_lograptor(args):
    """
    Exec a Lograptor intance from passed arguments.
    """
    # Check arguments
    matcher_count = [args.use_rules, args.exclude_rules, args.unparsed].count(True)
    if matcher_count == 0:
        args.use_rules = True
    elif matcher_count > 1:
        raise LograptorArgumentError("conflicting matchers specified")

    if args.report is None:
        args.report = 'default'

    if not args.patterns and not args.pattern_files:
        try:
            args.patterns.append(args.files.pop(0))
        except IndexError:
            raise LograptorArgumentError('PATTERN', 'no search pattern')

    _lograptor = Lograptor(args)

    try:
        retval = _lograptor.process()
    finally:
        _lograptor.cleanup()

    return 0 if retval else 1


class Lograptor(object):
    """
    This is the main class of Lograptor package.
      - options: contains options. Should be passed with an object (optparse)
        or with a dictionary. Absent options are overrided by defaults, with
        the exception of option 'loglevel' that is required for debugging;
      - args: List with almost one search path and filename paths.
    """
    def __init__(self, args):
        """
        Initialize parameters for lograptor instance and load apps configurations.

        # Instance attributes:
        #  parsers: cycle iterator of defined LogParser classes
        #  filters: list with passed filter options
        #  hosts: list with host names passed with the option
        #  apps: dictionary with enabled applications
        #  tagmap: dictionary map from tags to apps
        #  _search_flags: flags for re.compile of patterns
        #  tmpprefix: location for temporary files
        """
        try:
            self.config = ConfigMap(
                cfgfiles=args.cfgfile,
                defaults=DEFAULT_CONFIG,
                base_sections=['main', 'patterns']
            )
        except IOError as err:
            logger.critical('no configuration available in files %r: %r', args.cfgfile, err)
            raise FileMissingError('abort "{0}" for previous errors'.format(__name__))
        else:
            if 'stdout' in args.channels:
                set_logger('lograptor', args.loglevel)
            else:
                set_logger('lograptor', args.loglevel, logfile=self.config.getstr('main', 'logfile'))
            self.args = args

        # Check ad adapt arguments
        matcher_count = [args.use_rules, args.exclude_rules, args.unparsed].count(True)
        if matcher_count == 0:
            args.use_rules = True
        elif matcher_count > 1:
            raise LograptorArgumentError("conflicting matchers specified")

        if args.report is None:
            args.report = 'default'

        if not args.patterns and not args.pattern_files:
            try:
                args.patterns.append(args.files.pop(0))
            except IndexError:
                raise LograptorArgumentError('PATTERN', 'no search pattern')

        # Check arguments with loaded configuration
        self.fields = self.config.options('fields')
        unknown = set([k for k in walk(args.filters)])
        unknown.difference_update(self.fields)
        if unknown:
            raise LograptorArgumentError('undefined fields %r', list(unknown))
        self.channels = self.get_channels()

        self._debug = (args.loglevel == 4)
        self.patterns = self.get_patterns()
        self.final_dt, self.initial_dt = self.get_timeperiod()
        self.filters = args.filters
        self.hosts = self.get_hosts()

        # Create an output mapping instance only when is asked by options
        if any([args.anonymize, args.uid_lookup, args.ip_lookup]):
            self.name_cache = RenameCache(args, self.config)
        else:
            self.name_cache = None

        # Loading configured apps
        try:
            self._loaded_apps = self.read_apps()
        except ValueError as err:
            raise LograptorConfigError(err.message)
        else:
            if not self._loaded_apps:
                raise LograptorConfigError("no apps found!")

        # Loading required apps
        if self.args.appnames:
            try:
                self.apps = self.get_apps(self.args.appnames)
            except ValueError as err:
                raise LograptorArgumentError("--apps", err.message)
        else:
            # No --apps option ==> select only enabled apps
            self.apps = self.get_apps(enabled=True)

        self.tagmap = self.get_tags()
        self.known_tags = self.get_tags(self._loaded_apps.keys())

        logger.info("search patterns to be processed: %r", self.patterns)
        logger.info('datetime interval to be processed: (%r, %r)', self.initial_dt, self.final_dt)
        logger.info("provided filters: %r", self.filters)
        logger.info('hosts to be processed: %r', self.hosts)

        self.extra_tags = set()

        self.tmpprefix = None

        # Initialize the report object when the option is enabled
        if args.report:
            self.report = Report(args.report, self.patterns, self.apps, self.args, self.config)

        if not args.files and not os.isatty(sys.stdin.fileno()):
            # No files and input by a pipe
            self.logmap = [(sys.stdin, self.apps.values())]
        else:
            # Build the LogMap instance adding the list of files to be scanned.
            self.logmap = FileMap(self.initial_dt, self.final_dt)
            for app in self.apps.values():
                self.logmap.add(args.files or app.files, app, app.priority)

    def get_patterns(self):
        """
        Gets all the patterns from arguments and from files containing patterns.
        :return: Tuple with re.RegexObject objects as items.
        """
        # Get the patterns from arguments and files
        patterns = set()
        if self.args.pattern_files:
            patterns.update([p.rstrip('\n') for p in fileinput.input(self.args.pattern_files)])
        patterns.update(self.args.patterns)

        # If one pattern is empty then skip the other patterns
        if '' in patterns:
            return tuple()

        try:
            flags = re.IGNORECASE if self.args.case else 0
            return tuple([re.compile("(%s)" % pat, flags=flags) for pat in patterns])
        except RegexCompileError as err:
            raise LograptorArgumentError('wrong regex syntax for pattern: %r' % err)

    def get_hosts(self):
        return [re.compile(fnmatch.translate(host)) for host in set(self.args.hostnames or ['*'])]

    def get_timeperiod(self):
        """
        Return the timeperiod that is determined from arguments.
        :return:
        """
        if self.args.period is None:
            if self.args.files or not os.isatty(sys.stdin.fileno()):
                # diff = int(time.time())
                return None, None
            else:
                diff = 86400  # 24h = 86400 seconds
            return get_interval(int(time.time()), diff, 3600)
        else:
            return self.args.period

    def read_apps(self, cfgdir=None):
        """
        Read the configuration of applications returning a dictionary
        :param cfgdir: Read apps from a configuration directory.
        :return: A dictionary with application names as keys and configuration
        object as values.
        """
        apps_path = os.path.join(cfgdir or self.config.getstr('main', 'cfgdir'), 'conf.d/*.conf')
        apps = {}
        for cfgfile in glob.iglob(apps_path):
            name = os.path.basename(cfgfile)[0:-5]
            try:
                app = AppLogParser(name, cfgfile, self.args, self.config, self.name_cache)
            except (OptionError, LograptorConfigError, FormatError) as err:
                logger.error('cannot add app %r: %r', name, err)
            else:
                apps[name] = app

        if not apps:
            raise ValueError('no valid application in %r!' % cfgdir)
        return apps

    def get_apps(self, appnames=None, enabled=None):
        """
        Return a dictionary with loaded apps that satisfy some con
        :param appnames:
        :param enabled:
        :return:
        """
        apps = self._loaded_apps
        appnames = appnames or apps.keys()
        unknown = set(appnames)
        unknown.difference_update(self._loaded_apps)
        if unknown:
            raise ValueError("not found apps %r" % list(unknown))

        if enabled is None:
            return {k: v for k, v in apps.items() if k in appnames}
        else:
            return {k: v for k, v in apps.items() if k in appnames and v.enabled == enabled}

    def get_tags(self, appnames=None):
        """
        Set the tagmap dictionary for mapping app-name to app.

        :param appnames: Sequence or dict
        :return:
        """
        appnames = appnames or self.apps.keys()
        unknown = set(appnames)
        unknown.difference_update(self._loaded_apps.keys())
        if unknown:
            raise ValueError("not found apps %r" % list(unknown))

        apps = [v for v in self._loaded_apps.values() if v.name in appnames]
        tagmap = {}
        for app in sorted(apps, key=lambda x: (x.priority, x.name)):
            for tag in app.tags:
                if not tag:
                    raise LograptorConfigError('found an empty tag for app %r' % app.name)
                try:
                    tagmap[tag].append(app)
                except KeyError:
                    tagmap[tag] = [app]
        return tagmap

    def get_channels(self, channels=None):
        channels = channels or self.args.channels
        config_channels = [
            sec.strip().partition('.')[2] for sec in self.config.sections()
            if sec.strip().startswith('channel.')
        ]
        unknown = set(channels)
        unknown.difference_update(config_channels)
        if unknown:
            raise ValueError("undefined channel %r" % list(unknown))

        output_channels = []
        for channel in set(channels):
            channel_type = self.config.getstr("channel.%s" % channel, 'type')
            if channel_type == 'tty':
                output_channels.append(TermChannel(channel, self.args, self.config))
            elif channel_type == 'file':
                output_channels.append(FileChannel(channel, self.args, self.config))
            elif channel_type == 'mail':
                output_channels.append(MailChannel(channel, self.args, self.config))
            else:
                raise LograptorConfigError('unknown channel type %r' % channel_type)
        return output_channels

    def print_config(self):
        """
        Return a formatted text with main configuration parameters.
        """
        # Create a dummy report object if necessary
        channels = filter(lambda x: x.startswith('channel.'), self.config.sections())
        return u'\n'.join([
            u"\n--- %s configuration ---" % self.__class__.__name__,
            u"Configuration main file: %s" % self.config.cfgfile,
            u"Configuration directory: %s" % os.path.abspath(self.config.getstr('main', 'cfgdir')),
            u"Enabled applications: %s" % ', '.join(self.apps.keys()),
            u"Disabled applications: %s" % ', '.join([app for app in self.get_apps() if app not in self.apps]),
            u"Available fields: %s" % ', '.join(self.config.options('fields')),
            u"Output channels: %s" % ', '.join(channels) if channels else u'No channels defined',
            ''
        ])

    def get_run_summary(self, run_stats):
        """
        Produce a text summary from run statistics.

        :param run_stats:
        :return: Formatted multiline string
        """
        summary = [
            u'\n--- %s run summary ---' % self.__class__.__name__,
            u'Number of processed files: %(tot_files)d',
            u'Total lines read: %(tot_lines)d',
            u'Total log events matched: %(tot_counter)d',
        ]
        if run_stats['tot_unparsed'] > 0:
            summary.append(u'WARNING: Found %(tot_unparsed)d unparsed log header lines')
        if self.args.appnames:
            if any([app.counter > 0 for app in self.apps.values()]):
                proc_apps = [app for app in self.apps.values() if app.counter > 0]
                summary.append(u'Total log events for apps: %s' % u', '.join([
                    u'%s(%d)' % (app.name, app.counter)
                    for app in proc_apps
                ]))
                if len(proc_apps) == 1 and self.args.count:
                    rule_counters = {
                        rule.name: sum(rule.results.values()) for rule in proc_apps[0].rules
                    }
                    summary.append(u"App's rules counters: %s" % results_to_string(rule_counters))
            if run_stats['unknown_tags']:
                summary.append(u'Found unknown app\'s tags: %(unknown_tags)r')
            if any([app.unparsed_counter > 0 for app in self.apps.values()]):
                summary = u'{0}\nFound unparsed log lines for apps: {1}'.format(summary, u', '.join([
                    u'%s(%d)' % (app.name, app.unparsed_counter)
                    for app in self.apps.values() if app.unparsed_counter > 0
                ]))
        summary.append('\n')
        return '\n'.join(summary) % run_stats

    def process(self, parsers=None):
        """
        Log processing main routine. Iterate over the log files calling
        the processing internal routine for each file.
        """
        logger.info('processing log files ...')
        process_logfile = create_matcher_engine(self, parsers)
        tot_lines = tot_counter = tot_unparsed = 0
        start_event = end_event = None
        logfiles = []

        # Iter between log files. The iteration use the log files modified between the
        # initial and the final date, skipping the other files.
        for (path_or_file, applist) in self.logmap:
            logger.info('process %r for apps %r', path_or_file, applist)
            try:
                num_lines, counter, unparsed_counter, extra_tags, first_event, last_event = \
                    process_logfile(path_or_file, applist)
                logfiles.append(str(path_or_file))

                tot_lines += num_lines
                tot_counter += counter
                tot_unparsed += unparsed_counter
                self.extra_tags = self.extra_tags.union(extra_tags)
                try:
                    if start_event is None or start_event > first_event:
                        start_event = first_event
                    if end_event is None or end_event < last_event:
                        end_event = last_event
                except TypeError:
                    pass

                if self.args.thread:
                    map(lambda x: x.purge_threads(), applist)

            except IOError as msg:
                if not self.args.no_messages:
                    logger.error(msg)

        tot_files = len(logfiles)
        if not logfiles and self.initial_dt is not None:
            raise FileMissingError(
                "no file in datetime interval (%s, %s)!" % (self.initial_dt, self.final_dt)
            )

        try:
            starttime = datetime.datetime.fromtimestamp(start_event)
            endtime = datetime.datetime.fromtimestamp(end_event)
        except (TypeError, UnboundLocalError):
            starttime = endtime = None

        run_stats = {
            'starttime': starttime,
            'endtime': endtime,
            'tot_counter': tot_counter,
            'tot_files': tot_files,
            'tot_lines': tot_lines,
            'tot_unparsed': tot_unparsed,
            'logfiles': ', '.join(logfiles),
            'unknown_tags': set([tag for tag in self.extra_tags
                                 if tag not in self.known_tags and not tag.isdigit()]),
        }

        # If final report is requested then purge all unmatched threads and set time stamps.
        # Otherwise print a final run summary if messages are not disabled.
        if tot_counter > 0 and self.args.report:
            self.report.set_stats(run_stats)
            self.report.make()
            if True or not self.report.is_empty():
                self.send_report()
        elif not self.args.no_messages and not self.args.quiet:
            self.send_message(self.get_run_summary(run_stats))

        return tot_counter > 0

    def send_message(self, message):
        for channel in self.channels:
            channel.send_message(message)

    def send_report(self):
        formats = list(set([fmt for channel in self.channels for fmt in channel.formats]))
        report = self.report.get_report(formats)
        for channel in self.channels:
            channel.send_report(report)

    def cleanup(self):
        for channel in self.channels:
            channel.close()
        if self.args.report:
            self.report.cleanup()

        if self.tmpprefix is not None:
            logger.info('removing the temp dir %r', self.tmpprefix)
            os.rmdir(self.tmpprefix)
