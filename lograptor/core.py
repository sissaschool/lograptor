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
import tempfile
import socket
import sys
import itertools
import fnmatch
from sre_constants import error as RegexCompileError

from .application import AppLogParser
from .configmap import ConfigMap
from .exceptions import LograptorConfigError, FileMissingError, FormatError, OptionError, LograptorArgumentError
from .logparser import ParserRFC3164, ParserRFC5424
from .filemap import FileMap
from .outmap import OutMap
from .report import Report
from .channels import StdoutChannel, MailChannel, FileChannel
from .timedate import MONTHMAP, get_interval, parse_date, parse_last, TimeRange
from .tui import ProgressBar
from .utils import set_logger

logger = logging.getLogger(__name__)


# The RFC5424 no-value
NILVALUE = '-'

# Cleans the thread caches every time you process a certain number of lines.
PURGE_THREADS_LIMIT = 1000

# Lograptor default configuration
DEFAULT_CONFIG = {
    'main': {
        'cfgdir': '/etc/lograptor/',
        'logdir': '/var/log',
        'logfile': '/var/log/lograptor.log',
        'tmpdir': '/var/tmp',
        'email_address': 'root@{0}'.format(socket.gethostname()),
        'smtp_server': '/usr/sbin/sendmail -t',
        'tsa_server': None,
        'mapexp': 4,
    },
    'patterns': {
        'rfc3164_pattern': r'^(?:<(?P<pri>[0-9]{1,3})>|)'
                           r'(?P<month>[A-Z,a-z]{3}) (?P<day>(?:[1-3]| )[0-9]) '
                           r'(?P<ltime>[0-9]{2}:[0-9]{2}:[0-9]{2}) '
                           r'(?:last message repeated (?P<repeat>[0-9]{1,3}) times|'
                           r'(?P<host>\S{1,255})\s+'
                           r'(?P<message>(?P<apptag>[^ \[\(\:]{1,32})(?:[\[\(\:])?.*))',
        'rfc5424_pattern': r'^(?:<(?P<pri>[0-9]{1,3})>(?P<ver>[0-9]{0,2}) |)'
                           r'(?:-|(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})T)'
                           r'(?P<ltime>[0-9]{2}:[0-9]{2}:[0-9]{2})(?:|\.(?P<secfrac>[0-9]{1,6}))'
                           r'(?:Z |(?P<offset>(?:\+|-)[0-9]{2}:[0-9]{2}) )'
                           r'(?:-|(?P<host>\S{1,255})) (?:-|(?P<apptag>\S{1,48})) '
                           r'(?:-|(?P<procid>\S{1,128})) (?:-|(?P<msgid>\S{1,32})) '
                           r'(?P<message>.*)',
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
        'template.plain': '${cfgdir}/report_template.txt',
        'subreport.login_report': 'Logins',
        'subreport.mail_report': 'Mail report',
        'subreport.command_report': 'System commands',
        'subreport.query_report': 'Database lookups'
    },
    'channel.stdout': {
        'type': 'stdout',
        'formats': 'plain'
    },
    None: {
        # options for channels
        #'type': 'file',
        #'formats': 'plain',

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
    },
}


def exec_lograptor(args, is_batch=False):
    """
    Exec a Lograptor intance from passed arguments.
    """
    # Check arguments
    matcher_count = [args.use_rules, args.exclude_rules, args.unparsed].count(True)
    if matcher_count == 0:
        args.use_rules = True
    elif matcher_count > 1:
        raise LograptorArgumentError("conflicting matchers specified")

    if not args.patterns and not args.pattern_files:
        print(args.patterns)
        try:
            args.patterns.append(args.files.pop(0))
        except IndexError:
            raise LograptorArgumentError('PATTERN', 'no search pattern')

    my_raptor = Lograptor(args, is_batch)

    # Dump a configuration summary and exit when the program is called from the
    # command line without options and arguments or with only the --conf option.
    if not is_batch and (
            len(sys.argv) == 1 or
            (len(sys.argv) == 2 and sys.argv[1].startswith('--conf=')) or
            (len(sys.argv) == 3 and sys.argv[1] == '--conf')):
        print(my_raptor.print_config())
        my_raptor.cleanup()
        return 0

    try:
        retval = my_raptor.process()
        if my_raptor.make_report():
            my_raptor.send_report()
    finally:
        my_raptor.cleanup()

    return 0 if retval else 1


def walk(obj):
    try:
        for i in iter(obj):
            for j in iter(i):
                yield walk(j)
    except TypeError:
        yield obj


class Lograptor(object):
    """
    This is the main class of Lograptor package.
      - options: contains options. Should be passed with an object (optparse)
        or with a dictionary. Absent options are overrided by defaults, with
        the exception of option 'loglevel' that is required for debugging;
      - args: List with almost one search path and filename paths.
    """
    def __init__(self, args, is_batch=False):
        """
        Initialize parameters for lograptor instance and load apps configurations.

        # Instance attributes:
        #  parsers: cycle iterator of defined LogParser classes
        #  filters: list with passed filter options
        #  hosts: list with host names passed with the option
        #  apps: dictionary with enabled applications
        #  tagmap: dictionary map from tags to apps
        #  _search_flags: flags for re.compile of patterns
        #  rawfh: raw file handler
        #  tmpprefix: location for temporary files
        """
        try:
            self.config = ConfigMap(args.cfgfile, DEFAULT_CONFIG)
        except IOError as err:
            logger.critical('no configuration available in files %r: %r', args.cfgfile, err)
            raise FileMissingError('abort "{0}" for previous errors'.format(__name__))
        else:
            if is_batch:
                set_logger('lograptor', args.loglevel, logfile=self.config['logfile'])
            else:
                set_logger('lograptor', args.loglevel)
            self.args = args
            self.is_batch = is_batch

        # Check arguments with loaded configuration
        self.fields = self.config.options('fields')
        unknown = set([k for k in walk(args.filters)]).difference_update(self.fields)
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
            self.outmap = OutMap(args, self.config)
        else:
            self.outmap = None

        AppLogParser.set_options(args, self.config, self.filters, self.outmap)
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
        self.rawfh = None
        self.tmpprefix = None
        self.prefix = None

        # Setting print_lines and print_status for processing.
        if self.is_batch:
            self.print_lines = self.print_status = False
        elif args.quiet:
            logger.info('Quiet option provided: disabling output and status')
            self.print_lines = False
            self.print_status = False
        elif args.count:
            logger.info('Count option provided: disabling line output')
            self.print_lines = False
            self.print_status = True
        elif not self.filters and not self.patterns:
            self.print_lines = not args.report
            self.print_status = args.report
        else:
            self.print_lines = True
            self.print_status = False

        # Setting the output for filenames:
        #   print_filenames == None --> print as header at start of each file processing
        #   print_filename == True --> print as prefix for each matched line (no header)
        #   print_filename == False --> no filename printing
        if args.print_filename is not None:
            self.print_filename = bool(args.print_filename)
        elif len(args.files) == 1:
            self.print_filename = False
        else:
            self.print_filename = None
        logger.debug('output: prefix lines with filename: %r', self.print_filename)

        # Initialize the report object when the option is enabled
        if args.report:
            self.report = Report(self.patterns, self.apps, self.args, self.config)

        # Build the LogMap instance adding the list of files to be scanned.
        self.logmap = FileMap(self.initial_dt, self.final_dt)
        for app in self.apps.values():
            self.logmap.add(args.files or app.files, app.name, app.priority)

        # Set the parsers iterator with admitted formats.
        # TODO: Extend with other syslog formats using base LogParser class
        parsers = [
            ParserRFC3164(self.config['rfc3164_pattern']),
            ParserRFC5424(self.config['rfc5424_pattern'])
        ]
        self.parsers = itertools.cycle(parsers)
        self._parser = next(self.parsers)
        self._first_event = self._last_event = None  # Put them in a run object (collecting/purge runs)??

    def get_patterns(self):
        """
        Gets all the patterns from arguments and from files containing patterns.
        :return: Tuple with re.RegexObject objects as items.
        """
        # Get the patterns from arguments and files
        patterns = set()
        if self.args.pattern_files:
            patterns.update(
                [pattern.rstrip('\n') for pattern in fileinput.input(self.args.pattern_files)]
            )
        patterns.update([pattern.rstrip('\n') for pattern in self.args.patterns])

        try:
            flags = re.IGNORECASE if self.args.case else 0
            return tuple([re.compile(pattern, flags=flags) for pattern in patterns if pattern])
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
            if self.args.files:
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
        :param apps: List containing the names of the applications to read.
        :return: A dictionary with application names as keys and configuration
        object as values.
        """
        apps_path = os.path.join(cfgdir or self.config['cfgdir'], 'conf.d/*.conf')
        apps = {}
        for cfgfile in glob.iglob(apps_path):
            name = os.path.basename(cfgfile)[0:-5]
            try:
                app = AppLogParser(name, cfgfile, self.args, self.config)
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
        unknown = set(appnames).difference_update(self._loaded_apps)
        if unknown:
            raise ValueError("not found apps %r" % list(unknown))

        if enabled is None:
            return {k:v for k, v in apps.items() if k in appnames}
        else:
            return {k:v for k, v in apps.items() if k in appnames and v.enabled == enabled}

    def get_tags(self, appnames=None):
        """
        Set the tagmap dictionary for mapping app-name to app.

        :param appnames: Sequence or dict
        :return:
        """
        appnames = appnames or self.apps.keys()
        unknown = set(appnames).difference_update(self._loaded_apps.keys())
        if unknown:
            raise ValueError("not found apps %r" % list(unknown))

        apps = [v for v in self._loaded_apps.values() if v.name in appnames]
        tagmap = {}
        for app in sorted(apps, key=lambda x: (x.priority, x.name)):
            for tag in set(re.split('\s*,\s*', app.tags)):
                if not tag:
                    raise LograptorConfigError('found an empty tag for app %r' % app.name)
                try:
                    tagmap[tag].append(app)
                except KeyError:
                    tagmap[tag] = [app]
        return tagmap

    @staticmethod
    def _get_line(line):
        return line

    def _get_prefixed_line(self, line):
        return '{0}: {1}'.format(self.prefix, line)

    def get_channels(self, channels=None):
        channels = channels or self.args.channels
        config_channels = [sec for sec in self.config.sections() if sec.strip().startswith('channel.')]
        unknown = set(channels).difference_update(config_channels)
        if unknown:
            raise ValueError("undefined channel %r" % list(unknown))

        output_channels = []
        for channel in set(channels):
            channel_type = self.config.getstr("channel.%s" % channel, 'type')
            if channel_type == 'stdout':
                output_channels.append(StdoutChannel(channel, self.config))
            elif channel_type == 'file':
                output_channels.append(FileChannel(channel, self.config))
            elif channel_type == 'mail':
                output_channels.append(MailChannel(channel, self.config))
            else:
                raise LograptorConfigError('unknown channel type %r' % channel_type)
        return output_channels

    def print_config(self):
        """
        Return a formatted text with main configuration parameters.
        """
        # Create a dummy report object if necessary
        if not hasattr(self, 'report'):
            self.report = Report(self.patterns, self.apps, self.args, self.config)
        channels = self.get_channels()
        return u'\n'.join([
            u"\n--- {0} configuration ---".format(self.__class__.__name__),
            u"Configuration main file: {0}".format(self.args.cfgfile),
            u"Configuration directory: {0}".format(self.config['cfgdir']),
            u"Enabled applications: {0}".format(', '.join(self.apps.keys())),
            u"Disabled applications: {0}".format(', '.join([
                                                               app for app in self.get_apps() if app not in self.apps])),
            u"Available filters: {0}".format(', '.join([
                opt for opt in self.config.options('filters')])),
            u"Report HTML template file: {0}".format(self.config['html_template']),
            u"Report plain text template file: {0}".format(self.config['text_template']),
            u"Subreports: {0}".format(', '.join([
                subreport.name for subreport in self.report.subreports])),
            u"Report channels: \n    {0}\n".format('\n    '.join([
                repr(ch) for ch in channels])) if channels else u'No channels used\n',
            ])

    def get_run_summary(self, run_stats):
        """
        Produce a summary from run statistics.

        :return: Formatted multiline string
        """
        tot_counter = run_stats['tot_counter']
        tot_files = run_stats['tot_files']
        tot_lines = run_stats['tot_lines']
        tot_unparsed = run_stats['tot_unparsed']
        unknown_tags = run_stats['unknown_tags']
        summary = u'\n--- {0} run summary ---'.format(self.__class__.__name__)
        summary = '{0}\nNumber of processed files: {1}'.format(summary, tot_files)
        summary = u'{0}\nTotal lines read: {1}'.format(summary, tot_lines)
        summary = u'{0}\nTotal log events matched: {1}'.format(summary, tot_counter)
        if not self._debug and tot_unparsed > 0:
            summary = u'{0}\nWARNING: Found {1} unparsed log header lines'.format(summary, tot_unparsed)
        if self.args.appnames:
            if any([app.counter > 0 for app in self.apps.values()]):
                proc_apps = [app for app in self.apps.values() if app.counter > 0]
                summary = u'{0}\nTotal log events for apps: {1}'.format(summary, u', '.join([
                    u'%s(%d)' % (app.name, app.counter)
                    for app in proc_apps
                ]))

                if len(proc_apps) == 1 and self.args.count:
                    rule_counters = dict()
                    for rule in proc_apps[0].rules:
                        rule_counters[rule.name] = sum([val for val in rule.results.values()])
                    summary = u'{0}\nApp rules counters: {1}'.format(
                        summary,
                        u', '.join([
                            u'{0}({1})'.format(rule, rule_counters[rule])
                            for rule in sorted(rule_counters, key=lambda x: rule_counters[x], reverse=True)
                        ]))
            if unknown_tags:
                summary = u'{0}\nFound unknown app\'s tags: {1}'.format(summary, u', '.join(unknown_tags))

            if any([app.unparsed_counter > 0 for app in self.apps.values()]):
                summary = u'{0}\nFound unparsed log lines for apps: {1}'.format(summary, u', '.join([
                    u'%s(%d)' % (app.name, app.unparsed_counter)
                    for app in self.apps.values() if app.unparsed_counter > 0
                ]))
        return summary

    def process(self):
        """
        Log processing main routine. Iterate over the defined LogBase instance,
        calling the processing routine for each logfile.
        """

        logger.info('Start the log processing main routine ...')

        # Local variables
        apps = self.apps
        print_filename = self.print_filename
        print_header = self.print_status or self.print_lines and print_filename is None
        process_logfile = self.process_logfile
        tot_files = tot_lines = tot_counter = tot_unparsed = 0
        logfiles = []

        # Create temporary file for matches rawlog
        if self.args.report and self.report.need_rawlogs():
            self.mktempdir()
            self.rawfh = tempfile.NamedTemporaryFile(mode='w+', delete=False)
            logger.info('RAW strings file created in %r', self.rawfh.name)

        # Iter between log files. The iteration use the log files modified between the
        # initial and the final date, skipping the other files.
        for (filename, applist) in self.logmap:
            logger.debug('Process log %r for apps %r', filename, applist)

            if print_header:
                print('\n*** Filename: {0} ***'.format(filename))
            if self.rawfh is not None and print_filename is None:
                self.rawfh.write('\n*** Filename: {0} ***\n'.format(filename))

            # When process CLI paths use the ordered list of apps instead of "*"
            if applist[0] == "*" and self.args.apps:
                applist = self.applist

            try:
                # logfile = fileinput.input(logfile, openhook=fileinput.hook_compressed)
                num_lines, counter, unparsed_counter, extra_tags = process_logfile(filename, applist)
                logfiles.append(filename)

                tot_files += 1
                tot_lines += num_lines
                tot_counter += counter
                tot_unparsed += unparsed_counter
                self.extra_tags = self.extra_tags.union(extra_tags)

                if self.args.thread:
                    for app in applist:
                        try:
                            apps[app].purge_unmatched_threads()
                        except UnboundLocalError:
                            break

                # If option count is enabled print number of
                # matching lines for each file.
                if self.args.count:
                    print('{0}: {1}'.format(filename, counter))

            except IOError as msg:
                if not self.args.no_messages:
                    logger.error(msg)

        if tot_files == 0: # and self.initial_dt is not None:
            raise FileMissingError(
                "no file in the datetime interval (%s, %s)!!" % (self.initial_dt, self.final_dt)
            )

        logger.info('Total files processed: %d', tot_files)
        logger.info('Total log lines processed: %d', tot_lines)

        # Save run stats
        try:
            starttime = datetime.datetime.fromtimestamp(self._first_event)
            endtime = datetime.datetime.fromtimestamp(self._last_event)
        except TypeError:
            starttime = endtime = "None"

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
        if self.args.report:
            self.report.set_stats(run_stats)
            if self.rawfh is not None:
                self.rawfh.close()
        elif not self.args.no_messages and not self.args.quiet:
            print(u'%s\n' % self.get_run_summary(run_stats))

        return tot_counter > 0

    def process_logfile(self, filename, applist):
        """
        Process a single log file.

        Variables:
          prev_result: Record previous line result to process "last message
                       repeat N times" lines;
        """

        if self.print_filename:
            getline = self._get_prefixed_line
        else:
            getline = self._get_line

        # Load names to local variables to speed-up the run
        logparser = self._parser
        header_gids = logparser.parser.groupindex
        parsers = self.parsers
        num_parsers = 2 # len(self.parsers)
        outmap = self.outmap
        outstatus = self.print_status
        tagmap = self.tagmap
        max_count = self.args.max_count if not self.args.quiet else 1
        apps = self.apps
        rawfh = self.rawfh
        useapps = self.args.appnames
        regex_hosts = self.hosts
        patterns = self.patterns
        thread = self.args.thread
        print_lines = self.print_lines
        invert = self.args.invert
        match_unparsed = self.args.unparsed
        make_report = self.args.report
        timerange = self.args.timerange

        # Other local variables for the file lines iteration
        prev_data = None
        app = None
        app_thread = None
        hostlist = []
        matching_counter = 0
        unparsed_counter = 0

        readsize = 0
        progressbar = None
        draw_progress_bar = outstatus and not self._debug
        pattern_search = False
        full_match = False
        extra_tags = set()

        initial_dt = time.mktime(self.initial_dt.timetuple()) if self.initial_dt else None
        final_dt = time.mktime(self.final_dt.timetuple()) if self.final_dt else None
        first_event = self._first_event
        last_event = self._last_event

        all_hosts_flag = self.args.hostnames == '*'

        with open(filename) as logfile:
            ###
            # Set counters and status
            filelineno = 0
            if self.print_filename:
                self.prefix = logfile.name
            fstat = os.fstat(logfile.fileno())
            file_mtime = datetime.datetime.fromtimestamp(fstat.st_mtime)
            file_year = file_mtime.year
            file_month = file_mtime.month
            prev_year = file_year - 1
            if draw_progress_bar:
                progressbar = ProgressBar(sys.stdout, fstat.st_size, "lines parsed")

            for line in logfile:
                filelineno += 1
                if draw_progress_bar:
                    readsize += len(line)
                    progressbar.redraw(readsize, filelineno)

                ###
                # Parses the log line. If the regular expression of the parser doesn't match
                # the log line (result=None) changes the active log parser, trying the different
                # parsers configured.
                header_match = logparser.match(line)

                if header_match is None:
                    logger.debug("Change log parser")
                    for i in range(num_parsers):
                        nextparser = parsers.next()
                        if i != num_parsers:
                            header_match = nextparser.match(line)
                            if header_match is not None:
                                logparser = nextparser
                                header_gids = logparser.parser.groupindex
                                break
                    else:
                        unparsed_counter += 1
                        logger.debug('Unparsable log line: %r', line)
                        continue

                # Extract log data tuple from named matching groups
                logdata = logparser.LogData(*map(header_match.group, logparser.fields))
                logger.debug(logdata)

                ###
                # Process first RFC 3164 'last message repeated N times' log lines
                repeat = getattr(logdata, 'repeat', None)
                if repeat is not None:
                    repeat = int(repeat)
                    if prev_data is not None:
                        logger.debug('Repetition: %r', line[:-1])
                        if not thread:
                            matching_counter += repeat
                        if useapps:
                            apptag = prev_data.apptag
                            try:
                                app = tagmap[apptag]
                            except KeyError as e:
                                # Try the partial match
                                for tag in tagmap:
                                    if apptag.startswith(tag):
                                        app = tagmap[tag]
                                        break
                                else:
                                    raise KeyError(e)
                            app.increase_last(repeat)
                            app.counter += 1
                            if app_thread is not None:
                                app.cache.add_line(getline(line), app_thread,
                                                   pattern_search, full_match, event_time)
                        prev_data = None
                    elif app is not None:
                        app.counter += 1
                    continue
                prev_data = logdata

                ###
                # Get and check timestamp. Converts log's timestamp into a value from Epoch to
                # increase the speed of comparisons. Skip lines not included in date/time ranges.
                month = int(MONTHMAP[logdata.month])
                day = int(logdata.day)
                ltime = logdata.ltime
                hour = int(ltime[:2])
                minute = int(ltime[3:5])
                second = int(ltime[6:])
                year = int(getattr(
                    logdata, 'year', prev_year if month != 1 and file_month == 1 else file_year
                    ))

                event_time = time.mktime((year, month, day, hour, minute, second, 0, 0, -1))

                # Skip the lines older than the initial datetime
                if initial_dt is not None and event_time < initial_dt:
                    logger.debug('Skip older line: %r', line[:-1])
                    prev_data = None
                    continue

                # Skip the rest of the file if the event is newer than the final datetime
                if final_dt is not None and event_time > final_dt:
                    if fstat.st_mtime < event_time:
                        logger.error('Date-time inconsistency in comparison to the last '
                                     'modification of the file: %r', line[:-1])

                    logger.debug('Newer line, skip the rest of the file: %r', line[:-1])
                    break

                # Skip the lines not in timerange (if the option is provided).
                if timerange is not None and not timerange.between(ltime):
                    logger.debug('Skip line not in timerange: %r', line[:-1])
                    prev_data = None
                    continue

                ###
                # Check the hostname. If log line format don't
                # include host information, the host is None and consider the line as matched.
                host = getattr(logdata, 'host', None)
                if not all_hosts_flag and host is not None and host not in hostlist:
                    for regex in regex_hosts:
                        if regex.search(host) is not None:
                            hostlist.append(host)
                            break
                    else:
                        logger.debug('Skip the line of not selected hosts: %r', line[:-1])
                        prev_data = None
                        continue

                ###
                # Get the app-tag related to the log line. Then get the app from the tag, if any.
                # Skip the lines not related to the selected apps.
                if useapps:
                    apptag = getattr(logdata, 'apptag', None)
                    if apptag is not None:
                        # Try the exact match
                        if apptag not in tagmap:
                            # Try the partial match
                            for tag in tagmap:
                                if apptag.startswith(tag):
                                    app = tagmap[tag]
                                    break
                            else:
                                # Tag unmatched, skip the line
                                extra_tags.add(apptag)
                                prev_data = None
                                logger.debug('Skip line of another application (%s)', apptag)
                                continue
                        else:
                            app = tagmap[apptag]
                    else:
                        app = logparser.app
                    app.counter += 1

                ###
                # Process the message part of the log line. First search for provided pattern(s)
                # then process with app rules if the app processing is enabled.
                pattern_search = True
                if patterns:
                    for regexp in patterns:
                        pattern_match = regexp.search(logdata.message)
                        if (pattern_match is not None and not invert) or \
                           (pattern_match is None and invert):
                            break
                    else:
                        if not thread:
                            logger.debug('Unmatched line: %r', line[:-1])
                            prev_data = None
                            continue
                        pattern_search = False
                elif invert:
                    if not thread:
                        logger.debug('Unmatched line: %r', line[:-1])
                        prev_data = None
                        continue
                    pattern_search = False

                # Log message parsing with app's rules
                if useapps and (pattern_search or thread):
                    rule_match, full_match, app_thread, map_dict = app.process(logdata)
                    if not rule_match:
                        # Log message unparsable by app rules
                        if not match_unparsed:
                            if pattern_search:
                                logger.debug('Unparsable line: %r', line[:-1])
                            prev_data = None
                            continue
                        if map_dict is not None:
                            line = outmap.map2str(header_gids, header_match, map_dict)
                    elif match_unparsed:
                        # Log message parsed but match_unparsed option
                        prev_data = None
                        continue
                    elif app_thread is not None:
                        if map_dict is not None:
                            line = outmap.map2str(header_gids, header_match, map_dict)
                        app.cache.add_line(getline(line), app_thread,
                                           pattern_search, full_match, event_time)
                    elif not full_match and app.has_filters:
                        if pattern_search:
                            print('Filtered line: %r', line[:-1])
                        prev_data = None
                        continue
                    elif map_dict is not None:
                        line = outmap.map2str(header_gids, header_match, map_dict)

                    # Handle timestamps for report
                    if make_report:
                        if first_event is None:
                            first_event = event_time
                            last_event = event_time
                        else:
                            if first_event > event_time:
                                first_event = event_time
                            if last_event < event_time:
                                last_event = event_time

                ###
                # Increment counters and send to output. Purge old threads every
                # PURGE_THREADS_LIMIT processed lines.
                if thread:
                    if (filelineno % PURGE_THREADS_LIMIT) == 0:
                        for app in applist:
                            apps[app].purge_unmatched_threads(event_time)
                            max_threads = None if max_count is None else max_count - matching_counter
                            matching_counter += apps[app].cache.flush_old_cache(event_time, print_lines, max_threads)
                else:
                    matching_counter += 1
                    logger.debug('Matched line: %r', line[:-1])
                    if print_lines:
                        print(getline(line), end='')

                # Write line to raw file if provided by option
                if rawfh is not None:
                    rawfh.write(getline(line))

                # Stops iteration if max_count matchings is exceeded
                if max_count is not None and matching_counter >= max_count:
                    break

        # End-of file thread matching and output
        if thread:
            for app in applist:
                try:
                    apps[app].purge_unmatched_threads(event_time)
                except UnboundLocalError:
                    break
                if max_count is not None and matching_counter >= max_count:
                    break
                max_threads = None if max_count is None else max_count - matching_counter
                matching_counter += apps[app].cache.flush_cache(event_time, print_lines, max_threads)

        # Save modificable class variables
        self._parser = logparser
        if make_report:
            self._first_event = first_event
            self._last_event = last_event
        return filelineno, matching_counter, unparsed_counter, extra_tags

    def make_report(self):
        """
        Create the report based on the results of Lograptor run
        """
        if not self.args.report:
            return False

        if self.report.make():

            if self.args.output is None:
                formats = ['plain']
            else:
                formats = set()
                for channel in self.report.channels:
                    formats = formats.union(channel.formats)
            logger.debug('Creating report formats: %r', formats)
            self.report.make_formats(formats)
            return True
        return False

    def send_report(self):
        """
        Publish the report
        """
        self.report.send(self.apps, self.rawfh)

    def mktempdir(self):
        """
        Set up a safe temp dir
        """
        logger.info('Setting up a temporary directory')

        tmpdir = self.config['tmpdir']
        logger.debug('tmpdir=%r', tmpdir)
        if tmpdir != "":
            tempfile.tempdir = tmpdir
        logger.info('Creating a safe temporary directory')
        tmpprefix = tempfile.mkdtemp('.LOGRAPTOR')

        try:
            pass
        except:
            msg = 'could not create a temp directory in "{0}"!'.format(tmpprefix)
            raise LograptorConfigError(msg)

        self.tmpprefix = tmpprefix
        tempfile.tempdir = tmpprefix

        logger.info('Temporary directory created in %r', tmpprefix)

    def cleanup(self):
        """
        Clean up after ourselves.
        """
        logger.info('Cleanup routine called')

        if self.rawfh is not None:
            print("Close rawlogs file ...")
            self.rawfh.close()

        if self.tmpprefix is not None:
            from shutil import rmtree

            logger.info('Removing the temp dir %r', self.tmpprefix)
            rmtree(self.tmpprefix)
