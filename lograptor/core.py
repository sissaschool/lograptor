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
import fnmatch
from sre_constants import error as RegexCompileError

from .application import AppLogParser
from .configmap import ConfigMap
from .exceptions import LograptorConfigError, FileMissingError, FormatError, OptionError, LograptorArgumentError
from .matcher import create_matcher_engine
from .filemap import FileMap
from .cache import RenameCache
from .report import Report
from .channels import StdoutChannel, MailChannel, FileChannel
from .timedate import get_interval
from .utils import set_logger

logger = logging.getLogger(__name__)


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
        'template.plain': '${cfgdir}/report_template.txt',
        'subreport.login_report': 'Logins',
        'subreport.mail_report': 'Mail report',
        'subreport.command_report': 'System commands',
        'subreport.query_report': 'Database lookups'
    },
    'channel.default': {
        'type': 'stdout',
        'formats': 'plain',

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
        try:
            args.patterns.append(args.files.pop(0))
        except IndexError:
            raise LograptorArgumentError('PATTERN', 'no search pattern')

    _lograptor = Lograptor(args, is_batch)

    # Dump a configuration summary and exit when the program is called from the
    # command line without options and arguments or with only the --conf option.
    if not is_batch and (
            len(sys.argv) == 1 or
            (len(sys.argv) == 2 and sys.argv[1].startswith('--conf=')) or
            (len(sys.argv) == 3 and sys.argv[1] == '--conf')):
        print(_lograptor.print_config())
        _lograptor.cleanup()
        return 0

    try:
        retval = _lograptor.process()
        if _lograptor.make_report():
            _lograptor.send_report()
    finally:
        _lograptor.cleanup()

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
            self.config = ConfigMap(
                cfgfiles=args.cfgfile,
                defaults=DEFAULT_CONFIG,
                base_sections=['main', 'patterns']
            )
        except IOError as err:
            logger.critical('no configuration available in files %r: %r', args.cfgfile, err)
            raise FileMissingError('abort "{0}" for previous errors'.format(__name__))
        else:
            if is_batch:
                set_logger('lograptor', args.loglevel, logfile=self.config.getstr('main', 'logfile'))
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
        if args.report is not None:
            self.report = Report(self.patterns, self.apps, self.args, self.config)

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
        unknown = set(appnames).difference_update(self._loaded_apps)
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
        unknown = set(appnames).difference_update(self._loaded_apps.keys())
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
            u"Configuration directory: {0}".format(self.config.getstr('main', 'cfgdir')),
            u"Enabled applications: {0}".format(', '.join(self.apps.keys())),
            u"Disabled applications: {0}".format(', '.join([
                                                               app for app in self.get_apps() if app not in self.apps])),
            u"Available filters: {0}".format(', '.join([
                opt for opt in self.config.options('filters')])),
            u"Output channels: \n    {0}\n".format('\n    '.join([
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

    def get_line_printer(self):
        def dummy_printer(*args, **kwargs):
            pass

        line_printers = tuple([channel.get_line_printer() for channel in self.channels if channel.is_raw()])

        if not line_printers:
            return dummy_printer
        elif len(line_printers) == 1:
            return line_printers[0]

        def multi_line_printer(*args, **kwargs):
            for f in line_printers:
                f(*args, **kwargs)
        return multi_line_printer

    def process(self, parsers=None):
        """
        Log processing main routine. Iterate over the log files calling
        the processing internal routine for each file.
        """
        logger.info('starting the processing of the log files ...')

        apps = self.apps
        print_filename = self.print_filename
        process_logfile = create_matcher_engine(self, parsers)

        tot_lines = 0
        tot_counter = 0
        tot_unparsed = 0
        logfiles = []

        # Create temporary file for matches rawlog
        if self.args.report is not None and self.report.need_rawlogs():
            self.mktempdir()
            self.rawfh = tempfile.NamedTemporaryFile(mode='w+', delete=False)
            logger.info('RAW strings file created in %r', self.rawfh.name)

        # Iter between log files. The iteration use the log files modified between the
        # initial and the final date, skipping the other files.
        for (filename, applist) in self.logmap:
            logger.debug('process %r for apps %r', filename, applist)
            if self.rawfh is not None and print_filename is None:
                self.rawfh.write('\n*** Filename: {0} ***\n'.format(filename))

            try:
                num_lines, counter, unparsed_counter, extra_tags, first_event, last_event = process_logfile(filename, applist)
                logfiles.append(filename)

                tot_lines += num_lines
                tot_counter += counter
                tot_unparsed += unparsed_counter
                self.extra_tags = self.extra_tags.union(extra_tags)

                if self.args.thread:
                    for app in applist:
                        apps[app].purge_threads()

            except IOError as msg:
                if not self.args.no_messages:
                    logger.error(msg)

        tot_files = len(logfiles)
        if not logfiles and self.initial_dt is not None:
            raise FileMissingError(
                "no file in datetime interval (%s, %s)!" % (self.initial_dt, self.final_dt)
            )

        logger.info('Total files processed: %d', tot_files)
        logger.info('Total log lines processed: %d', tot_lines)

        # Save run stats
        try:
            starttime = datetime.datetime.fromtimestamp(first_event)
            endtime = datetime.datetime.fromtimestamp(last_event)
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
        if self.args.report is not None:
            self.report.set_stats(run_stats)
            if self.rawfh is not None:
                self.rawfh.close()
        elif not self.args.no_messages and not self.args.quiet:
            print(u'%s\n' % self.get_run_summary(run_stats))

        return tot_counter > 0

    def make_report(self):
        """
        Create the report based on the results of Lograptor run
        """
        if self.args.report is None:
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

        tmpdir = self.config.getstr('main', 'tmpdir')
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
