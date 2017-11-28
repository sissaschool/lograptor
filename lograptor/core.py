# -*- coding: utf-8 -*-
"""
This module contain core classes and methods for lograptor package.
"""
#
# This file is part of lograptor.
#
# Lograptor is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Lograptor is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with lograptor; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# See the file 'LICENSE' in the root directory of the present
# distribution for more details.
#
# @Author Davide Brunato <brunato@sissa.it>
#
import os
import time
import datetime
import re
import glob
import logging
import fileinput
import sys
import fnmatch

from .exceptions import (
    LogRaptorConfigError, FileMissingError, LogFormatError, LogRaptorOptionError, LogRaptorArgumentError
)
from .confparsers import LogRaptorConfig
from .application import AppLogParser
from .matcher import create_matcher_engine
from .filemap import FileMap
from .cache import LookupCache
from .report import Report
from .channels import TermChannel, MailChannel, FileChannel
from .timedate import get_interval
from .utils import results_to_string, is_pipe, is_redirected, protected_property, normalize_path

logger = logging.getLogger(__package__)

try:
    STDIN_FILENO = sys.stdin.fileno()
except ValueError:
    STDIN_FILENO = 0

try:
    prompt = raw_input
except NameError:
    prompt = input


class LogRaptor(object):
    """
    This is the core class of the lograptor package.

    :param args: Namespace of arguments with run options.
    :param config: List of configuration files paths. The first file readable is used.
    """
    DEFAULT_CONFIG_FILES = (
        'lograptor.conf',
        '%s/.config/lograptor/lograptor.conf' % os.path.expanduser('~'),
        '/etc/lograptor/lograptor.conf'
    )

    def __init__(self, args, config=None):
        try:
            self.config = LogRaptorConfig(cfgfiles=args.cfgfiles or self.DEFAULT_CONFIG_FILES)
        except IOError as err:
            logger.critical('no configuration available in files %r: %r', args.cfgfiles, err)
            raise FileMissingError('abort %r for previous errors' % __package__)
        else:
            self.args = args
            self.set_logger()
            logger.debug("args={}".format(args))

        # Create a lookup cache when required by arguments
        if any([args.anonymize, args.uid_lookup, args.ip_lookup]):
            self.name_cache = LookupCache(args, self.config)
        else:
            self.name_cache = None

        self._matcher = self.matcher
        self._patterns = self.patterns
        self._time_range = self.time_range
        self._fields = self.fields
        self._hosts = self.hosts
        self._channels = self.channels
        self._report = self.report

        # Load applications
        self._config_apps = self._read_apps()
        self._config_tags = {}
        self._apps = self.apps
        self._tags = self.tags
        self._logmap = self.logmap

        self.unknown_tags = set()

        if args.loglevel == 4:
            logger.debug("End of lograptor setup!!")
            prompt("press <ENTER> to continue ...")

    # Argument properties
    @property
    def filters(self):
        """Log processor filters."""
        return self.args.filters

    @property
    def recursive(self):
        return self.args.recursive or self.args.dereference_recursive

    @property
    def follow_symlinks(self):
        return self.args.dereference_recursive

    @property
    def include(self):
        return self.args.include

    @property
    def exclude(self):
        if self.exclude_from:
            try:
                exclude = [p.rstrip('\n') for p in fileinput.input(self.args.exclude_from)]
            except (IOError, OSError) as err:
                raise LogRaptorArgumentError('exclude-from', err)
            else:
                return exclude.extend(self.args.exclude)
        else:
            return self.args.exclude

    @property
    def exclude_from(self):
        return self.args.exclude_from

    @property
    def exclude_dir(self):
        return self.args.exclude_dir

    def set_logger(self):
        """
        Setup lograptor logger with an handler and a formatter. The logging
        level is defined by a [0..4] range, where an higher value means a
        more verbose logging. The loglevel value is mapped to correspondent
        logging module's value:

        LOG_CRIT=0 (syslog.h value is 2) ==> logging.CRITICAL
        LOG_ERR=1 (syslog.h value is 3) ==> logging.ERROR
        LOG_WARNING=2 (syslog.h value is 4) ==> logging.WARNING
        LOG_INFO=3 (syslog.h value is 6) ==> logging.INFO
        LOG_DEBUG=4 (syslog.h value is 7) ==> logging.DEBUG

        If the stdout is a tty the log is sent to stderr, otherwise is sent
        to the configured logfile.
        """
        # Higher or lesser argument values are also mapped to DEBUG or CRITICAL
        effective_level = max(logging.DEBUG, logging.CRITICAL - self.args.loglevel * 10)
        logger.setLevel(effective_level)

        # Add an handler if missing
        if not logger.handlers:
            if sys.stdout.isatty():
                handler = logging.StreamHandler()
            else:
                try:
                    handler = logging.FileHandler(self.config.getstr('main', 'logfile'))
                except (IOError, OSError, TypeError, AttributeError):
                    handler = logging.StreamHandler()
            logger.addHandler(handler)

        # Set the formatter of each handler (normally there is only one handler)
        for handler in logger.handlers:
            if effective_level <= logging.DEBUG:
                formatter = logging.Formatter("[%(levelname)s:%(module)s:%(funcName)s: %(lineno)s] %(message)s")
            else:
                formatter = logging.Formatter("%(levelname)s: %(message)s")
            handler.setLevel(effective_level)
            handler.setFormatter(formatter)

    @protected_property
    def report(self):
        logger.debug("configure a %r report ...", self.args.report)
        if self.args.report is None:
            return None
        elif self.args.report is True:
            return Report('default', self._patterns, self.args, self.config)
        else:
            return Report(self.args.report, self._patterns, self.args, self.config)

    @protected_property
    def patterns(self):
        """
        A tuple with re.RegexObject objects created from regex pattern arguments.
        """
        # No explicit argument for patterns ==> consider the first source argument as pattern.
        if not self.args.patterns and not self.args.pattern_files:
            try:
                self.args.patterns.append(self.args.files.pop(0))
            except IndexError:
                raise LogRaptorArgumentError('PATTERN', 'no search pattern')

        # Get the patterns from arguments and files
        patterns = set()
        if self.args.pattern_files:
            patterns.update([p.rstrip('\n') for p in fileinput.input(self.args.pattern_files)])
        patterns.update(self.args.patterns)
        logger.debug("search patterns to be processed: %r", patterns)

        # If one pattern is empty then skip the other patterns
        if '' in patterns:
            logger.info("an empty pattern provided: match all strings!")
            return tuple()

        try:
            flags = re.IGNORECASE if self.args.case else 0 | re.UNICODE
            return tuple([
                re.compile(r'(\b%s\b)' % pat if self.args.word else '(%s)' % pat, flags=flags)
                for pat in patterns if pat
            ])
        except re.error as err:
            raise LogRaptorArgumentError('wrong regex syntax for pattern: %r' % err)

    @protected_property
    def files(self):
        """
        A list of input sources. Each item can be a file path, a glob path or URL.
        """
        # If no files but a recursion option ==> use the current directory
        if not self.args.files and self.recursive:
            return ['.']
        else:
            return self.args.files

    @protected_property
    def fields(self):
        logger.debug("get fields from arguments ...")
        unknown = [k for item in self.filters for k in item if k not in self.config.options('fields')]
        if unknown:
            raise LogRaptorArgumentError('fields', 'undefined fields: %r.' % list(unknown))
        return self.config.options('fields')

    @protected_property
    def matcher(self):
        """
        Matcher engine: ruled, unruled, unparsed.
        """
        if self.args.matcher is None:
            return 'ruled'
        elif self.args.matcher.startswith('-'):
            matcher = self.args.matcher.strip('-').replace('-', '_')
        else:
            matcher = self.args.matcher

        if matcher not in ['ruled', 'unruled', 'unparsed']:
            raise LogRaptorArgumentError('matcher', 'unknown matcher argument %r' % matcher)
        return matcher

    @protected_property
    def hosts(self):
        hosts = [re.compile(fnmatch.translate(host)) for host in set(self.args.hostnames or ['*'])]
        logger.debug('hosts to be processed: %r', hosts)
        return hosts

    @protected_property
    def time_range(self):
        """
        Time range that is determined from arguments.
        """
        if self.args.period is None:
            if self.args.files or is_pipe(STDIN_FILENO) or is_redirected(STDIN_FILENO):
                time_range = (None, None)
            else:
                diff = 86400  # 24h = 86400 seconds
                time_range = get_interval(int(time.time()), diff, 3600)
        else:
            time_range = self.args.period

        logger.debug('time range to be processed: %r', time_range)
        return time_range

    @property
    def confdir(self):
        confdir = self.config.get('main', 'confdir')
        return normalize_path(confdir, base_path=os.path.dirname(self.config.cfgfile))

    def _read_apps(self):
        """
        Read the configuration of applications returning a dictionary
        :param confdir: Read apps from a configuration directory.
        :return: A dictionary with application names as keys and configuration
        object as values.
        """
        apps = {}
        for cfgfile in glob.iglob(os.path.join(self.confdir, '*.conf')):
            name = os.path.basename(cfgfile)[0:-5]
            try:
                app = AppLogParser(name, cfgfile, self.args, self.config, self.name_cache, self.report)
            except (LogRaptorOptionError, LogRaptorConfigError, LogFormatError) as err:
                logger.error('cannot add app %r: %s', name, err)
            else:
                apps[name] = app

        if not apps:
            raise LogRaptorConfigError('no configured application in %r!' % self.confdir)
        return apps

    @protected_property
    def apps(self):
        """
        Dictionary with loaded applications.
        """
        logger.debug("initialize applications ...")
        enabled = None
        appnames = self.args.appnames or self._config_apps.keys()
        unknown = set(appnames) - set(self._config_apps.keys())
        if unknown:
            raise LogRaptorArgumentError("--apps", "not found apps %r" % list(unknown))

        if appnames or enabled is None:
            return {k: v for k, v in self._config_apps.items() if k in appnames}
        else:
            return {k: v for k, v in self._config_apps.items() if k in appnames and v.enabled == enabled}

    @protected_property
    def tags(self):
        """
        Map from log app-name to an application.
        """
        logger.debug("populate tags map ...")
        appnames = self._apps.keys()
        unknown = set(appnames)
        unknown.difference_update(self._config_apps.keys())
        if unknown:
            raise ValueError("unknown apps: %r" % list(unknown))

        apps = [v for v in self._config_apps.values() if v.name in appnames]
        tagmap = {}
        for app in sorted(apps, key=lambda x: (x.priority, x.name)):
            for tag in app.tags:
                if not tag:
                    raise LogRaptorConfigError('found an empty tag for app %r' % app.name)
                try:
                    tagmap[tag].append(app)
                except KeyError:
                    tagmap[tag] = [app]
        return tagmap

    @protected_property
    def logmap(self):
        if not self.args.files and (is_pipe(STDIN_FILENO) or is_redirected(STDIN_FILENO)):
            # No files and input by a pipe
            return [(sys.stdin, self._apps.values())]
        else:
            # Build the LogMap instance adding the list of files to be scanned.
            logmap = FileMap(self._time_range, self.recursive,
                             self.follow_symlinks, self.include, self.exclude, self.exclude_dir)
            for app in self._apps.values():
                logmap.add(self.args.files or app.files, app, app.priority)
            if len(logmap) > 1 and self.args.with_filename is None:
                self.args.with_filename = True
            return logmap

    @protected_property
    def channels(self):
        """Output channels"""
        try:
            return self._channels
        except AttributeError:
            logger.debug("initialize output channels ...")

        channels = self.args.channels
        config_channels = [sec.rpartition('_')[0] for sec in self.config.sections(suffix='_channel')]
        unknown = set(channels) - set(config_channels)
        if unknown:
            raise ValueError("undefined channel %r" % list(unknown))

        output_channels = []
        for channel in set(channels):
            channel_type = self.config.get('%s_channel' % channel, 'type')
            if channel_type == 'tty':
                output_channels.append(TermChannel(channel, self.args, self.config))
            elif channel_type == 'file':
                output_channels.append(FileChannel(channel, self.args, self.config))
            elif channel_type == 'mail':
                output_channels.append(MailChannel(channel, self.args, self.config))
            else:
                raise LogRaptorConfigError('unknown channel type %r' % channel_type)
        return output_channels

    def print_config(self):
        """
        Return a formatted text with main configuration parameters.
        """
        # Create a dummy report object if necessary
        channels = [sect.rsplit('_')[0] for sect in self.config.sections(suffix='_channel')]
        channels.sort()
        disabled_apps = [app for app in self._config_apps.keys() if app not in self._apps]
        return u''.join([
            u"\n--- %s configuration ---" % __package__,
            u"\nConfiguration file: %s" % self.config.cfgfile,
            u"\nConfiguration directory: %s" % self.confdir,
            u"\nConfigured applications: %s" % ', '.join(self._config_apps.keys()),
            u"\nDisabled applications: %s" % ', '.join(disabled_apps) if disabled_apps else '',
            u"\nFilter fields: %s" % ', '.join(self.config.options('fields')),
            u"\nOutput channels: %s\n" % ', '.join(channels) if channels else u'No channels defined',
            ''
        ])

    def get_run_summary(self, run_stats):
        """
        Produce a text summary from run statistics.

        :param run_stats:
        :return: Formatted multiline string
        """
        summary = [
            u'\n--- %s run summary ---' % __package__,
            u'Number of processed files: %(tot_files)d',
            u'Total lines read: %(tot_lines)d',
            u'Total log events matched: %(tot_counter)d',
        ]
        if run_stats['tot_unparsed'] > 0:
            summary.append(u'WARNING: Found %(tot_unparsed)d unparsed log header lines')
        if self.args.appnames:
            if any([app.counter > 0 for app in self._apps.values()]):
                proc_apps = [app for app in self._apps.values() if app.counter > 0]
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
                summary.append(u'Found unknown app tags: %(unknown_tags)s')
            if any([app.unparsed_counter > 0 for app in self._apps.values()]):
                summary.append(u'Found unparsed log lines for apps: {}'.format(u', '.join([
                    u'%s(%d)' % (app.name, app.unparsed_counter)
                    for app in self._apps.values() if app.unparsed_counter > 0
                ])))
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
        self.open()

        # Iter between log files. The iteration use the log files modified between the
        # initial and the final date, skipping the other files.
        for (path_or_file, applist) in self._logmap:
            logger.debug('process %r for apps %r', path_or_file, applist)
            try:
                num_lines, counter, unparsed_counter, unknown_tags, first_event, last_event = \
                    process_logfile(path_or_file, applist)
                logfiles.append(str(path_or_file))

                tot_lines += num_lines
                tot_counter += counter
                tot_unparsed += unparsed_counter
                self.unknown_tags = self.unknown_tags.union(unknown_tags)
                try:
                    if start_event is None or start_event > first_event:
                        start_event = first_event
                    if end_event is None or end_event < last_event:
                        end_event = last_event
                except TypeError:
                    pass

            except IOError as msg:
                if self.args.loglevel:
                    logger.error(msg)

        tot_files = len(logfiles)
        if not logfiles and self._time_range[0] is not None:
            raise FileMissingError("no file in time range {}!".format([
                datetime.datetime.strftime(e, '%Y-%m-%dT%H:%M:%S') for e in self._time_range
            ]))
        elif not tot_lines:
            return False

        try:
            start_time = datetime.datetime.fromtimestamp(start_event)
            end_time = datetime.datetime.fromtimestamp(end_event)
        except (TypeError, UnboundLocalError):
            start_time = end_time = None

        run_stats = {
            'start_time': start_time,
            'end_time': end_time,
            'tot_counter': tot_counter,
            'tot_files': tot_files,
            'tot_lines': tot_lines,
            'tot_unparsed': tot_unparsed,
            'files': ', '.join(logfiles),
            'unknown_tags': ', '.join(
                set([tag for tag in self.unknown_tags
                     if tag not in self._config_tags and not tag.isdigit()])
            )
        }

        # If final report is requested then purge all unmatched threads and set time stamps.
        # Otherwise send final run summary if messages are not disabled.
        if tot_counter > 0 and self.args.report:
            self.report.set_stats(run_stats)
            self.report.make(self._apps)
            self.send_report()
        elif self.args.loglevel and not self.args.quiet:
            self.send_message(self.get_run_summary(run_stats))

        return tot_counter > 0

    def open(self):
        for channel in self._channels:
            channel.open()

    def send_message(self, message):
        for channel in self._channels:
            channel.send_message(message)

    def send_report(self):
        formats = list(set([fmt for channel in self._channels for fmt in channel.formats]))
        report_parts = self.report.get_report_parts(self._apps, formats)
        for channel in self._channels:
            channel.send_report(report_parts)

    def cleanup(self):
        for channel in self._channels:
            channel.close()
        if self.args.report:
            self.report.cleanup()
