# -*- coding: utf-8 -*-
"""
This module contain core classes and methods for lograptor package.
"""
#
# Copyright (C), 2011-2017, by SISSA - International School for Advanced Studies.
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
import os
import time
import datetime
import re
import glob
import logging
import fileinput
import sys
import fnmatch
from collections import Counter

from .exceptions import (
    LogRaptorConfigError, FileMissingError, LogFormatError, LogRaptorOptionError, LogRaptorArgumentError
)
from .confparsers import LogRaptorConfig
from .application import AppLogParser
from .matcher import create_matcher
from .filemap import FileMap
from .cache import LookupCache
from .dispatchers import UnbufferedDispatcher, LineBufferDispatcher, ThreadedDispatcher
from .report import Report
from .channels import TermChannel, MailChannel, FileChannel
from .timedate import get_datetime_interval
from .utils import is_pipe, is_redirected, protected_property, normalize_path, safe_expand

logger = logging.getLogger(__package__)

try:
    STDIN_FILENO = sys.stdin.fileno()
except ValueError:
    STDIN_FILENO = 0

try:
    prompt = raw_input
except NameError:
    prompt = input


STANDARD_ENCODINGS = ['utf_8', 'latin1', 'latin2']


class LogRaptor(object):
    """
    This is the core class of the lograptor package.

    :param args: Namespace of arguments with run options.
    """
    DEFAULT_CONFIG_FILES = (
        'lograptor.conf',
        os.path.expanduser('~/.config/lograptor/lograptor.conf'),
        '/etc/lograptor/lograptor.conf',
        os.path.join(os.path.dirname(__file__), 'config/lograptor.conf'),
    )

    def __init__(self, args):
        try:
            self.config = LogRaptorConfig(cfgfiles=args.cfgfiles or self.DEFAULT_CONFIG_FILES)
        except (IOError, OSError) as err:
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

        self._encodings = self.encodings
        self._matcher = self.matcher
        self._patterns = self.patterns
        self._time_period = self.time_period
        self._fields = self.fields
        self._hosts = self.hosts

        # Load applications
        self._config_apps = self._read_apps()
        self._config_tags = {}
        self._apps = self.apps
        self._tags = self.apptags
        self._logmap = self.logmap

        # Setup output channels
        self._channels = self.channels
        self._report = self.report

        if args.loglevel == 4:
            logger.debug("End of lograptor setup!!")
            prompt("press <ENTER> to continue ...")

    def _read_apps(self):
        """
        Read the configuration of applications returning a dictionary

        :return: A dictionary with application names as keys and configuration \
        object as values.
        """
        apps = {}
        for cfgfile in glob.iglob(os.path.join(self.confdir, '*.conf')):
            name = os.path.basename(cfgfile)[0:-5]
            try:
                app = AppLogParser(name, cfgfile, self.args, self.logdir,
                                   self.fields, self.name_cache, self.report)
            except (LogRaptorOptionError, LogRaptorConfigError, LogFormatError) as err:
                logger.error('cannot add app %r: %s', name, err)
            else:
                apps[name] = app

        if not apps:
            raise LogRaptorConfigError('no configured application in %r!' % self.confdir)
        return apps

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
                    handler = logging.FileHandler(self.config.get('main', 'logfile'))
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
        if self.args.report is False:
            return False
        elif self.args.report is None:
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

        patterns = {k: v for k, v in self.config.items('patterns')}
        return {
            k: safe_expand(v, patterns) for k, v in self.config.items('fields')
        }

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
        hosts = [re.compile(fnmatch.translate(host)) for host in set(self.args.hosts or ['*'])]
        logger.debug('hosts to be processed: %r', hosts)
        return hosts

    @property
    def time_range(self):
        """
        Selected time range for log matching. If `None` then match always (equivalent to 0:00-23:59).
        """
        return self.args.time_range

    @protected_property
    def time_period(self):
        """
        Time period that is determined from the arguments --date and --last. It's a 2-tuple with
        (<start datetime>, <end_datetime>) items. An item is `None` if there isn't a limit.
        """
        if self.args.time_period is None:
            if self.args.files or is_pipe(STDIN_FILENO) or is_redirected(STDIN_FILENO):
                time_period = (None, None)
            else:
                diff = 86400  # 24h = 86400 seconds
                time_period = get_datetime_interval(int(time.time()), diff, 3600)
        else:
            time_period = self.args.time_period

        logger.debug('time period to be processed: %r', time_period)
        return time_period

    @property
    def confdir(self):
        confdir = self.config.get('main', 'confdir')
        return normalize_path(confdir, base_path=os.path.dirname(self.config.cfgfile))

    @property
    def logdir(self):
        confdir = self.config.get('main', 'logdir')
        return normalize_path(confdir, base_path=os.path.dirname(self.config.cfgfile))

    @property
    def encodings(self):
        return self.config.get('main', 'encodings').split(',')

    @protected_property
    def apps(self):
        """
        Dictionary with loaded applications.
        """
        logger.debug("initialize applications ...")
        enabled = None
        apps = self.args.apps or self._config_apps.keys()
        unknown = set(apps) - set(self._config_apps.keys())
        if unknown:
            raise LogRaptorArgumentError("--apps", "not found apps %r" % list(unknown))

        if apps or enabled is None:
            return {k: v for k, v in self._config_apps.items() if k in apps}
        else:
            return {k: v for k, v in self._config_apps.items() if k in apps and v.enabled == enabled}

    @protected_property
    def apptags(self):
        """
        Map from log app-name to an application.
        """
        logger.debug("populate tags map ...")
        apps = self._apps.keys()
        unknown = set(apps)
        unknown.difference_update(self._config_apps.keys())
        if unknown:
            raise ValueError("unknown apps: %r" % list(unknown))

        apps = [v for v in self._config_apps.values() if v.name in apps]
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
        apps = sorted(self._apps.values(), key=lambda x: x.priority)
        if self.args.files:
            logmap = FileMap(self._time_period, recursive=self.recursive, follow_symlinks=self.follow_symlinks,
                             include=self.include, exclude=self.exclude, exclude_dir=self.exclude_dir)
            logmap.add(self.args.files, apps)
        elif is_pipe(STDIN_FILENO) or is_redirected(STDIN_FILENO):
            # No files and input by a pipe
            logmap = [(sys.stdin, apps)]
        else:
            # Build the LogMap instance adding the list of files from app config files
            logmap = FileMap(self._time_period, recursive=self.recursive, follow_symlinks=self.follow_symlinks,
                             include=self.include, exclude=self.exclude, exclude_dir=self.exclude_dir)
            for app in apps:
                logmap.add(app.files, [app])

        if self.args.with_filename is None:
            iter_logmap = iter(logmap)
            try:
                next(iter_logmap)
                next(iter_logmap)
            except StopIteration:
                pass
            else:
                # the logmap has more than one file --> prefix log with filename
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

    def __repr__(self):
        return u"<%s %r at %#x>" % (self.__class__.__name__, self.config.cfgfile, id(self))

    def __call__(self, dispatcher=None, parsers=None):
        """
        Log processing main routine. Iterate over the log files calling
        the processing internal routine for each file.
        """
        if dispatcher is None:
            dispatcher = self.create_dispatcher()
        matcher_engine = self.create_matcher(dispatcher, parsers=parsers)
        dispatcher.open()

        files = []
        lines = matches = unknown = 0
        extra_tags = Counter()
        first_event = last_event = None
        if self.args.report:
            self.report.cleanup()

        # Iter between log files. The iteration use the log files modified between the
        # initial and the final date, skipping the other files.
        for (source, apps) in self._logmap:
            if apps is not None:
                logger.debug('process %r for apps %r', source, apps)
            else:
                if self.args.files:
                    logger.error("%s: No such file or directory", source)
                continue

            try:
                for encoding in self._encodings:
                    try:
                        result = matcher_engine(source, apps, encoding)
                    except UnicodeDecodeError:
                        continue
                    break
                else:
                    logger.error("no valid decoder found for %r." % source)
                    continue

                files.append(str(source))

                lines += result.lines
                matches += result.matches
                unknown += result.unknown
                if result.extra_tags:
                    extra_tags.update(result.extra_tags)
                if result.first_event is not None:
                    if first_event is None or first_event > result.first_event:
                        first_event = result.first_event
                if result.last_event is not None:
                    if last_event is None or last_event < result.last_event:
                        last_event = result.last_event

            except IOError as msg:
                if self.args.loglevel:
                    logger.error(msg)

        if not files and self._time_period[0] is not None:
            raise FileMissingError("no file in time period {}!".format([
                datetime.datetime.strftime(e, '%Y-%m-%dT%H:%M:%S') for e in self._time_period
            ]))
        elif not lines:
            return False

        try:
            first_event = datetime.datetime.fromtimestamp(first_event)
            last_event = datetime.datetime.fromtimestamp(last_event)
        except (TypeError, UnboundLocalError):
            first_event = last_event = None

        run_stats = {
            'files': files,
            'first_event': first_event,
            'last_event': last_event,
            'matches': matches,
            'lines': lines,
            'unknown': unknown,
            'extra_tags': extra_tags,
        }

        if unknown > 0:
            logger.warning('found {} lines with an unknown log format'.format(unknown))
        if extra_tags:
            num_lines = sum(extra_tags.values())
            logger.warning(u'found {} unknown extra app tags: {}'.format(num_lines, dict(extra_tags)))

        # If the final report is requested then purge all unmatched threads and set time stamps.
        # Otherwise send final run summary if messages are not disabled.
        if matches > 0 and self.report:
            self.report.set_stats(run_stats)
            self._report.make(self._apps)
            formats = list(set([fmt for channel in self._channels for fmt in channel.formats]))
            report_parts = self._report.get_report_parts(self._apps, formats)
            dispatcher.send_report(report_parts)
        elif self.args.loglevel and not self.args.quiet:
            dispatcher.send_message(self.get_run_summary(run_stats))
        dispatcher.close()

        return matches > 0

    def create_dispatcher(self):
        """
        Return a dispatcher for configured channels.
        """
        before_context = max(self.args.before_context, self.args.context)
        after_context = max(self.args.after_context, self.args.context)

        if self.args.files_with_match is not None or self.args.count or self.args.only_matching or self.args.quiet:
            # Sending of log lines disabled by arguments
            return UnbufferedDispatcher(self._channels)
        elif before_context == 0 and after_context == 0:
            # Don't need line buffering
            return UnbufferedDispatcher(self._channels)
        elif self.args.thread:
            return ThreadedDispatcher(self._channels, before_context, after_context)
        else:
            return LineBufferDispatcher(self._channels, before_context, after_context)

    def create_matcher(self, dispatcher, parsers=None):
        return create_matcher(
            dispatcher=dispatcher,
            parsers=parsers,
            apptags=self.apptags,
            matcher=self.matcher,
            patterns=self.patterns,
            hosts=self.hosts,
            time_range=self.time_range,
            time_period=self.time_period,
            thread=self.args.thread,
            invert=self.args.invert,
            count=self.args.count,
            files_with_match=self.args.files_with_match,
            max_count=self.args.max_count,
            only_matching=self.args.only_matching,
            quiet=self.args.quiet,
            name_cache=self.name_cache,
        )

    def get_config(self):
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
            u"\nOutput channels: %s" % ', '.join(channels) if channels else u'No channels defined',
            u"\nReports: %s\n" % ', '.join(
                [section[:-7] for section in self.config.sections(suffix='_report')]
            ),
            ''
        ])

    def get_run_summary(self, run_stats):
        """
        Produce a text summary from run statistics.

        :param run_stats: A dictionary containing run stats
        :return: Formatted multiline string
        """
        run_stats = run_stats.copy()
        run_stats['files'] = len(run_stats['files'])
        summary = [
            u'\n--- %s run summary ---' % __package__,
            u'Number of processed files: %(files)d',
            u'Total lines read: %(lines)d',
            u'Total log events matched: %(matches)d',
        ]
        if any([app.matches or app.unparsed for app in self.apps.values()]):
            if self.matcher == 'unruled':
                summary.append("Applications found (application rules not used):")
                for app in filter(lambda x: x.matches, self.apps.values()):
                    summary.append(u'  %s(matches=%d)' % (app.name, app.matches))
            else:
                summary.append("Applications found:")
                for app in filter(lambda x: x.matches or x.unparsed, self.apps.values()):
                    summary.append(u'  %s(matches=%d, unparsed=%s)' % (app.name, app.matches, app.unparsed))
        summary.append('\n')
        return '\n'.join(summary) % run_stats
