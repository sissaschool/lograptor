"""
This module defines core runner class for lograptor package.
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
import os
import time
import re
import glob
import logging
import fileinput
import sys
import fnmatch
import pathlib
import warnings
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from functools import cached_property
from typing import Any

from lograptor.exceptions import LogRaptorConfigError, FileMissingError, \
    LogFormatError, LogRaptorOptionError, LogRaptorArgumentError
from lograptor.confparsers import LogRaptorConfig
from lograptor.application import AppLogParser
from lograptor.logparsers import LogParser
from lograptor.matcher import create_matcher
from lograptor.filemap import FileMap
from lograptor.cache import LookupCache
from lograptor.dispatchers import DispatcherType, UnbufferedDispatcher, \
    LineBufferDispatcher, ThreadedDispatcher
from lograptor.patterns import GrokPattern, RulePattern
from lograptor.report import Report
from lograptor.channels import TermChannel, MailChannel, FileChannel
from lograptor.timedate import format_dt, get_datetime_interval, TimeRange
from lograptor.utils import is_pipe, is_redirected, normalize_path

logger = logging.getLogger(__package__)

try:
    STDIN_FILENO = sys.stdin.fileno()
except ValueError:
    STDIN_FILENO = 0

DEFAULT_ENCODINGS = ('utf_8', 'latin1', 'latin2')


class LogRaptor:
    """
    This is the core class of the lograptor package.

    :param args: Namespace with run options, as provided by CLI argument parser.
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

        self.args = args
        self.set_logger()

        if logger.level <= logging.DEBUG:
            logger.debug("args=%r", args)

            if self.interactive:
                choice = input("DEBUG level set: do you want to activate the debugger? (y/n): ...")
                if choice.lower() in ('y', 'yes'):
                    breakpoint()

        self.default_patterns = {k: p.pattern for k, p in self.named_patterns.items()}
        self.check_config()

    def check_config(self):
        # Check the rest of config using some cached properties.
        _ = self.apptags
        _ = self.exclude
        _ = self.matcher
        _ = self.patterns
        _ = self.filters
        _ = self.channels

        if not isinstance(self.args.max_count, int) or self.args.max_count < 0:
            raise LogRaptorConfigError('max_count must be a positive integer')

    def __repr__(self):
        return "<%s %r at %#x>" % (self.__class__.__name__, self.config.cfgfile, id(self))

    def set_logger(self):
        """
        Set up lograptor logger with a handler and a formatter. The logging
        level is defined by a [0..4] range, where a higher value means a
        more verbose logger. The loglevel value is mapped to correspondent
        logging module value:

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

        # Add a handler if missing
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
                formatter = logging.Formatter(
                    "[%(levelname)s:%(module)s:%(funcName)s: %(lineno)s] %(message)s"
                )
            else:
                formatter = logging.Formatter("%(levelname)s: %(message)s")
            handler.setLevel(effective_level)
            handler.setFormatter(formatter)

    def clear(self):
        """Clear out cached properties."""
        for k, v in self.__class__.__dict__.items():
            if isinstance(v, cached_property):
                self.__dict__.pop(k, None)

    @cached_property
    def interactive(self) -> bool:
        """Is True if the standard input is a TTY or a pipe or a redirection."""
        try:
            stdin_fileno = sys.stdin.fileno()
        except ValueError:
            return sys.stdin.isatty()
        else:
            if logger.level <= logging.DEBUG:
                logger.debug("is_atty: %r", os.isatty(STDIN_FILENO))
                logger.debug("is_pipe: %r", is_pipe(STDIN_FILENO))
                logger.debug("is_redirected: %r", is_redirected(STDIN_FILENO))
            return os.isatty(stdin_fileno) and (is_pipe(stdin_fileno) or is_redirected(stdin_fileno))

    @cached_property
    def config_apps(self) -> dict[str, AppLogParser]:
        """Returns a dictionary with configured applications."""
        logger.debug("load configured applications ...")

        apps: dict[str, AppLogParser] = {}
        for config_file in glob.iglob(os.path.join(self.confdir, '*.conf')):
            name = os.path.basename(config_file)[0:-5]
            try:
                app = AppLogParser(name, config_file, self)
            except (LogRaptorOptionError, LogRaptorConfigError, LogFormatError) as err:
                logger.error('cannot add app %r: %s', name, err)
            else:
                apps[name] = app

        if not apps:
            raise LogRaptorConfigError('no configured application in %r!' % self.confdir)
        return apps

    @cached_property
    def apps(self) -> dict[str, AppLogParser]:
        """Returns a dictionary with selected applications."""
        logger.debug('load selected applications ...')

        if not self.args.apps:
            # Without argument -a/--apps selects only the enabled applications
            return {k: v for k, v in self.config_apps.items() if v.enabled}

        if unknown := set(self.args.apps) - set(self.config_apps.keys()):
            raise LogRaptorArgumentError("--apps", "not found apps %r" % list(unknown))
        return {k: v for k, v in self.config_apps.items() if k in self.args.apps}

    @cached_property
    def apptags(self) -> dict[str, list[AppLogParser]]:
        """
        Map from log app-name to an application.
        """
        logger.debug("populate tags map ...")
        apps = [v for v in self.config_apps.values() if v.name in self.apps]

        tagmap: dict[str, list[AppLogParser]] = {}
        for app in sorted(apps, key=lambda x: (x.priority, x.name)):
            for tag in app.tags:
                if not tag:
                    msg = f'found an empty tag for app {app.name!r}'
                    if self.interactive:
                        raise LogRaptorConfigError(msg)
                    warnings.warn(msg, UserWarning)
                try:
                    tagmap[tag].append(app)
                except KeyError:
                    tagmap[tag] = [app]
        return tagmap

    @property
    def recursive(self) -> bool:
        """f True read all files under each directory, recursively."""
        return self.args.recursive or self.args.dereference_recursive

    @property
    def follow_symlinks(self) -> bool:
        """If true reads all files under each directory, recursively and following all symlinks."""
        return self.args.dereference_recursive

    @property
    def include(self) -> list[str]:
        """Search only in files that match any provided GLOB pattern."""
        return self.args.include

    @cached_property
    def exclude(self) -> list[str]:
        """
        List of GLOB patterns for excluding files whose base name matches any of them.
        Includes GLOB patterns expressed by both --exclude and --exclude-from options.
        """
        if self.args.exclude_from:
            try:
                exclude = [p.rstrip('\n') for p in fileinput.input(self.args.exclude_from)]
            except (IOError, OSError) as err:
                if self.interactive:
                    raise LogRaptorArgumentError('exclude-from', err)
                warnings.warn(f'processing exclude-from option fails: {err}', UserWarning)
                return self.args.exclude
            else:
                exclude.extend(self.args.exclude)
                return exclude
        else:
            return self.args.exclude

    @property
    def exclude_dir(self) -> list[str]:
        """List of GLOB patterns for excluding directories whose base name matches any of them."""
        return self.args.exclude_dir

    @cached_property
    def report(self) -> Report | None:
        logger.debug("configure a %r report ...", self.args.report)
        if self.args.report is False:
            # Default: no report
            return None
        elif self.args.report is None:
            # When --report option is provided without a name.
            return Report('default', self.patterns, self.args, self.config)
        else:
            # When --report <name> option is provided.
            return Report(self.args.report, self.patterns, self.args, self.config)

    @cached_property
    def patterns(self) -> Sequence[re.Pattern[str]]:
        """
        Returns a tuple with re.Pattern objects created from regex *pattern* arguments.
        These patterns are intended as additional filters for the log lines and don't
        interact with patterns loaded from configuration that are named patterns and
        are applied to app rules to get the final list of patterns to be processed.
        """
        patterns = set()

        # No explicit argument for patterns ==> consider the first source argument as pattern.
        if not self.args.patterns and not self.args.pattern_files:
            try:
                patterns.add(self.args.files.pop(0))
            except IndexError:
                raise LogRaptorArgumentError('PATTERN', 'no search pattern')
        elif self.args.pattern_files:
            # Get the patterns from arguments and files
            patterns.update([p.rstrip('\n') for p in fileinput.input(self.args.pattern_files)])

        patterns.update(self.args.patterns)
        logger.debug("search patterns to be processed: %r", patterns)

        # If one pattern is empty skip the other patterns
        if '' in patterns:
            logger.info("an empty pattern provided: match all strings!")
            return tuple()

        try:
            flags = re.IGNORECASE if self.args.ignore_case else 0 | re.UNICODE
            return tuple([
                re.compile(r'(\b%s\b)' % pat if self.args.word else '(%s)' % pat, flags=flags)
                for pat in patterns if pat
            ])
        except re.error as err:
            raise LogRaptorArgumentError('wrong regex syntax for pattern: %r' % err)

    @cached_property
    def named_patterns(self):
        """The named patterns loaded from configuration files that are used ."""
        patterns = {}

        def add_patterns(arg: Sequence[str]) -> None:
            try:
                name, pattern = arg
                grok_pattern = GrokPattern(pattern)
            except ValueError as err:
                logger.error("skip invalid GROK pattern %r: %s", arg[0], err)
            except TypeError:
                logger.debug("skip rule pattern in grok-pattern file: %r", arg[0])
            else:
                if name in patterns:
                    logger.info("override rule pattern: %r", name)
                else:
                    logger.debug("add rule pattern: %r", name)
                patterns[name] = grok_pattern

        for k, v in self.config.items('pattern_files'):
            filepath = pathlib.Path(self.config.cfgfile).parent / v
            with filepath.open('r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    add_patterns(line.split(None, 1))

        for item in self.config.items('patterns'):
            add_patterns(item)
        return patterns

    @cached_property
    def files(self) -> list[str]:
        """
        A list of input sources. Each item can be a file path, a glob path or URL.
        """
        # If no files but a recursion option ==> use the current directory
        if not self.args.files and self.recursive:
            return ['.']
        else:
            return self.args.files

    @cached_property
    def filters(self) -> list[dict[str, RulePattern]]:
        logger.debug("get fields from arguments ...")
        if not self.args.filters:
            return []

        fields = self.config.options('fields')
        filters: list[dict[str, RulePattern]] = []

        default_patterns = self.default_patterns
        for flt_spec in self.args.filters:
            flt_patterns: dict[str, RulePattern] = {}
            for k, v in flt_spec.items():
                if k not in fields:
                    raise LogRaptorArgumentError('fields', f'undefined field {k!r}')
                try:
                    flt_patterns[k] = RulePattern(v, default_patterns)
                except (ValueError, TypeError) as err:
                    logger.error("filter %r: skip invalid pattern %r: %s", k, v, err)
            filters.append(flt_patterns)

        return filters

    @cached_property
    def matcher(self) -> str:
        """
        Matcher engine: ruled, unruled, unparsed.
        """
        if self.args.matcher is None:
            return 'ruled'
        elif self.args.matcher.startswith('-'):
            matcher = self.args.matcher.strip('-').replace('-', '_')
        else:
            matcher = self.args.matcher

        if matcher not in ('ruled', 'unruled', 'unparsed'):
            raise LogRaptorArgumentError('matcher', 'invalid argument matcher=%r' % matcher)
        return matcher

    @cached_property
    def hosts(self) -> Sequence[re.Pattern[str]]:
        """Returns a tuple with re.Pattern objects for matching the given --hosts option."""
        hosts: list[re.Pattern] = []
        for pattern in set(self.args.hosts or ['*']):
            hosts.append(re.compile(fnmatch.translate(pattern)))

            # If the pattern has a dotted local host part, add another pattern for local part.
            if '.' in pattern:
                local_hostname = pattern.split('.')[0]
                if local_hostname and '*' not in local_hostname:
                    hosts.append(re.compile(fnmatch.translate(local_hostname)))

        logger.debug('host patterns to be processed: %r', hosts)
        return tuple(hosts)

    @property
    def time_range(self) -> TimeRange | None:
        """
        Selected time range for log matching. A `None` value for time
        range means no time restriction (equivalent to 0:00-23:59).
        """
        return self.args.time_range

    @cached_property
    def time_period(self) -> tuple[datetime | None, datetime | None]:
        """
        Time period that is determined from the arguments --date and --last. It's a 2-tuple with
        (<start datetime>, <end_datetime>) items. An item is `None` if there isn't a limit.
        """
        time_period: tuple[datetime | None, datetime | None]

        if self.args.time_period is None:
            if self.args.files or self.interactive:
                time_period = (None, None)
            else:
                diff = 86400  # 24h = 86400 seconds
                time_period = get_datetime_interval(int(time.time()), diff, 3600)
        else:
            time_period = self.args.time_period

        logger.debug('time period to be processed: %r', time_period)
        return time_period

    @property
    def confdir(self) -> str:
        confdir = self.config.get('main', 'confdir')
        return normalize_path(confdir, base_path=os.path.dirname(self.config.cfgfile))

    @property
    def logdir(self) -> str:
        confdir = self.config.get('main', 'logdir')
        return normalize_path(confdir, base_path=os.path.dirname(self.config.cfgfile))

    @cached_property
    def encodings(self) -> tuple[str, ...]:
        """Logfile encodings, usually 'utf_8', 'latin1' or 'latin2'"""
        return tuple(self.config.get('main', 'encodings').split(',')) or DEFAULT_ENCODINGS

    @cached_property
    def logmap(self):
        apps = sorted(self.apps.values(), key=lambda x: x.priority)
        if self.args.files:
            logmap = FileMap(self.time_period, recursive=self.recursive,
                             follow_symlinks=self.follow_symlinks,
                             include=self.include, exclude=self.exclude,
                             exclude_dir=self.exclude_dir)
            logmap.add(self.args.files, apps)
        elif self.interactive:
            # No files provided but input is from a tty pipe/redirection
            logmap = [(sys.stdin, apps)]
        else:
            # Build the LogMap instance adding the list of files from app config files
            logmap = FileMap(self.time_period, recursive=self.recursive,
                             follow_symlinks=self.follow_symlinks,
                             include=self.include, exclude=self.exclude,
                             exclude_dir=self.exclude_dir)

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

    @cached_property
    def channels(self) -> list[TermChannel | MailChannel | FileChannel]:
        """Output channels"""
        logger.debug("initialize output channels ...")
        channels = self.args.channels
        config_channels = [
            sec.rpartition('_')[0] for sec in self.config.sections(suffix='_channel')
        ]
        unknown = set(channels) - set(config_channels)
        if unknown:
            raise ValueError("undefined channel %r" % list(unknown))

        output_channels: list[TermChannel | MailChannel | FileChannel] = []
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

    @cached_property
    def name_cache(self) -> LookupCache | None:
        # Create a lookup cache when required by arguments
        if self.args.anonymize or self.args.uid_lookup or self.args.ip_lookup:
            return LookupCache.from_args(self.args, self.config)
        return None

    def __call__(self, dispatcher: DispatcherType | None = None,
                 parsers: Sequence[LogParser] | None = None) -> bool:
        """
        Log processing main routine. Iterate over the log files calling
        the processing internal routine for each file.
        """
        if dispatcher is None:
            dispatcher = self.create_dispatcher()
        matcher_engine = self.create_matcher(dispatcher, parsers=parsers)
        dispatcher.open()

        display_progress_bar = sys.stdout.isatty() and not dispatcher.has_channel('stdout')

        logger.info("starting log processor ...")
        files = []
        lines = matches = unknown = 0
        extra_tags: Counter[str] = Counter()
        first_event: float | None = None
        last_event: float | None = None

        if self.args.report and self.report is not None:
            self.report.cleanup()

        # Iter between log files. The iteration use the log files modified between the
        # initial and the final date, skipping the other files.
        for source, apps in self.logmap:
            if apps is not None:
                logger.info('process %r for apps %r', source, apps)
            else:
                if self.args.files:
                    logger.error("%s: No such file or directory", source)
                continue

            try:
                for encoding in self.encodings:
                    try:
                        result = matcher_engine(source, apps, encoding)
                    except UnicodeDecodeError:
                        if display_progress_bar:
                            print()
                        logger.error("decoding error using the %r codec, "
                                     "change encoding and reprocess.", encoding)
                        continue
                    break
                else:
                    logger.error("no valid decoder found for %r.", source)
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

        if not files and self.time_period[0] is not None:
            tp = self.time_period
            raise FileMissingError(f"no file in time period ({format_dt(tp[0]), format_dt(tp[1])})!")
        elif not lines:
            return False

        run_stats: dict[str, Any] = {
            'files': files,
            'first_event': None,
            'last_event': None,
            'matches': matches,
            'lines': lines,
            'unknown': unknown,
            'extra_tags': extra_tags,
        }

        try:
            if isinstance(first_event, float):
                run_stats['first_event'] = datetime.fromtimestamp(first_event)
            if isinstance(last_event, float):
                run_stats['last_event'] = datetime.fromtimestamp(last_event)
        except (TypeError, UnboundLocalError):
            pass

        if sys.stdout.isatty():
            sys.stdout.write('\n')
        if unknown > 0:
            logger.error('found %d lines with an unknown log format', unknown)
        if extra_tags:
            num_lines = sum(extra_tags.values())
            logger.warning('found %d unknown extra app tags', num_lines)
            logger.warning('unknown app tags: %r', dict(extra_tags))
            if sys.stdout.isatty():
                sys.stdout.write('\n')

        # If the final report is requested then purge all unmatched threads and set time stamps,
        # otherwise send final run summary if messages are not disabled.
        if matches > 0 and self.report:
            self.report.set_stats(run_stats)
            self.report.make(self.apps)
            formats = list(set([fmt for channel in self.channels for fmt in channel.formats]))
            report_parts = self.report.get_report_parts(self.apps, formats)
            dispatcher.send_report(report_parts)
        elif self.args.loglevel and not self.args.quiet:
            dispatcher.send_message(self.get_run_summary(run_stats))
        dispatcher.close()

        logger.info("matcher processed %d files.", len(files))
        return matches > 0

    def create_dispatcher(self) -> DispatcherType:
        """
        Return a dispatcher for configured channels.
        """
        before_context = max(self.args.before_context, self.args.context)
        after_context = max(self.args.after_context, self.args.context)

        if self.args.files_with_match is not None or \
                self.args.count or self.args.only_matching or self.args.quiet:
            # Sending of log lines disabled by arguments
            return UnbufferedDispatcher(self.channels)
        elif before_context == 0 and after_context == 0:
            # Don't need line buffering
            return UnbufferedDispatcher(self.channels)
        elif self.args.thread:
            return ThreadedDispatcher(self.channels, before_context, after_context)
        else:
            return LineBufferDispatcher(self.channels, before_context, after_context)

    def create_matcher(self, dispatcher: DispatcherType, parsers: Sequence[LogParser] | None = None):
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

    def get_config(self) -> str:
        """
        Return a formatted text with main configuration parameters.
        """
        # Create a dummy report object if necessary
        channels = [sect.rsplit('_')[0] for sect in self.config.sections(suffix='_channel')]
        channels.sort()
        disabled_apps = [app for app in self.config_apps.keys() if app not in self.apps]
        return ''.join([
            "\n--- %s configuration ---" % __package__,
            "\nConfiguration file: %s" % self.config.cfgfile,
            "\nConfiguration directory: %s" % self.confdir,
            "\nConfigured applications: %s" % ', '.join(self.config_apps.keys()),
            "\nDisabled applications: %s" % ', '.join(disabled_apps) if disabled_apps else '',
            "\nFilter fields: %s" % ', '.join(self.config.options('fields')),
            "\nOutput channels: %s" % ', '.join(channels) if channels else 'No channels defined',
            "\nReports: %s\n" % ', '.join(
                [section[:-7] for section in self.config.sections(suffix='_report')]
            ),
            ''
        ])

    def get_run_summary(self, run_stats: dict[str, Any]) -> str:
        """
        Produce a text summary from run statistics.

        :param run_stats: A dictionary containing run stats
        :return: Formatted multiline string
        """
        run_stats = run_stats.copy()
        run_stats['files'] = len(run_stats['files'])
        summary = [
            '\n--- %s run summary ---' % __package__,
            'Number of processed files: %(files)d',
            'Total lines read: %(lines)d',
            'Total log events matched: %(matches)d',
        ]
        if any([app.matches or app.unparsed for app in self.apps.values()]):
            if self.matcher == 'unruled':
                summary.append("Applications found (application rules not used):")
                for app in filter(lambda x: x.matches, self.apps.values()):
                    summary.append('  %s(matches=%d)' % (app.name, app.matches))
            else:
                summary.append("Applications found:")
                for app in filter(lambda x: x.matches or x.unparsed, self.apps.values()):
                    summary.append(
                        '  %s(matches=%d, unparsed=%s)' % (app.name, app.matches, app.unparsed)
                    )
        summary.append('\n')
        return '\n'.join(summary) % run_stats
