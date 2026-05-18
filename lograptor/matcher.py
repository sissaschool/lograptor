"""
This module define the matcher engine of lograptor package.
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
import sys
import os
import re
import time
import logging
from collections import namedtuple, Counter
from collections.abc import Iterable, Sequence, Callable
from datetime import datetime
from types import MappingProxyType

from lograptor.application import AppLogParser
from lograptor.cache import LookupCache
from lograptor.dispatchers import DispatcherType, ThreadedDispatcher
from lograptor.logparsers import CycleParsers, LogData, LogParser
from lograptor.timedate import TimeRange
from lograptor.tui import ProgressBar
from lograptor.utils import open_resource

logger = logging.getLogger(__name__)


# Map for month field from any admitted representation to numeric.
MONTHMAP = MappingProxyType({
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04', 'May': '05', 'Jun': '06',
    'Jul': '07', 'Aug': '08', 'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12',
    '01': '01', '02': '02', '03': '03', '04': '04', '05': '05', '06': '06',
    '07': '07', '08': '08', '09': '09', '10': '10', '11': '11', '12': '12'
})

NILVALUE = '-'  # RFC-5424 NILVALUE


class MatcherResult(namedtuple('MatcherResult',
                               "lines matches unknown extra_tags first_event, last_event")):
    lines: int
    matches: int
    unknown: int
    extra_tags: Counter[str]
    first_event: float | None
    last_event: float | None


def get_mktime(year: str, month: str, day: str, ltime) -> float | None:
    try:
        return time.mktime((
            int(year),
            int(MONTHMAP[month]),
            int(day),
            int(ltime[:2]),     # Hour
            int(ltime[3:5]),    # Minute
            int(ltime[6:]),     # Second
            0, 0, -1
        ))
    except (KeyError, ValueError):
        return None


def get_mktime_period(time_period: tuple[datetime | None, datetime | None]) -> tuple[float, float]:
    """Convert a """
    if time_period[0] is None:
        start_dt = 0.0
    else:
        start_dt = time.mktime(time_period[0].timetuple())

    if time_period[1] is None:
        return start_dt, time.mktime((2222, 2, 2, 0, 0, 0, 0, 0, 0))
    else:
        return start_dt, time.mktime(time_period[1].timetuple())


def get_app(log_data: LogData,
            apps: list['AppLogParser'],
            tags: dict[str, list[AppLogParser]],
            extra_tags: Counter[str]) -> AppLogParser | None:
    """
    Selects the application for log data matching.

    :param log_data: log data regex match.
    :param apps: the list of loaded applications.
    :param tags: dictionary with a map from app-tags to application.
    :param extra_tags: a counter map for unknown app-tags.
    :return: an application instance if a match is found, `None` otherwise.
    """
    apptag = getattr(log_data, 'apptag', None)
    if apptag is None or apptag == NILVALUE or apptag.isdigit():
        # The app-tag is missing or has not a significative value
        for app in apps:
            if app.match_rules(log_data)[0]:
                return app
        return None

    # Find app using the app-tag
    try:
        tag_apps = tags[apptag]
    except KeyError:
        tag_apps = [
            app for tag, _apps in tags.items() if apptag.startswith(tag)
            for app in _apps
        ]

    if not tag_apps:
        # Tag unmatched, skip the line
        extra_tags.update([apptag])
        return None
    elif len(tag_apps) == 1:
        return tag_apps[0]
    else:
        # Match the tag using app's rules
        for app in tag_apps:
            if app.match_rules(log_data)[0]:
                return app
        else:
            # Return the first app (the line will be registered as unparsed)
            return tag_apps[0]


def create_host_matcher(hosts: Iterable[re.Pattern[str]]) -> Callable[[LogData], bool]:
    """
    Create a matcher for hostname patterns. If the log line data
    doesn't include host information considers the line as matched.
    The matcher has a cache for speed-up matching.
    """
    def has_host_match(log_data: LogData) -> bool:
        try:
            hostname = log_data.host
        except AttributeError:
            return True
        else:
            if hostname in host_cache:
                return True

        for host_pattern in hosts:
            if host_pattern.search(hostname) is not None:
                host_cache.add(hostname)
                return True
        else:
            return False

    host_cache = {None, ''}
    return has_host_match


##
# Pattern search functions

def inverted_pattern_search(line: str, patterns: Sequence[re.Pattern[str]]) \
        -> tuple[bool, re.Match[str] | None, str]:
    if not patterns:
        return False, None, line

    for regexp in patterns:
        match = regexp.search(line)
        if match is not None:
            return False, match, line
    else:
        return True, None, line


def matching_pattern_search(line: str, patterns: Sequence[re.Pattern[str]]) \
        -> tuple[bool, re.Match[str] | None, str]:
    if not patterns:
        return True, None, line

    for regexp in patterns:
        match = regexp.search(line)
        if match is not None:
            return True, match, '%s\n' % match.group(1)
    else:
        return False, None, line


def normal_pattern_search(line: str, patterns: Sequence[re.Pattern[str]]) \
        -> tuple[bool, re.Match[str] | None, str]:
    if not patterns:
        return True, None, line

    for regexp in patterns:
        match = regexp.search(line)
        if match is not None:
            return True, match, line
    else:
        return False, None, line


def create_matcher(dispatcher: DispatcherType,
                   parsers: Sequence[LogParser] | None,
                   apptags: dict[str, list[AppLogParser]],
                   matcher: str = 'ruled',
                   patterns: Sequence[re.Pattern[str]] = (),
                   hosts: Sequence[re.Pattern[str]] = (),
                   time_range: TimeRange | None = None,
                   time_period: tuple[datetime | None, datetime | None] = (None, None),
                   invert: bool = False,
                   count: bool = False,
                   files_with_match: bool | None = None,
                   max_count: int = 0,
                   only_matching: bool = False,
                   quiet: bool = False,
                   thread: bool = False,
                   name_cache: LookupCache | None = None):
    """
    Create a matcher engine.
    :return: A matcher function.
    """
    cyclic_parser_selector = CycleParsers(parsers)
    max_matches = 1 if quiet else max_count
    use_app_rules = matcher != 'unruled'
    select_unparsed = matcher == 'unparsed'
    register_log_lines = not (quiet or count or files_with_match is not None)

    start_dt, end_dt = get_mktime_period(time_period)
    has_host_match = create_host_matcher(hosts)

    if invert:
        pattern_search = inverted_pattern_search
    elif only_matching:
        pattern_search = matching_pattern_search
    else:
        pattern_search = normal_pattern_search

    dispatch_selected = dispatcher.dispatch_selected
    dispatch_context = dispatcher.dispatch_context
    display_progress_bar = sys.stdout.isatty() and not dispatcher.has_channel('stdout')

    def process_logfile(source: str, apps: list[AppLogParser], encoding='utf-8'):
        log_parser = next(cyclic_parser_selector)  # type: ignore[call-overload]
        first_event: float | None = None
        last_event: float | None = None
        app_thread = None
        selected_data = None
        line_counter: int = 0
        unknown_counter: int = 0
        selected_counter: int = 0
        extra_tags = Counter[str]()
        dispatcher.reset()
        read_size: int = 0
        progress_bar: ProgressBar | None = None

        with open_resource(source) as logfile:
            # Set counters and status
            logfile_name = logfile.name

            fstat = os.fstat(logfile.fileno())
            file_mtime = datetime.fromtimestamp(fstat.st_mtime)
            file_year = file_mtime.year
            file_month = file_mtime.month
            prev_year = file_year - 1

            if display_progress_bar:
                read_size = 0
                progress_bar = ProgressBar(sys.stdout, fstat.st_size, logfile_name)

            for line in logfile:
                line = line.decode(encoding)
                line_counter += 1
                if line[-1] != '\n':
                    line += '\n'

                if progress_bar is not None:
                    read_size += len(line)
                    if not line_counter % 100:
                        progress_bar.redraw(read_size)

                ###
                # Parses the line and extracts the log data
                log_match = log_parser.match(line)
                if log_match is None:
                    # The current parser doesn't match: try another available parser.
                    next_parser, log_match = cyclic_parser_selector.detect(line)
                    if log_match is not None:
                        log_parser = next_parser
                    elif line_counter == 1:
                        logger.error("the file %r has an unknown format, skip ...", logfile_name)
                        break
                    else:
                        unknown_counter += 1
                        continue
                log_data = log_parser.get_data(log_match)

                ###
                # Process last event repetition (e.g. 'last message repeated N times')
                if getattr(log_data, 'repeat', None) is not None:
                    if selected_data is not None:
                        repeat = int(log_data.repeat)
                        if not thread:
                            selected_counter += repeat
                        if use_app_rules:
                            app = log_parser.app or \
                                get_app(selected_data, apps, apptags, extra_tags)
                            assert app is not None, "app is None"
                            app.increase_last(repeat)
                            app.matches += 1
                            dispatch_context(
                                key=(app, app_thread),
                                filename=logfile_name,
                                line_number=line_counter,
                                rawlog=line
                            )
                        selected_data = None
                    continue
                selected_data = None

                ###
                # Parse the log's timestamp and gets the event datetime
                year = getattr(
                    log_data, 'year',
                    prev_year if MONTHMAP[log_data.month] != '01' and file_month == 1 else file_year
                )
                event_dt = get_mktime(
                    year=str(year),
                    month=log_data.month,
                    day=log_data.day,
                    ltime=log_data.ltime
                )

                ###
                # Scope exclusions
                if event_dt is None or event_dt < start_dt:
                    # Excludes lines older than the start datetime
                    continue
                elif event_dt > end_dt:
                    # Excludes lines newer than the end datetime
                    if fstat.st_mtime < event_dt:
                        logger.error("found anomaly with mtime of file %r at line %d",
                                     logfile_name, line_counter)
                    logger.warning("newer event at line %d: skip the rest of the file %r",
                                   line_counter, logfile_name)
                    break
                elif time_range is not None and not time_range.between(log_data.ltime):
                    # Excludes lines not in time range
                    continue
                elif hosts and not has_host_match(log_data):
                    # Excludes lines with host restriction
                    continue

                ###
                # Search log line with provided not-empty pattern(s)
                pattern_matched, match, rawlog = pattern_search(line, patterns)
                if not pattern_matched and not thread:
                    dispatch_context(filename=logfile_name, line_number=line_counter, rawlog=rawlog)
                    continue

                ###
                # App parsing: get the app from parser or from the log data
                app = log_parser.app or get_app(log_data, apps, apptags, extra_tags)
                if app is None:
                    # Unmatchable tag --> skip the line
                    continue
                elif use_app_rules:
                    # Parse the log message with app's rules
                    app_matched, full_match, app_thread, output_data = app.match_rules(log_data)
                    if not pattern_matched and app_matched and app_thread is None:
                        continue
                    if output_data and name_cache is not None:
                        rawlog = name_cache.match_to_string(
                            log_match, log_parser.parser.groupindex, output_data
                        )
                    if app_matched:
                        app.matches += 1
                        if not full_match or select_unparsed:
                            dispatch_context(
                                key=(app, app_thread),
                                filename=logfile_name,
                                line_number=line_counter,
                                rawlog=rawlog
                            )
                            continue
                    else:
                        app.unparsed += 1
                        if not select_unparsed:
                            dispatch_context(
                                key=(app, app_thread),
                                filename=logfile_name,
                                line_number=line_counter,
                                rawlog=rawlog
                            )
                            continue

                ###
                # Event selected: register event's data and datetime
                selected_data = log_data

                if first_event is None:
                    first_event = event_dt
                    last_event = event_dt
                else:
                    if first_event > event_dt:
                        first_event = event_dt
                    if last_event is not None and last_event < event_dt:
                        last_event = event_dt

                if pattern_matched:
                    if max_matches and selected_counter >= max_matches:
                        # Stops iteration if max_count matches is exceeded
                        break
                    selected_counter += 1
                    if files_with_match:
                        break
                    if register_log_lines:
                        dispatch_selected(
                            key=(app, app_thread),
                            filename=logfile_name,
                            line_number=line_counter,
                            log_data=log_data,
                            rawlog=rawlog,
                            match=match
                        )
                elif register_log_lines and not only_matching:
                    # Thread matching
                    dispatch_context(
                        key=(app, app_thread),
                        filename=logfile_name,
                        line_number=line_counter,
                        rawlog=rawlog
                    )

            if progress_bar is not None:
                progress_bar.redraw(fstat.st_size)

        if isinstance(dispatcher, ThreadedDispatcher):
            try:
                for key in dispatcher:
                    dispatcher.flush(key)
            except (NameError, AttributeError):
                pass

        # If the count option is enabled, register only the number of matched lines.
        if files_with_match is not None and not files_with_match ^ selected_counter:
            dispatch_selected(filename=logfile.name)
        elif count:
            dispatch_selected(filename=logfile.name, counter=selected_counter)

        return MatcherResult(
            lines=line_counter,
            matches=selected_counter,
            unknown=unknown_counter,
            extra_tags=extra_tags,
            first_event=first_event,
            last_event=last_event
        )

    return process_logfile
