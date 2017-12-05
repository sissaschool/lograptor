# -*- coding: utf-8 -*-
"""
This module define the matcher engine of lograptor package.
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
import logging
from collections import namedtuple

from .logparsers import CycleParsers
from .utils import dummy, build_dispatcher, open_resource
from .cache import LineCache, ThreadsCache

logger = logging.getLogger(__name__)


# Map for month field from any admitted representation to numeric.
MONTHMAP = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04', 'May': '05', 'Jun': '06',
    'Jul': '07', 'Aug': '08', 'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12',
    '01': '01', '02': '02', '03': '03', '04': '04', '05': '05', '06': '06',
    '07': '07', '08': '08', '09': '09', '10': '10', '11': '11', '12': '12'
}

MatcherResult = namedtuple(
    'MatcherResult', "lines matches unknown extra_tags unparsed first_event, last_event"
)


def get_mktime(year, month, day, ltime):
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


def get_mktime_period(time_period):
    try:
        start_dt = time.mktime(time_period[0].timetuple())
    except AttributeError:
        start_dt = float(0)
    try:
        return start_dt, time.mktime(time_period[1].timetuple())
    except AttributeError:
        return start_dt, time.mktime((2222, 2, 2, 0, 0, 0, 0, 0, 0))


def get_app(log_data, tags, extra_tags):
    apptag = getattr(log_data, 'apptag', None)
    if apptag is not None:
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
            extra_tags.add(apptag)
            return
        elif len(tag_apps) == 1:
            return tag_apps[0]
        else:
            # Match the tab using app's rules
            for app in tag_apps:
                rule_match, full_match, app_thread, map_dict = app.match_rules(log_data)
                if rule_match:
                    return app


def create_search_function(invert, only_matching):
    def inverted_pattern_search(line, patterns):
        if not patterns:
            return False, None, line

        for regexp in patterns:
            match = regexp.search(line)
            if match is not None:
                return False, match, line
        else:
            return True, None, line

    def matching_pattern_search(line, patterns):
        if not patterns:
            return True, None, line

        for regexp in patterns:
            match = regexp.search(line)
            if match is not None:
                return True, match, '%s\n' % match.group(1)
        else:
            return False, None, line

    def normal_pattern_search(line, patterns):
        if not patterns:
            return True, None, line

        for regexp in patterns:
            match = regexp.search(line)
            if match is not None:
                return True, match, line
        else:
            return False, None, line

    if invert:
        return inverted_pattern_search
    elif only_matching:
        return matching_pattern_search
    else:
        return normal_pattern_search


host_cache = set()

def has_host_match(log_data, hosts):
    """
    Match the data with a list of hostname patterns. If the log line data
    doesn't include host information considers the line as matched.
    """
    hostname = getattr(log_data, 'host', None)
    if hostname and hostname not in host_cache:
        for host_pattern in hosts:
            if host_pattern.search(hostname) is not None:
                host_cache.add(hostname)
                return True
        else:
            return False
    return True


def create_matcher(apptags, channels, matcher='ruled', parsers=None, hosts=tuple(), time_range=None,
                   time_period=(None, None), patterns=tuple(), invert=False, count=False,
                   files_with_match=None, max_count=0, only_matching=False, quiet=False,
                   thread=False, before_context=0, after_context=0, name_cache=None):
    """
    Create a matcher engine.
    :return: A matcher function.
    """
    parsers = CycleParsers(parsers)
    max_matches = 1 if quiet else max_count
    use_app_rules = matcher != 'unruled'
    unparsed = matcher == 'unparsed'
    register_log_lines = not (quiet or count or files_with_match is not None)
    start_dt, end_dt = get_mktime_period(time_period)
    pattern_search = create_search_function(invert, only_matching)

    # Define functions for processing of the context.
    if not register_log_lines or not (before_context + after_context) or only_matching:
        register_selected = build_dispatcher(channels, 'send_selected')
        register_context = context_reset = dummy
    else:
        if thread:
            context_cache = ThreadsCache(channels, before_context, after_context)
        else:
            context_cache = LineCache(channels, before_context, after_context)
        register_selected = context_cache.register_selected
        register_context = context_cache.register_context
        context_reset = context_cache.reset

    def process_logfile(source, apps):
        first_event = None
        last_event = None
        app_thread = None
        prev_data = None
        log_parser = next(parsers)
        source_app = apps[0] if len(apps) == 1 else None

        line_counter = 0
        unknown_counter = 0
        matching_counter = 0
        unparsed_counter = 0
        extra_tags = set()
        context_reset()

        with open_resource(source) as logfile:
            # Set counters and status
            logfile_name = logfile.name

            fstat = os.fstat(logfile.fileno())
            file_mtime = datetime.datetime.fromtimestamp(fstat.st_mtime)
            file_year = file_mtime.year
            file_month = file_mtime.month
            prev_year = file_year - 1

            for line in logfile:
                line_counter += 1
                if line[-1] != '\n':
                    line += '\n'

                ###
                # Parses the log line. If the parser doesn't match the log format
                # then try another available parser. If any the change the active parser.
                log_match = log_parser.match(line)
                if log_match is None:
                    next_parser, log_match = parsers.detect(line)
                    if log_match is not None:
                        log_parser = next_parser
                    else:
                        unknown_counter += 1
                        continue

                # Extract log data tuple from named matching groups
                log_data = log_parser.get_data(log_match)

                ###
                # Process last event repetition (eg. 'last message repeated N times' RFC 3164's logs)
                if getattr(log_data, 'repeat', None) is not None:
                    if prev_data is not None:
                        repeat = int(log_data.repeat)
                        if not thread:
                            matching_counter += repeat
                        if use_app_rules:
                            app = log_parser.app or get_app(prev_data, apptags, extra_tags) or source_app
                            app.increase_last(repeat)
                            app.matches += 1
                            register_context(
                                key=(app, app_thread),
                                filename=logfile_name,
                                line_number=line_counter,
                                rawlog=line
                            )
                        prev_data = None
                    continue
                else:
                    prev_data = None

                ###
                # Checks event time with selected scope.
                # Converts log's timestamp into the time in seconds since the epoch
                # as a floating point number, in order to speed up comparisons.
                year = getattr(
                    log_data, 'year',
                    prev_year if MONTHMAP[log_data.month] != '01' and file_month == 1 else file_year
                )
                event_time = get_mktime(
                    year=year,
                    month=log_data.month,
                    day=log_data.day,
                    ltime=log_data.ltime
                )

                # Skip errors and the lines older than the initial datetime
                if event_time is None or event_time < start_dt:
                    continue

                # Skip the rest of the file if the event is newer than the final datetime
                if event_time > end_dt:
                    if fstat.st_mtime < event_time:
                        logger.error("found anomaly with mtime of file %r at line %d", logfile_name, line_counter)
                    logger.warning("newer event at line %d: skip the rest of the file %r", line_counter, logfile_name)
                    break

                # Skip the lines not in time range
                if time_range is not None and not time_range.between(log_data.ltime):
                    continue

                if hosts and not has_host_match(log_data, hosts):
                    continue

                # Search log line with provided not-empty pattern(s)
                pattern_matched, match, rawlog = pattern_search(line, patterns)
                if not pattern_matched and not thread:
                    register_context(filename=logfile_name, line_number=line_counter, rawlog=rawlog)
                    continue

                ###
                # Get the app from parser or from the app-tag extracted from the log line.
                app = log_parser.app or get_app(log_data, apptags, extra_tags) or source_app
                if app is None:
                    # TODO: check the logparser class if the appname maybe None!!
                    continue

                ###
                # Parse the log message with app's rules
                if use_app_rules and (pattern_matched or thread):
                    app_matched, has_full_match, app_thread, map_dict = app.match_rules(log_data)
                    if not pattern_matched and app_matched and app_thread is None:
                        unparsed_counter += 1
                        continue
                    if map_dict:
                        line = name_cache.match_to_string(log_match, log_parser.parser.groupindex, map_dict)
                    if (not (app_matched ^ unparsed)) or (app_matched and not has_full_match and app.has_filters):
                        register_context(
                            key=(app, app_thread),
                            filename=logfile_name,
                            line_number=line_counter,
                            rawlog=rawlog
                        )
                        unparsed_counter += 1
                        continue

                ###
                # Event matched: register event's data and datetime
                prev_data = log_data

                if first_event is None:
                    first_event = event_time
                    last_event = event_time
                else:
                    if first_event > event_time:
                        first_event = event_time
                    if last_event < event_time:
                        last_event = event_time

                if pattern_matched:
                    if max_matches and matching_counter >= max_matches:
                        # Stops iteration if max_count matchings is exceeded
                        break
                    matching_counter += 1
                    app.matches += 1
                    if files_with_match:
                        break
                    if register_log_lines:
                        register_selected(
                            key=(app, app_thread),
                            filename=logfile_name,
                            line_number=line_counter,
                            log_data=log_data,
                            rawlog=rawlog,
                            match=match
                        )
                elif register_log_lines and not only_matching:
                    register_context(
                        key=(app, app_thread),
                        filename=logfile_name,
                        line_number=line_counter,
                        rawlog=rawlog
                    )

        try:
            for key in list(context_cache.keys()):
                context_cache.flush(key)
        except (NameError, AttributeError):
            pass

        # If count option is enabled then register only the number of matched lines.
        if files_with_match and matching_counter or files_with_match is False and not matching_counter:
            register_selected(filename=logfile.name)
        elif count:
            register_selected(filename=logfile.name, counter=matching_counter)

        return MatcherResult(
            lines=line_counter,
            matches=matching_counter,
            unknown=unknown_counter,
            extra_tags=extra_tags,
            unparsed=unparsed_counter,
            first_event=first_event,
            last_event=last_event
        )

    return process_logfile
