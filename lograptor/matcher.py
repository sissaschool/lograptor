# -*- coding: utf-8 -*-
"""
This module define the matcher engine of lograptor package.
"""
#
# Copyright (C), 2011-2017, by SISSA - International School for Advanced Studies.
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
import logging

from .logparsers import CycleParsers
from .utils import dummy, build_dispatcher
from .cache import LineCache, ThreadsCache

logger = logging.getLogger(__name__)


# Map for month field from any admitted representation to numeric.
MONTHMAP = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04', 'May': '05', 'Jun': '06',
    'Jul': '07', 'Aug': '08', 'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12',
    '01': '01', '02': '02', '03': '03', '04': '04', '05': '05', '06': '06',
    '07': '07', '08': '08', '09': '09', '10': '10', '11': '11', '12': '12'
}


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


def get_app(log_data, tagmap, extra_tags):
    apptag = getattr(log_data, 'apptag', None)
    if apptag is not None:
        # Find app using the app-tag
        try:
            tag_apps = tagmap[apptag]
        except KeyError:
            tag_apps = [
                app for tag, _apps in tagmap.items() if apptag.startswith(tag)
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
                rule_match, full_match, app_thread, map_dict = app.process(log_data)
                if rule_match:
                    return app


def multiple_search(line, patterns, invert=False):
    if not patterns:
        return not invert, None

    for regexp in patterns:
        match = regexp.search(line)
        if match is not None:
            if invert:
                return False, match
            else:
                return True, match
    else:
        return invert, None


def create_matcher_engine(obj, parsers):
    """
    Return a tailored matcher engine for log files.

    :param obj: The lograptor instance.
    :return: The matcher function.
    """

    parsers = CycleParsers(parsers)
    name_cache = obj.name_cache
    tags = obj.tags
    max_count = 1 if obj.args.quiet else obj.args.max_count
    use_rules = obj.matcher != 'unruled'
    hosts = obj.hosts
    if hosts:
        hostset = set()
    patterns = obj.patterns
    thread = obj.args.thread
    invert = obj.args.invert
    files_with_match = obj.args.files_with_match
    count = obj.args.count
    unparsed = obj.matcher == 'unparsed'
    time_range = obj.args.time_range
    only_matching = obj.args.only_matching
    register_log_lines = not (obj.args.quiet or obj.args.count or obj.args.files_with_match is not None)
    initial_dt = time.mktime(obj.time_range[0].timetuple()) if obj.time_range[0] is not None else float(0)
    final_dt = time.mktime(obj.time_range[1].timetuple() if obj.time_range[1] else (2222, 2, 2, 0, 0, 0, 0, 0, 0))

    # Define functions for processing of the context.
    before_context = max(obj.args.before_context, obj.args.context)
    after_context = max(obj.args.after_context, obj.args.context)
    if not register_log_lines or not (before_context + after_context) or only_matching:
        register_selected = build_dispatcher(obj.channels, 'send_selected')
        register_context = context_reset = dummy
    else:
        if thread:
            context_cache = ThreadsCache(obj.channels, before_context, after_context)
        else:
            context_cache = LineCache(obj.channels, before_context, after_context)
        register_selected = context_cache.register_selected
        register_context = context_cache.register_context
        context_reset = context_cache.reset

    def process_logfile(path_or_file, applist):
        first_event = None
        last_event = None
        app_thread = None
        prev_data = None
        log_parser = next(parsers)

        matching_counter = 0
        unparsed_counter = 0
        extra_tags = set()
        context_reset()

        try:
            _logfile = open(path_or_file)
        except TypeError:
            _logfile = path_or_file

        with _logfile as logfile:
            ###
            # Set counters and status
            logfile_name = logfile.name
            line_counter = 0
            file_app = applist[0] if len(applist) == 1 else None

            fstat = os.fstat(logfile.fileno())
            file_mtime = datetime.datetime.fromtimestamp(fstat.st_mtime)
            file_year = file_mtime.year
            file_month = file_mtime.month
            prev_year = file_year - 1

            for line in logfile:
                line_counter += 1

                ###
                # Parses the log line. If the parser doesn't match the log format
                # then try another available parser. If any the change the active parser.
                log_match = log_parser.match(line)
                if log_match is None:
                    next_parser, log_match = parsers.detect(line)
                    if log_match is not None:
                        log_parser = next_parser
                    else:
                        unparsed_counter += 1
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
                        if use_rules:
                            app = log_parser.app or get_app(prev_data, tags, extra_tags) or file_app
                            app.increase_last(repeat)
                            app.counter += 1
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
                if event_time is None or event_time < initial_dt:
                    continue

                # Skip the rest of the file if the event is newer than the final datetime
                if event_time > final_dt:
                    if fstat.st_mtime < event_time:
                        logger.error("found anomaly with mtime of file %r at line %d", logfile_name, line_counter)
                    logger.warning("newer event at line %d: skip the rest of the file %r", line_counter, logfile_name)
                    break

                # Skip the lines not in timerange (if the option is provided).
                if time_range is not None and not time_range.between(log_data.ltime):
                    continue

                ###
                # Check the hostname with the related optional argument. If the log line
                # format don't include host information considers the line as matched.
                if hosts:
                    hostname = getattr(log_data, 'host', None)
                    if hostname and hostname not in hostset:
                        for host_pattern in hosts:
                            if host_pattern.search(hostname) is not None:
                                hostset.add(hostname)
                                break
                        else:
                            continue

                ###
                # Process the message part of the log with provided not-empty pattern(s).
                # Skip log lines that not match any pattern.
                pattern_matched, match = multiple_search(line, patterns, invert)
                if not pattern_matched and not thread:
                    register_context(filename=logfile_name, line_number=line_counter, rawlog=line)
                    continue

                ###
                # Get the app from parser or from the app-tag extracted from the log line.
                app = log_parser.app or get_app(log_data, tags, extra_tags) or file_app
                if app is None:
                    continue

                ###
                # Parse the log message with app's rules
                if use_rules and (pattern_matched or thread):
                    rule_match, full_match, app_thread, map_dict = app.process(log_data)
                    if not pattern_matched and rule_match and app_thread is None:
                        continue
                    if map_dict:
                        line = name_cache.match_to_string(log_match, log_parser.parser.groupindex, map_dict)
                    if (not (rule_match ^ unparsed)) or (rule_match and not full_match and app.has_filters):
                        register_context(
                            key=(app, app_thread),
                            filename=logfile_name,
                            line_number=line_counter,
                            rawlog=line
                        )
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
                    if max_count and matching_counter >= max_count:
                        # Stops iteration if max_count matchings is exceeded
                        break
                    matching_counter += 1
                    app.counter += 1
                    if files_with_match:
                        break
                    if register_log_lines:
                        register_selected(
                            key=(app, app_thread),
                            filename=logfile_name,
                            line_number=line_counter,
                            log_data=log_data,
                            rawlog='%s\n' % match.group(1) if only_matching and match else line,
                            match=match
                        )
                elif register_log_lines and not only_matching:
                    register_context(
                        key=(app, app_thread),
                        filename=logfile_name,
                        line_number=line_counter,
                        rawlog=line
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

        return line_counter, matching_counter, unparsed_counter, extra_tags, first_event, last_event

    return process_logfile
