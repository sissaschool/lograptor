# -*- coding: utf-8 -*-
"""
This module define the matcher engine of Lograptor package.
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
import logging
import sys

from .parsers import CycleParsers
from .tui import ProgressBar

logger = logging.getLogger(__name__)


# Cleans the thread caches every time you process a certain number of lines.
PURGE_THREADS_LIMIT = 1000


# Map for month field from any admitted representation to numeric.
MONTHMAP = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04', 'May': '05', 'Jun': '06',
    'Jul': '07', 'Aug': '08', 'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12',
    '01': '01', '02': '02', '03': '03', '04': '04', '05': '05', '06': '06',
    '07': '07', '08': '08', '09': '09', '10': '10', '11': '11', '12': '12'
}


def get_mktime(year, month, day, ltime):
    return time.mktime((
        int(year),
        int(MONTHMAP[month]),
        int(day),
        int(ltime[:2]),     # Hour
        int(ltime[3:5]),    # Minute
        int(ltime[6:]),     # Second
        0, 0, -1
    ))


def create_matcher_engine(obj, parsers):
    """
    Return a tailored matcher engine for log files.

    :param obj: The Lograptor instance.
    :return: The matcher function.
    """
    printline = obj.get_line_printer()
    if obj.print_filename:
        getline = obj._get_prefixed_line
    else:
        getline = obj._get_line

    # Load names to local variables to speed-up the run
    parsers = CycleParsers(parsers)
    name_cache = obj.name_cache
    outstatus = obj.print_status
    tagmap = obj.tagmap
    max_count = obj.args.max_count if not obj.args.quiet else 1
    apps = obj.apps
    rawfh = obj.rawfh
    use_rules = obj.args.use_rules
    hosts = obj.hosts
    patterns = obj.patterns
    thread = obj.args.thread
    print_lines = obj.print_lines
    invert = obj.args.invert
    count = obj.args.count
    match_unparsed = obj.args.unparsed
    make_report = obj.args.report is not None
    timerange = obj.args.timerange
    draw_progress_bar = outstatus and not obj._debug
    print_filename = obj.print_filename
    print_header = obj.print_status or obj.print_lines and print_filename is None

    initial_dt = time.mktime(obj.initial_dt.timetuple()) if obj.initial_dt else float(0)
    final_dt = time.mktime(obj.final_dt.timetuple() if obj.final_dt else (2222, 2, 2, 0 ,0, 0, 0, 0, 0))
    hostset = set()

    def process_logfile(filename, applist):
        first_event = None
        last_event = None
        log_parser = next(parsers)
        prev_data = None
        app = None
        app_thread = None

        matching_counter = 0
        unparsed_counter = 0

        readsize = 0
        progressbar = None
        pattern_search = False
        full_match = False
        extra_tags = set()

        with open(filename) as logfile:
            ###
            # Set counters and status
            file_app = applist[0] if len(applist) == 1 else None
            line_counter = 0
            if obj.print_filename:
                obj.prefix = logfile.name
            fstat = os.fstat(logfile.fileno())
            file_mtime = datetime.datetime.fromtimestamp(fstat.st_mtime)
            file_year = file_mtime.year
            file_month = file_mtime.month
            prev_year = file_year - 1
            if draw_progress_bar:
                progressbar = ProgressBar(sys.stdout, fstat.st_size, "lines parsed")

            if print_header:
                printline('\n*** Filename: {0} ***'.format(filename))

            for line in logfile:
                line_counter += 1
                if draw_progress_bar:
                    readsize += len(line)
                    progressbar.redraw(readsize, line_counter)

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
                            apptag = prev_data.apptag
                            try:
                                app = tagmap[apptag]
                            except KeyError as e:
                                # Try a partial match
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
                prev_data = log_data

                ###
                # Checks event time with selected scope.
                # Converts log's timestamp into the time in seconds since the epoch
                # as a floating point number, in order to speed up comparisons.
                event_time = get_mktime(
                    year=getattr(log_data, 'year', prev_year if log_data.month != '1' and file_month == 1 else file_year),
                    month=log_data.month,
                    day=log_data.day,
                    ltime=log_data.ltime
                )

                # Skip the lines older than the initial datetime
                if event_time < initial_dt:
                    prev_data = None
                    continue

                # Skip the rest of the file if the event is newer than the final datetime
                if event_time > final_dt:
                    if fstat.st_mtime < event_time:
                        logger.error('time inconsistency with the mtime of the file: %r', line[:-1])
                    logger.warning('Newer line, skip the rest of the file: %r', line[:-1])
                    break

                # Skip the lines not in timerange (if the option is provided).
                if timerange is not None and not timerange.between(log_data.ltime):
                    prev_data = None
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
                            prev_data = None
                            continue

                ###
                # Process the message part of the log with provided pattern(s).
                # Skip log lines that not match any pattern.
                pattern_search = True
                if patterns:
                    for regexp in patterns:
                        pattern_match = regexp.search(log_data.message)
                        if (pattern_match is not None and not invert) or \
                           (pattern_match is None and invert):
                            break
                    else:
                        if not thread:
                            prev_data = None
                            continue
                        pattern_search = False
                elif invert:
                    if not thread:
                        prev_data = None
                        continue
                    pattern_search = False

                ###
                # Get the app from parser or from the app-tag extracted from the log line.
                app = log_parser.app
                if app is None:
                    apptag = getattr(log_data, 'apptag', None)
                    if apptag is not None:
                        try:
                            tag_apps = tagmap[apptag]
                        except:
                            tag_apps = [app for app in tagmap for tag in tagmap if apptag.startswith(tag)]

                        if not apps:
                            # Tag unmatched, skip the line
                            extra_tags.add(apptag)
                            prev_data = None
                            continue
                        else:
                            app = tag_apps[0]
                    elif file_app:
                        app = file_app
                    else:
                        logger.error("unknown app for log: %r", line[:-1])
                        prev_data = None
                        continue

                app.counter += 1

                # Log message parsing with app's rules
                if use_rules and (pattern_search or thread):
                    rule_match, full_match, app_thread, map_dict = app.process(log_data)
                    if not rule_match:
                        # Log message unparsable by app rules
                        if not match_unparsed:
                            if pattern_search:
                                logger.debug('Unparsable line: %r', line[:-1])
                            prev_data = None
                            continue
                        if map_dict is not None:
                            line = name_cache.map2str(log_parser.parser.groupindex, log_match, map_dict)
                    elif match_unparsed:
                        # Log message parsed but match_unparsed option
                        prev_data = None
                        continue
                    elif app_thread is not None:
                        if map_dict is not None:
                            line = name_cache.map2str(
                                log_parser.parser.groupindexheader_gids, log_match, map_dict
                            )
                        app.cache.add_line(getline(line), app_thread,
                                           pattern_search, full_match, event_time)
                    elif not full_match and app.has_filters:
                        if pattern_search:
                            printline('Filtered line: %r', line[:-1])
                        prev_data = None
                        continue
                    elif map_dict is not None:
                        line = name_cache.map2str(
                            log_parser.parser.groupindex, log_match, map_dict
                        )

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
                    if (line_counter % PURGE_THREADS_LIMIT) == 0:
                        for app in applist:
                            apps[app].purge_threads(event_time)
                            max_threads = None if max_count is None else max_count - matching_counter
                            matching_counter += apps[app].cache.flush_old_cache(event_time, print_lines, max_threads)
                else:
                    matching_counter += 1
                    if print_lines:
                        printline(getline(line), end='')

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
                    apps[app].purge_threads(event_time)
                except UnboundLocalError:
                    break
                if max_count is not None and matching_counter >= max_count:
                    break
                max_threads = None if max_count is None else max_count - matching_counter
                matching_counter += apps[app].cache.flush_cache(event_time, print_lines, max_threads)

        # If count option is enabled then print the number of matched lines.
        if count:
            printline('%s: %d' % (filename, matching_counter))

        return line_counter, matching_counter, unparsed_counter, extra_tags, first_event, last_event

    return process_logfile
