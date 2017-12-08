#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Command line interface of the lograptor package.
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
import sys
import argparse
import time
import re
import sre_constants

from .core import LogRaptor
from .info import __version__, __description__
from .exceptions import (
    LogRaptorConfigError, LogRaptorOptionError, LogFormatError, FileMissingError,
    FileAccessError, LogRaptorArgumentError
)
from .timedate import get_datetime_interval, parse_date_period, parse_last_period, TimeRange


class StoreOptionAction(argparse.Action):
    """
    An action that stores the max length option as value, useful when
    a selection between more conflicting options is needed.
    """
    def __init__(self, option_strings, dest, required=False, help=None, metavar=None):
        const = sorted(option_strings, key=lambda x: len(x))[-1]
        super(StoreOptionAction, self).__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=0,
            const=const,
            default=None,
            type=str,
            required=required,
            help=help,
            metavar=metavar,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        value = getattr(namespace, self.dest, None)
        if value != self.default and value != self.const:
            raise argparse.ArgumentError(self, "conflict with option %s" % value)
        setattr(namespace, self.dest, self.const)


def positive_integer(string):
    value = int(string)
    if value <= 0:
        msg = "%r is not a positive integer" % string
        raise argparse.ArgumentTypeError(msg)
    return value


def filter_spec(string):
    _filter = dict()
    for flt in string.split(','):
        try:
            field, pattern = flt.split('=', 1)
            field, pattern = field.lower(), pattern.strip('\'"')
            if not field:
                raise argparse.ArgumentTypeError('filter %r: empty field name!' % flt)
            elif not pattern:
                raise argparse.ArgumentTypeError('filter %r: empty pattern!' % flt)

            try:
                re.compile(pattern)
                _filter[field] = pattern
            except sre_constants.error:
                raise argparse.ArgumentTypeError("wrong regex pattern in filter %r" % flt)
        except ValueError:
            raise argparse.ArgumentTypeError('filter %r: wrong format!' % flt)
    return _filter


def comma_separated_string(string):
    return [x.strip() for x in string.split(',')]


def last_period_spec(string):
    try:
        diff = parse_last_period(string)
    except TypeError:
        raise argparse.ArgumentTypeError('wrong format: %r' % string)
    else:
        return get_datetime_interval(int(time.time()), diff, 3600)


def date_interval_spec(string):
    try:
        return parse_date_period(string)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError('%r: wrong format, use [YYYY]MMDD[,[YYYY]MMDD]' % string)


def create_argument_parser():
    """
    Command line options and arguments parsing. This function return
    a list of options and the list of arguments (pattern, filenames).
    """
    parser = argparse.ArgumentParser(prog='lograptor', description=__description__, add_help=False)
    parser.usage = """%(prog)s [options] PATTERN [FILE ...]
    %(prog)s [options] [-e PATTERN | -f FILE] [FILE ...]
    Try '%(prog)s --help' for more information."""

    group = parser.add_argument_group("General Options")
    group.add_argument(
        "--conf", dest="cfgfiles", action='append', default=None, metavar="FILE",
        help="use a specific configuration file"
    )
    group.add_argument(
        "-d", dest="loglevel", default=2, type=int, metavar="[0-4]", choices=range(5),
        help="Logging level (default is 2, use 4 for debug). A level of 0 suppress also "
             "error messages about nonexistent or unreadable files."
    )
    group.add_argument('-V', '--version', action='version', version=__version__)
    group.add_argument('--help', action='help', help="show this help message and exit")

    group = parser.add_argument_group("Scope Selection")
    group.add_argument(
        "-a", "--apps", metavar='APP[,APP...]', type=comma_separated_string,
        default=[], help="process the log lines related to a list of applications"
    )
    group.add_argument(
        "--hosts", metavar="HOSTNAME/IP[,HOSTNAME/IP...]", type=comma_separated_string,
        default=[], help="process the log lines related to an hostname/IP"
    )
    group.add_argument(
        "-F", "--filter", metavar="FIELD=PATTERN[,FIELD=PATTERN...]",
        action="append", dest="filters", type=filter_spec, default=[],
        help="process the log lines that match all the conditions for rule's field values"
    )
    group.add_argument(
        "--time", metavar="HH:MM,HH:MM", type=TimeRange, action="store", dest="time_range",
        help="process the log lines related to a time range"
    )
    group.add_argument(
        "--date", metavar="[YYYY]MMDD[,[YYYY]MMDD]", action="store", dest="time_period",
        type=date_interval_spec, help="restrict the search scope to a date or a date interval"
    )
    group.add_argument(
        "--last", action="store", dest="time_period", type=last_period_spec,
        metavar="[hour|day|week|month|Nh|Nd|Nw|Nm]",
        help="restrict the search scope to a previous time period"
    )

    group = parser.add_argument_group("Matcher Selection")
    group.add_argument(
        "-G", "--ruled", dest='matcher', action=StoreOptionAction,
        help="use patterns and application rules (default)"
    )
    group.add_argument(
        "-X", "--unruled", dest='matcher', action=StoreOptionAction,
        help="use patterns only, skip application rules"
    )
    group.add_argument(
        "-U", "--unparsed", dest='matcher', action=StoreOptionAction,
        help="match the patterns, don't match any application rule"
    )

    group = parser.add_argument_group("Matching Control")
    group.add_argument(
        "-e", "--regexp", metavar="PATTERN", dest="patterns", default=[],
        action="append", help="use PATTERN for matching"
    )
    group.add_argument(
        "-f", "--file", metavar="FILE", dest="pattern_files", default=[],
        action="append", help="obtain patterns from FILE"
    )
    group.add_argument(
        "-i", "--ignore-case", action="store_true", dest="case", default=False,
        help="ignore case distinctions"
    )
    group.add_argument(
        "-v", "--invert-match", action="store_true", dest="invert", default=False,
        help="invert the sense of patterns regexp matching"
    )
    group.add_argument(
        "-w", "--word-regexp", action="store_true", dest="word", default=False,
        help="force PATTERN to match only whole words"
    )

    group = parser.add_argument_group("General Output Control")
    group.add_argument(
        "--output", default=['stdout'], metavar='CHANNEL[,CHANNEL...]', dest='channels',
        type=comma_separated_string, help="send output to channels (default: ['stdout'])"
    )
    group.add_argument(
        "-c", "--count", action="store_true", default=False,
        help="print only a count of matching lines per FILE"
    )
    group.add_argument(
        "--color", default='auto', nargs='?', choices=['auto', 'always', 'never'],
        help="use markers to highlight the matching strings"
    )
    group.add_argument(
        "-L", "--files-without-match", action="store_false", dest="files_with_match", default=None,
        help="print only names of FILEs containing no match"
    )
    group.add_argument(
        "-l", "--files-with-match", action="store_true", dest="files_with_match",
        help="print only names of FILEs containing matches"
    )
    group.add_argument(
        "-m", "--max-count", metavar='NUM', action="store", type=positive_integer, default=0,
        help="stop after NUM matches"
    )
    group.add_argument(
        "-o", "--only-matching", action="store_true", default=False,
        help="show only the part of a line matching PATTERN"
    )
    group.add_argument(
        "-q", "--quiet", action="store_true", default=False, help="suppress all normal output"
    )
    group.add_argument(
        "-s", "--no-messages", action="store_const", const=0, dest='loglevel',
        help="suppress error messages (equivalent to -d 0)"
    )

    group = parser.add_argument_group("Output Data Control")
    group.add_argument(
        "--report", metavar='NAME', nargs='?', default=False,
        help="produce a report at the end of processing"
    )
    group.add_argument(
        "--ip-lookup", action="store_true", default=False,
        help="translate IP addresses to DNS names"
    )
    group.add_argument(
        "--uid-lookup", action="store_true", default=False,
        help="translate UIDs to usernames"
    )
    group.add_argument(
        "--anonymize", action="store_true", default=False,
        help="anonymize defined rule's fields value"
    )

    group = parser.add_argument_group("Output Line Prefix Control")
    group.add_argument(
        "-n", "--line-number", action="store_true", default=False,
        help="print line number with output lines"
    )
    group.add_argument(
        "-H", "--with-filename", action="store_true", dest="with_filename", default=None,
        help="print the file name for each match"
    )
    group.add_argument(
        "-h", "--no-filename", action="store_false", dest="with_filename", default=None,
        help="suppress the file name prefix on output"
    )

    group = parser.add_argument_group("Context Line Control")
    group.add_argument(
        "-T", "--thread", action="store_true", default=False,
        help="the context is the log thread of the application"
    )
    group.add_argument(
        "-B", "--before-context", metavar='NUM', type=positive_integer, default=0,
        help="print NUM lines of leading context"
    )
    group.add_argument(
        "-A", "--after-context", metavar='NUM', type=positive_integer, default=0,
        help="print NUM lines of trailing context"
    )
    group.add_argument(
        "-C", "--context", metavar='NUM', type=positive_integer, default=0,
        help="print NUM lines of output context"
    )
    group.add_argument(
        "--group-separator", metavar='SEP', default='--',
        help="use SEP as a group separator. By default SEP is double hyphen (--)."
    )
    group.add_argument(
        "--no-group-separator", dest="group_separator", action="store_const", const='',
        help="use empty string as a group separator"
    )

    group = parser.add_argument_group("File and Directory Selection")
    group.add_argument(
        "-r", "--recursive", action="store_true", default=False,
        help="read all files under each directory, recursively"
    )
    group.add_argument(
        "-R", "--dereference-recursive", action="store_true", default=False,
        help="likewise, but follow all symlinks"
    )
    group.add_argument(
        "--include", metavar='GLOB', default=[], action="append",
        help="search only files that match GLOB"
    )
    group.add_argument(
        "--exclude", metavar='GLOB', default=[], action="append",
        help="skip files and directories matching GLOB"
    )
    group.add_argument(
        "--exclude-from", metavar='FILE', default=[], action="append",
        help="skip files matching any file pattern from FILE"
    )
    group.add_argument(
        "--exclude-dir", metavar='DIR', default=[], action="append",
        help="exclude directories matching the pattern DIR"
    )

    parser.add_argument(
        'files', metavar='[FILE ...]', nargs='*',
        help='Input files. Each argument can be a file path or a glob pathname. '
             'A "-" stands for standard input. If no arguments are given then processes '
             'all the files included within the scope of the selected applications.'
    )
    return parser


def has_void_args(argv):
    """
    Check if the command line has no arguments or only the --conf optional argument.
    """
    n_args = len(argv)
    return n_args == 1 or n_args == 2 and argv[1].startswith('--conf=') or n_args == 3 and argv[1] == '--conf'


def lograptor(files, patterns=None, matcher='ruled', cfgfiles=None, apps=None, hosts=None,
              filters=None, time_period=None, time_range=None, case=False, invert=False,
              word=False, files_with_match=None, count=False, quiet=False, max_count=0,
              only_matching=False, line_number=False, with_filename=None,
              ip_lookup=False, uid_lookup=False, anonymize=False, thread=False,
              before_context=0, after_context=0, context=0):
    """
    Run lograptor with arguments. Experimental feature to use the log processor into
    generic Python scripts. This part is still under development, do not use.

    :param files: Input files. Each argument can be a file path or a glob pathname.
    :param patterns: Regex patterns, select the log line if at least one pattern matches.
    :param matcher: Matcher engine, can be 'ruled' (default), 'unruled' or 'unparsed'.
    :param cfgfiles: use a specific configuration file.
    :param apps: process the log lines related to a list of applications.
    :param hosts: process the log lines related to a list of hosts.
    :param filters: process the log lines that match all the conditions for rule's field values.
    :param time_range: process the log lines related to a time range.
    :param time_period: restrict the search scope to a date or a date interval.
    :param case: ignore case distinctions, defaults to `False`.
    :param invert: invert the sense of patterns regexp matching.
    :param word: force PATTERN to match only whole words.
    :param files_with_match: get only names of FILEs containing matches, defaults is `False`.
    :param count: get only a count of matching lines per FILE.
    :param quiet: suppress all normal output.
    :param max_count: stop after NUM matches.
    :param only_matching: get only the part of a line matching PATTERN.
    :param line_number: get line number with output lines.
    :param with_filename: get or suppress the file name for each match.
    :param ip_lookup: translate IP addresses to DNS names.
    :param uid_lookup: translate numeric UIDs to usernames.
    :param anonymize: anonymize defined rule's fields value.
    :param thread: get the lines of logs related to each log line selected.
    :param before_context: get NUM lines of leading context for each log line selected.
    :param after_context: get NUM lines of trailing context for each log line selected.
    :param context: get NUM lines of output context for each log line selected.
    :return:
    """
    cli_parser = create_argument_parser()
    args = cli_parser.parse_args()
    args.files = files
    args.matcher = matcher
    args.cfgfiles = cfgfiles
    args.time_period = time_period
    args.time_range = time_range
    args.case = case
    args.invert = invert
    args.word = word
    args.files_with_match = files_with_match
    args.count = count
    args.quiet = quiet
    args.max_count = max_count
    args.only_matching = only_matching
    args.line_number = line_number
    args.with_filename = with_filename
    args.anonymize = anonymize
    args.ip_lookup = ip_lookup
    args.uid_lookup = uid_lookup
    args.thread = thread
    args.context = context
    args.after_context = after_context
    args.before_context = before_context
    args.patterns = [''] if patterns is None else patterns

    if apps is not None:
        args.apps = apps
    if hosts is not None:
        args.hosts = hosts
    if filters is not None:
        args.filters = filters

    _lograptor = LogRaptor(args)
    return _lograptor()


def main():
    if sys.version_info < (2, 7, 0):
        sys.stderr.write("You need python 2.7 or later to run this program\n")
        sys.exit(1)

    cli_parser = create_argument_parser()
    args = cli_parser.parse_args()

    try:
        if has_void_args(sys.argv) and 'stdout' in args.channels:
            # If the command is called with no relevant args (eg. no args
            # or only --conf argument) then prints the configuration and exit.
            args.patterns.append('')
            _lograptor = LogRaptor(args)
            print(_lograptor.get_config())
            sys.exit(0)

        _lograptor = LogRaptor(args)
        retval = _lograptor()
    except (LogRaptorArgumentError, LogRaptorOptionError, LogRaptorConfigError, LogFormatError,
            FileMissingError, FileAccessError) as err:
        if 'stdout' not in args.channels:
            sys.exit(u"ERROR: {0}\nExiting ...".format(err))
        elif str(err):
            cli_parser.error(err)
        else:
            cli_parser.print_usage()
            sys.exit(2)
    except KeyboardInterrupt:
        print("\nCtrl-C pressed, terminate the process ...")
        sys.exit(1)
    else:
        sys.exit(0 if retval else 1)


if __name__ == '__main__':
    main()
