#!/usr/bin/env python
"""
Command line interface of the lograptor package.
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
import argparse
import time
import re
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Union, NamedTuple, Any

from lograptor.runner import LogRaptor
from lograptor.info import __version__, __description__
from lograptor.exceptions import (
    LogRaptorConfigError, LogRaptorOptionError, LogFormatError, FileMissingError,
    FileAccessError, LogRaptorArgumentError
)
from lograptor.timedate import get_datetime_interval, parse_date_period, \
    parse_last_period, TimeRange


# noinspection PyShadowingBuiltins
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


def positive_integer(arg: str) -> int:
    try:
        value = int(arg)
        if value <= 0:
            raise ValueError()
    except ValueError:
        msg = "%r is not a positive integer" % arg
        raise argparse.ArgumentTypeError(msg) from None
    else:
        return value


def filter_spec(arg: str) -> dict[str, str]:
    filters: dict[str, str] = {}

    for flt in arg.split(','):
        try:
            field, pattern = flt.split('=', 1)
            field, pattern = field.lower(), pattern.strip('\'"')
            if not field:
                raise argparse.ArgumentTypeError('filter %r: empty field name!' % flt)
            elif not pattern:
                raise argparse.ArgumentTypeError('filter %r: empty pattern!' % flt)

            try:
                re.compile(pattern)
                filters[field] = pattern
            except re.error:
                raise argparse.ArgumentTypeError("wrong regex pattern in filter %r" % flt)
        except ValueError:
            raise argparse.ArgumentTypeError('filter %r: wrong format!' % flt)
    return filters


def comma_separated_string(arg: str) -> list[str]:
    return [x.strip() for x in arg.split(',')]


def last_period_spec(arg: str) -> tuple[datetime, datetime]:
    try:
        diff = parse_last_period(arg)
    except ValueError:
        raise argparse.ArgumentTypeError('wrong format: %r' % arg)
    else:
        return get_datetime_interval(int(time.time()), diff, 3600)


def date_interval_spec(arg) -> tuple[datetime, datetime]:
    try:
        return parse_date_period(arg)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError('%r: wrong format, use [YYYY]MMDD[,[YYYY]MMDD]' % arg)


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Command line options and arguments parsing. This function returns
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
        action="append", help="use unnamed PATTERN for matching"
    )
    group.add_argument(
        "-f", "--file", metavar="FILE", dest="pattern_files", default=[],
        action="append", help="obtain patterns from FILE"
    )
    group.add_argument(
        "-i", "--ignore-case", action="store_true", default=False,
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
        help="skip files whose base name matches any of the file-name globs"
    )
    group.add_argument(
        "--exclude-from", metavar='FILE', default=[], action="append",
        help="skip files whose base name matches any of the file-name globs read from FILE"
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


class ActionInfo(NamedTuple):
    """Stores information about argparse actions, used to check command line arguments."""

    dest: str
    type: Callable[[Any], Any] | None = None
    default: Any = None
    required: bool = False
    choices: Union[Sequence[Any], dict[str, "ActionInfo"], None] = None

    @classmethod
    def from_action(cls, action: argparse.Action) -> "ActionInfo":
        kwargs = {
            "dest": action.dest,
            "type": action.type,
            "choices": action.choices,
            "default": action.default,
            "required": action.required,
        }
        if not isinstance(action.type, type) and action.const is not None:
            kwargs["type"] = type(action.const)
        if isinstance(action.choices, dict):
            kwargs["choices"] = {
                key: cls.from_parser(subparser)
                for key, subparser in action.choices.items()
                if isinstance(subparser, argparse.ArgumentParser)
            }
        return cls(**kwargs)

    @classmethod
    def from_parser(cls, parser: argparse.ArgumentParser) -> dict[str, "ActionInfo"]:
        """Extract parser actions returning a dictionary with info about actions."""
        actions = {}
        for key, obj in vars(parser).items():
            if isinstance(obj, (list, tuple)) and \
                    any(isinstance(item, argparse.Action) for item in obj):
                for item in obj:
                    if isinstance(item, argparse.Action):
                        if item.dest == "help":
                            continue
                        assert item.dest not in actions
                        actions[item.dest] = cls.from_action(item)
        return actions

    def verify(self, dest: str, value: Any) -> None:
        if dest != self.dest:
            raise ValueError(f"{dest!r} is not equal to {self.dest!r}")
        if isinstance(self.choices, dict):
            if not isinstance(value, str):
                raise TypeError(f"{value!r} is not an instance {str!r}")
            if value not in self.choices:
                raise ValueError(f"{value!r} is not a valid choice for {self.dest!r}")
            return
        elif value is None:
            if not self.required:
                return

        if isinstance(self.type, type) and not isinstance(value, self.type):
            raise TypeError(f"{value!r} is not an instance of {self.type!r}")
        if self.choices:
            if value not in self.choices:
                raise ValueError(f"{value!r} is not a valid choice for {self.dest!r}")
        if self.default is not None:
            if value == self.default:
                return


def has_void_args(argv):
    """
    Check if the command line has no arguments or only the --conf optional argument.
    """
    n_args = len(argv)
    return n_args == 1 or n_args == 2 and argv[1].startswith('--conf=') or \
        n_args == 3 and argv[1] == '--conf'


def lograptor(files: Sequence[str] = (), *,
              cfgfiles: Sequence[str] = (),
              apps: Sequence[str] = (),
              hosts: Sequence[str] = (),
              patterns: Sequence[str] = (),
              pattern_files: Sequence[str] = (),
              channels: Sequence[str] = ('stdout',),
              filters: dict[str, str] | None = None,
              time_period: tuple[datetime, datetime] | None = None,
              time_range: TimeRange | None = None,
              matcher: str = 'ruled',
              ignore_case: bool = False,
              invert: bool = False,
              word: bool = False,
              files_with_match: bool | None = None,
              count: bool = False,
              color: str = 'auto',
              quiet: bool = False,
              max_count: int = 0,
              only_matching: bool = False,
              line_number: bool = False,
              with_filename: bool | None = None,
              ip_lookup: bool = False,
              uid_lookup: bool = False,
              anonymize: bool = False,
              thread: bool = False,
              recursive: bool = False,
              dereference_recursive: bool = False,
              include: Sequence[str] = (),
              exclude: Sequence[str] = (),
              exclude_from: Sequence[str] = (),
              exclude_dir: Sequence[str] = (),
              before_context: int = 0,
              after_context: int = 0,
              context: int = 0,
              group_separator: str = '--',
              report: str | None = None,
              loglevel: int = 2):
    """
    Run lograptor with arguments. Experimental feature for use the log processor into
    generic Python scripts. This part is still under development, do not use.

    :param files: input files, each argument can be a file path or a glob pathname.
    :param cfgfiles: use a specific configuration file.
    :param matcher: the matcher engine to use; can be 'ruled' (default), 'unruled' or 'unparsed'.
    :param apps: process the log lines related to a list of applications.
    :param hosts: process the log lines related to a list of hosts.
    :param patterns: regex patterns, select the log line if at least one pattern matches.
    :param pattern_files: get patterns from FILE.
    :param channels: send output to o set of output channels (default: ['stdout']).
    :param filters: process the log lines that match all the conditions for rule's field values.
    :param time_range: process the log lines related to a time range.
    :param time_period: restrict the search scope to a date or a date interval.
    :param ignore_case: ignore case distinctions, defaults to `False`.
    :param invert: invert the sense of patterns regexp matching.
    :param word: force PATTERN to match only whole words.
    :param files_with_match: get only names of FILEs containing matches, defaults to `None`.
    :param count: get only a count of matching lines per FILE.
    :param color: use markers to highlight the matching strings, defaults to `auto`.
    :param quiet: suppress all normal output.
    :param max_count: stop after NUM matches.
    :param only_matching: get only the part of a line matching PATTERN.
    :param line_number: get line number with output lines.
    :param with_filename: get or suppress the file name for each match.
    :param ip_lookup: translate IP addresses to DNS names.
    :param uid_lookup: translate numeric UIDs to usernames.
    :param anonymize: anonymize defined rule's fields value.
    :param thread: get the lines of logs related to each log line selected.
    :param recursive: read all files under each directory, recursively.
    :param dereference_recursive: likewise, but follow all symlinks.
    :param include: search only files that match GLOB.
    :param exclude: skip files whose base name matches any of the file-name globs.
    :param exclude_from: skip files whose base name matches any of the file-name \
    globs read from FILE.
    :param exclude_dir: exclude directories matching the pattern DIR.
    :param before_context: get NUM lines of leading context for each log line selected.
    :param after_context: get NUM lines of trailing context for each log line selected.
    :param context: get NUM lines of output context for each log line selected.
    :param group_separator: which string to use as a group separator, for default \
    is double hyphen (--).
    :param report: produce a report at the end of processing, defaults to `False`. \
    Provide a name for the report or `None` to produce an unnamed report to stdout.
    :param loglevel: logging level [0=DEBUG], defaults to `2`.
    """
    if filters is None:
        filters = {}

    args = argparse.Namespace(**{k: v for k, v in locals().items()})
    return LogRaptor(args)
    action_info = ActionInfo.from_parser(cli_parser)

    # Check provided command line arguments, filling missing ones with default values.
    for key, value in vars(args).items():
        current = action_info
        while True:
            if key in current:
                current[key].verify(key, value)
                break

            subcommand: Any = None
            for k, v in current.items():
                if not isinstance(v.choices, dict):
                    if v.required:
                        raise AttributeError(f"missing required attribute {k!r} in {args!r}")
                elif k in args and getattr(args, k) in v.choices:
                    if subcommand is not None:
                        raise ValueError(f"find more actions for subcommand {subcommand[0]!r}")
                    subcommand = k, v
            else:
                if subcommand is None:
                    raise TypeError(f"unknow argument {key!r} with value {value!r}")
                current = subcommand[1].choices[getattr(args, subcommand[0])]

    return LogRaptor(args)


def main():
    args = cli_parser.parse_args()
    try:
        if has_void_args(sys.argv) and 'stdout' in args.channels:
            # If the command is called with no relevant args (eg. no args
            # or only --conf argument) then prints the configuration and exit.
            args.patterns.append('')
            runner = LogRaptor(args)
            print(runner.get_config())
            sys.exit(0)

        runner = LogRaptor(args)
        retval = runner()
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


cli_parser = create_argument_parser()

if __name__ == '__main__':
    main()
