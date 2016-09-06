#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Command line tools for Lograptor package.
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
import os
import sys
import contextlib
import argparse
from .core import Lograptor
from .info import __version__, __description__
from .exceptions import (ConfigError, OptionError, FormatError, FileMissingError, FileAccessError)


def create_argument_parser(cfgfile_default):
    """
    Command line options and arguments parsing. This function return
    a list of options and the list of arguments (pattern, filenames).
    """
    parser = argparse.ArgumentParser(prog='lograptor', description=__description__)
    parser.usage = """ %(prog)s [options] [PATTERN] [FILE ...]
    %(prog)s [options] [ -e PATTERN | -f FILE ] [FILE ...]
    Try '%(prog)s --help' for more information."""
    parser.add_argument('--version', action='version', version=__version__)

    # Options of the group "General Options"
    group = parser.add_argument_group("General Options")
    group.add_argument(
        "--conf", dest="cfgfile", type=str, default=cfgfile_default, metavar="<CONFIG_FILE>",
        help="Use a specific configuration file for Lograptor, instead of the "
             "default file located in {0}. Calling the program without other "
             "options and arguments produce a dump of the configuration settings "
             "to stdout.".format(cfgfile_default)
    )
    group.add_argument(
        "-d", dest="loglevel", default=2, type=int, metavar="[0-4]",
        help="Logging level. The default is 2 (warning). Level 0 log only "
             "critical errors, higher levels shows more information."
    )

    # Options of the group "Scope Options"
    group = parser.add_argument_group("Scope Options")
    group.add_argument(
        "-H", "--hosts", metavar="HOST/IP[,HOST/IP...]", action="store", dest="hosts", default='*',
        help="Will analyze only log lines related to comma separated list of hostnames and/or "
             "IP addresses. File path wildcards can be used for hostnames."
    )
    parser.set_defaults(apps='')
    group.add_argument(
        '-a', "--apps", metavar='APP[,APP...]', action="store", dest="apps",
        help="Analyze only log lines related to a comma separated list of applications. "
             "An app is valid when a configuration file is defined. For default the program "
             "process all enabled apps."
    )
    group.add_argument(
        "-A", action="store_const", dest="apps", const=None,
        help="Skip applications processing. The searches are performed only with pattern(s) "
             "matching. This option is incompatible with report and matching options related "
             "to app's rules."
    )
    group.add_argument(
        "--last", action="store", dest="period", default=None,
        metavar="[hour|day|week|month|Nh|Nd|Nw|Nm]",
        help="Restrict search scope to a previous time period."
    )
    group.add_argument(
        "--date", metavar="[YYYY]MMDD[,[YYYY]MMDD]", action="store", dest="period", default=None,
        help="Restrict search scope to a date or an interval of dates."
    )
    group.add_argument(
        "--time", metavar="HH:MM,HH:MM", action="store", dest="timerange", default=None,
        help="Restrict search scope to a time range."
    )

    # Options of the group "Matching Control"
    group = parser.add_argument_group("Matching Control")
    group.add_argument(
        "-e", "--regexp", dest="patterns", default=None, action="append",
        help="The search pattern. Use the option more times to specify multiple "
             "search patterns. Empty patterns are skipped."
    )
    group.add_argument(
        "-f", "--file", dest="pattern_file", default=None, metavar="FILE",
        help="Obtain patterns from FILE, one per line. Empty patterns are skipped."
    )
    group.add_argument(
        "-i", "--ignore-case", action="store_true", dest="case", default=False,
        help="Ignore case distinctions in matching."
    )
    group.add_argument(
        "--invert-match", action="store_true", dest="invert", default=False,
        help="Invert the sense of matching, to select non-matching lines."
    )
    group.add_argument(
        "-F", "--filter", metavar="FILTER=PATTERN[,FILTER=PATTERN...]",
        action="append", dest="filters", default=None,
        help="Refine the search with a comma separated list of filters. "
             "The filters list are applied with logical disjunction (OR). "
             "Providing more --filter options perform logical conjunction (AND)."
    )
    group.add_argument(
        "-t", "--thread", dest="thread", action="store_true", default=False,
        help="Perform matching at thread level, using the thread rules defined in "
             "configuration files of each application."
    )
    group.add_argument(
        "-u", "--unparsed", action="store_true", dest="unparsed", default=False,
        help="Match lines that are unparsable by app's rules. Useful for finding anomalies and for "
             "application's rules debugging. This option is incompatible with option -F/--filters"
    )

    # Options of the group "Output Control"
    group = parser.add_argument_group("Output Control")
    group.add_argument(
        "-c", "--count", action="store_true", default=False,
        help="Suppress normal output; instead print a count of matching lines for each input file. "
             "With  the  -v/--invert-match option, counts non-matching lines.")
    group.add_argument(
        "-m", "--max-count", metavar='NUM', action="store", type=int, dest="max_count", default=None,
        help="Stop reading a file after NUM matching lines. When -c/--count option is also used, "
             "the program does not output a count greater than NUM."
    )
    group.add_argument(
        "-q", "--quiet", action="store_true", default=None,
        help="Quiet; do not write anything  to standard output. Exit immediately with zero status "
             "when a match is found, even if an error was detected. See also the -s or --no-messages options."
    )
    group.add_argument(
        "-s", "--no-messages", action="store_true", default=False,
        help="Suppress final run summary and error messages about nonexistent or unreadable files."
    )
    group.add_argument(
        "-o", "--with-filename", action="store_true", dest="print_filenames", default=None,
        help="Print the filename for each matching line."
    )
    group.add_argument(
        "-O", "--no-filename", action="store_false", dest="print_filenames", default=None,
        help="Suppress the default headers with filenames on output. This is the default "
             "behaviour for output also when searching in a single file."
    )
    group.add_argument(
        "--ip", action="store_true", dest="ip_lookup", default=False,
        help="Do a reverse lookup translation for the IP addresses for report data. Use a DNS local "
             "caching to improve the speed of the lookups and reduce the network service's load."
    )
    group.add_argument(
        "--uid", action="store_true", dest="uid_lookup", default=False,
        help="Map numeric UIDs to usernames for report data. The configured local system authentication "
             "is used for lookups, so it must be inherent to the UIDs that have to be resolved."
    )
    group.add_argument(
        "--anonymize", action="store_true", dest="anonymize", default=False,
        help="Anonymize output for values connected to provided filters. Translation tables are built "
             "in volatile memory for each run. The anonymous tokens have the format FILTER_NN. "
             "This option overrides --ip, --uid."
    )

    # Options of the group "Report Control"
    group = parser.add_argument_group("Report Control")
    group.add_argument(
        "-r", "--report", dest="report", action="store_true", default=False,
        help="Make a formatted text report at the end of processing and display it on console."
    )
    group.add_argument(
        "--publish", dest="publish", default=None, metavar='PUBLISHER[,PUBLISHER...]',
        help="Make a report and publish it using a comma separated list of publishers, choosed "
             "from the ones defined in the configuration file. You have to define your publishers "
             "in the main configuration file."
    )

    parser.add_argument('files', metavar='[FILE...]', nargs='*', help="Input filename/s.")
    return parser


def exec_lograptor(args, as_batch=False):
    """
    Main routine: parse command line, create the Lograptor instance, call
    processing of log files and manage exception errors.
    """
    # If debug level choosed than activate the logger immediately
    if args.loglevel == 4:
        import lograptor.utils
        lograptor.utils.set_logger(args.loglevel)

    my_raptor = Lograptor(args, as_batch)

    # Dump a configuration summary and exit when the program is called from the
    # command line without options and arguments or with only the --conf option.
    if not as_batch and (
            len(sys.argv) == 1 or
            (len(sys.argv) == 2 and sys.argv[1].startswith('--conf=')) or
            (len(sys.argv) == 3 and sys.argv[1] == '--conf')):
        print(my_raptor.get_configuration())
        my_raptor.cleanup()
        return 0

    try:
        retval = my_raptor.process()
        if my_raptor.make_report():
            my_raptor.publish_report()
    finally:
        my_raptor.cleanup()

    return 0 if retval else 1


class DummyFile(object):
    def write(self, x):
        pass

    def flush(self):
        pass


@contextlib.contextmanager
def nostdout():
    """Redirect the stdout to a dummy file"""
    save_stdout = sys.stdout
    sys.stdout = DummyFile()
    yield
    sys.stdout = save_stdout


def main():
    if sys.version_info < (2, 7, 0):
        sys.stderr.write("You need python 2.7 or later to run this program\n")
        sys.exit(1)

    cli_parser = create_argument_parser('/etc/lograptor/lograptor.conf')
    args = cli_parser.parse_args()
    if os.isatty(sys.stdin.fileno()):
        try:
            retval = exec_lograptor(args, as_batch=False)
        except OptionError as e:
            cli_parser.error(e)
        except (ConfigError, FormatError, FileMissingError, FileAccessError) as e:
            sys.exit(u"ERROR: {0}\nExiting ...".format(e))
        except KeyboardInterrupt:
            print("\nCtrl-C pressed, terminate the process ...")
            sys.exit(1)
    else:
        with nostdout():
            try:
                retval = exec_lograptor(args, as_batch=True)
            except (OptionError, ConfigError, FormatError, FileMissingError, FileAccessError) as e:
                sys.exit(u"ERROR: {0}\nExiting ...".format(e))
    sys.exit(retval)


if __name__ == '__main__':
    main()
