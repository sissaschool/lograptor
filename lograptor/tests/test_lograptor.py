#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test script for lograptor.
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
import re
import sys
import pytest
import tarfile

# Move into the test directory and adds the path of the package that contains the test.
os.chdir(os.path.dirname(__file__))
pkg_search_path = os.path.abspath('../..')
if sys.path[0] != pkg_search_path:
    sys.path.insert(0, pkg_search_path)

from .. import __name__ as package_name
from ..cli import create_argument_parser
from ..exceptions import (
    LograptorArgumentError, OptionError, LograptorConfigError, FormatError, FileMissingError, FileAccessError
)
from ..core import Lograptor

# Extract sample files
tar = tarfile.open('samples.tar', "r:")
tar.extractall()
tar.close()


def pytest_report_header(config):
    return "Lograptor test"


class TestLograptor(object):
    """
    Test which lograptor applications have unparsed line issues.
    """
    cli_parser = create_argument_parser()

    def setup_method(self, method):
        print("\n%s:%s" % (type(self).__name__, method.__name__))

    def exec_lograptor(self, cmd_line):
        print(u"# {} {}".format(package_name, cmd_line))
        args = self.cli_parser.parse_args(args=cmd_line.split())

        args.patterns = [pat.strip('\'') for pat in args.patterns]
        if not args.patterns:
            pat = args.files.pop(0)
            args.patterns.append(pat.strip('\''))

        try:
            _lograptor = Lograptor(args)
            try:
                retval = _lograptor.process()
            finally:
                _lograptor.cleanup()
        except (LograptorArgumentError, OptionError, LograptorConfigError, FormatError,
                FileMissingError, FileAccessError) as err:
            if 'stdout' not in args.channels:
                sys.exit(u"ERROR: {0}\nExiting ...".format(err))
            elif str(err):
                self.cli_parser.error(err)
            else:
                self.cli_parser.print_usage()
                sys.exit(2)
        except KeyboardInterrupt:
            print("\nCtrl-C pressed, terminate the process ...")
            sys.exit(1)

        return 0 if retval else 1

    @pytest.mark.unparsed
    def test_unparsed(self, capsys):
        tests = (
            "-U -s -c --apps postfix -e '' samples/postfix.log",
            "-U -s -c --apps dovecot -e '' samples/dovecot.log",
            "-U -s -c --apps sshd -e '' samples/sshd.log",
        )
        for cmd_line in tests:
            out, err = capsys.readouterr()
            print("--- Test unparsed matching ---\n")
            retval = self.exec_lograptor(cmd_line)
            print(u"\n{0}".format(out))
            assert retval == 1

    @pytest.mark.threads
    def test_threads(self, capsys):
        """
        Tests for threaded searching.
        """
        tests = [
            ("-HnT -a postfix -e stegosaurus samples/postfix.log",
             r' 21\nTotal log events matched: 6\n'),
            ("-HnT --apps dovecot '' samples/dovecot.log",
             r' 20\nTotal log events matched: 20\n'),
            ("-HnT -a dovecot,postfix -e trice samples/postfix.log samples/dovecot.log",
             r' 41\nTotal log events matched: 5\n'),
            ("-T --apps postfix -F from=triceratops.* '' samples/postfix.log",
             r'(Jan .*\n){3}(.*\n){3}.* 21\nTotal log events matched: 3\s*\n')
        ]
        for cmd_line, result in tests:
            print("--- Test threaded matching ---\n")
            retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval == 0 and re.search(result, out) is not None

    @pytest.mark.pattern
    def test_basic_pattern(self, capsys):
        tests = [
            ("-a postfix -c -e triceratops samples/postfix.log",
             r'samples\/postfix\.log\n4\n'),
            ("-a dovecot -c -e triceratops samples/dovecot.log",
             r'20\nTotal log events matched: 1\n'),
            ("-c -e triceratops samples/postfix.log samples/dovecot.log",
             r'41\nTotal log events matched: 5\n'),
        ]
        for cmd_line, result in tests:
            print("--- Test basic pattern matching ---\n")
            retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval == 0 and re.search(result, out) is not None

    @pytest.mark.patfile
    def test_patfile(self, capsys):
        tests = [
            ("-a postfix -c -s -f ./samples/patterns.txt '' samples/postfix.log",
             r'samples\/postfix\.log\n21\n'),
            ("-a dovecot --color=never -H -c -s -f ./samples/patterns.txt '' samples/*",
             r'samples\/dovecot.log\:20\n'),
        ]
        for cmd_line, result in tests:
            print("--- Test file patterns matching ---\n")
            retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval == 0 and re.search(result, out) is not None

    @pytest.mark.period
    def test_period(self, capsys):
        """
        Test the time period parameters (options --date and --last).
        """
        tests = [
            # ("-a postfix --date=20141001,20141002 -c -s samples/*", r'No file found in the '),
            ("-a postfix -c -s --date=20150101,20150201 '' samples/postfix.log",
             r'samples/postfix.log\n21\s*\n'),
            #("-a postfix --last=1d -c -s", r'\.log: NN\n'),
        ]
        for cmd_line, result in tests:
            print("--- Test basic pattern matching with pediod ---\n")
            retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(result, out) is not None

    @pytest.mark.timerange
    def test_timerange(self, capsys):
        """
        Test the timerange option --time.
        """
        tests = [
            ("-a postfix --time=08:00,18:00 -H -c -s -e triceratops samples/postfix.log",
             r"samples\/postfix\.log:4\s*\n"),
            ("--time=08:00,09:00 -c -s -e triceratops samples/*.log",
             r"samples\/postfix\.log:4\s*\n"),
        ]
        for cmd_line, result in tests:
            print("--- Test --time option ---\n")
            retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(result, out) is not None

    @pytest.mark.noapps
    def test_noapps(self, capsys):
        """
        Tests for no-apps searching.
        """
        tests = [
            ('-X -c --date=20150101,20150201 -e triceratops samples/*',
             r' 85\nTotal log events matched: 11\n'),
            #('-A -c --date=20160701,20160731 -e triceratops samples/*',
            # r'No file found in the '),
        ]
        for cmd_line, result in tests:
            print("--- Test pattern matching with no-apps ---\n")
            retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(result, out) is not None

    @pytest.mark.fileset
    def test_fileset(self, capsys):
        """
        Test search on application fileset.
        """
        tests = [
            ('-c -a postfix --date=20150130,20150131 -e triceratops',
             r'triceratops\n4\n'),
            ('-c -a dovecot --date=20150401,20150430 -e triceratops',
             r' 20\nTotal log events matched: 1\n'),
            ('-c --date=20150101,20150430 -e triceratops',
             r' 77\nTotal log events matched: 12\n')
        ]
        for cmd_line, result in tests:
            print("--- Test fileset ---\n")
            retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval == 0 and re.search(result, out) is not None

    @pytest.mark.report
    def test_report(self, capsys):
        """
        Test on-line report.
        """
        tests = [
            ('--report -c -a postfix -e triceratops samples/*',
             r': 2015\-01\-31 09:50:08\s*\nLast event: 2015\-01\-31 09:50:08\s*\n'),
            ('--report -c -a dovecot -e tarbosa samples/*',
             r': 2015-04-01 10:00:12\s*\nLast event: 2015-04-01 10:00:13\s*\n'),
            ('--report -c -e triceratops samples/*',
             r'First event: 2015-01-31 01:51:12\s*\nLast event: 2015-04-01 10:00:03\s*\n')

        ]
        for cmd_line, result in tests:
            print("--- Test on-line reporting ---\n")
            retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(result, out) is not None

    @pytest.mark.output
    def test_output(self, capsys):
        """
        Test output to no stdin channels.
        """
        tests = [
            ("-c --report --output mail1,file1 -a dovecot '' samples/dovecot.log",
             r'Mailed the report to: brunato@sissa.it\s*\n'),
            #('-c --report --output mail1,file1 '' samples/dovecot.log',
            # r"Mailed the report")
        ]
        for cmd_line, result in tests:
            print("--- Test on-line report publishing ---\n")
            retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval == 0 and re.search(result, out) is not None

    @pytest.mark.filters
    def test_filters(self, capsys):
        """
        Test Lograptor's filters.
        """
        tests = [
            ("-c -a postfix -F from=\"triceratops.*\" '' samples/*",
             r" 123\s*\nTotal log events matched: 3\s*\n"),
            ("-c -a postfix -F rcpt=tarbosaurus.* '' samples/*",
             r" 123\s*\nTotal log events matched: 0\s*\n"),
            ("-c -a postfix -F from=tarbosaurus.* -F rcpt=trex.* -e '' samples/*",
             r" 123\s*\nTotal log events matched: 2\s*\n"),
            ("-c -F user='triceratops.*' -e '' samples/*.log",
             r" 118\s*\nTotal log events matched: 8\s*\n")
        ]
        for cmd_line, result in tests:
            print("--- Test filters ---\n")
            retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(result, out) is not None

    @pytest.mark.quiet
    def test_quiet(self, capsys):
        """
        Test quiet option.
        """
        tests = [
            ('-q -a postfix -e triceratops samples/postfix.log', 0),
            ('-q -a dovecot -e dakjejakjeae samples/dovecot.log', 1),
            ('-q -e triceratops samples/*', 0)
        ]
        for cmd_line, retval in tests:
            print("--- Test quiet pattern matching ---\n")
            _retval = self.exec_lograptor(cmd_line)
            print("RETVAL: ", _retval)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert bool(retval) == bool(_retval)

    @pytest.mark.invert
    def test_invert(self, capsys):
        """
        Test inverted matching.
        """
        tests = [
            ('-c -a postfix --invert-match -e triceratops samples/*',
             r' 123\s*\nTotal log events matched: 17\s*\n', 0),
            ('-c -a dovecot --invert-match -e dakjejakjeae samples/*',
             r' 123\s*\nTotal log events matched: 20\s*\n', 0),
            ('-c --invert-match -e tricera* samples/*',
             r' 123\s*\nTotal log events matched: 65\s*\n', 0)
        ]
        for cmd_line, result, retval in tests:
            print("--- Test inverted pattern matching ---\n")
            _retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval == _retval and re.search(result, out) is not None

    @pytest.mark.case
    def test_case(self, capsys):
        """
        Test case insensitive matching.
        """
        tests = [
            ('-i -c -a postfix -e TriceRatops samples/*',
             r' 123\s*\nTotal log events matched: 4\s*\n', 0),
            ('-ic -a dovecot -e dakjejakjeae samples/dovecot.log',
             r' 123\s*\nTotal log events matched: 4\s*\n', 1)
        ]
        for cmd_line, result, retval in tests:
            print("--- Test case insensitive pattern matching ---\n")
            _retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval == _retval and re.search(result, out) is not None

    @pytest.mark.maxcount
    def test_maxcount(self, capsys):
        """
        Test case insensitive matching.
        """
        tests = [
            ('-c -a postfix -m 8 -e triceratops samples/*',
             r' 123\s*\nTotal log events matched: 4\s*\n'),
            ('-c -a dovecot -m 5 -e triceratops samples/*',
             r' 123\s*\nTotal log events matched: 1\s*\n'),
            ('-c -m 13 -e triceratops samples/*',
             r' 123\s*\nTotal log events matched: 12\s*\n')
        ]
        for cmd_line, result in tests:
            print("--- Test max count option ---\n")
            _retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(result, out) is not None

    @pytest.mark.hosts
    def test_hosts(self, capsys):
        """
        Test hosts parameter.
        """
        tests = [
            ('-c -a postfix --hosts raptor -e triceratops samples/postfix.log',
             r' 21\s*\nTotal log events matched: 4\s*\n'),
            ('-c -a dovecot --hosts raptor -e triceratops samples/dovecot.log',
             r' 20\s*\nTotal log events matched: 1\s*\n'),
            ('-c --hosts * -e triceratops samples/*',
             r' 123\s*\nTotal log events matched: 12\s*\n'),
            ('-c --hosts rapto? -e triceratops samples/*',
             r' 123\s*\nTotal log events matched: 12\s*\n')
        ]
        for cmd_line, result in tests:
            print("--- Test hosts option ---\n")
            _retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(result, out) is not None

    @pytest.mark.filenames
    def test_filenames(self, capsys):
        """
        Test output filenames parameters.
        """
        tests = [
            ('-H -m 3 -e triceratops samples/*.log',
             r'\nsamples\/(.){1,10}\.log'),
            ('-h -m 3 -a dovecot -e triceratops samples/*.log',
             r'118\s*\nTotal log events matched: 1\s*\n')
        ]
        for cmd_line, result in tests:
            print("--- Test output filename options ---\n")
            _retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(result, out) is not None

    @pytest.mark.anonymize
    def test_anonymize(self, capsys):
        """
        Test anonymized output feature.
        """
        tests = [
            ('--anonymize -a postfix -m 3 -e triceratops samples/dovecot.log samples/postfix.log',
             r'HOST_0001.*: THREAD_0001: from=<'),
            ('--anonymize -a dovecot -m 3 -e triceratops samples/dovecot.log samples/postfix.log',
             r'HOST_0001 dovecot: imap-login: Login: user=<'),
            ('--anonymize -m 3 -e triceratops samples/*.log',
             r'postfix\/pickup\[7350\]: THREAD_0004: uid=300 ')
        ]
        for cmd_line, result in tests:
            print("--- Test anonymized output option ---\n")
            _retval = self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(result, out) is not None
