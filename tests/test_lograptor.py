#
# Copyright (C), 2011-2020, by SISSA - International School for Advanced Studies.
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
import re
import sys

import lograptor
from lograptor.exceptions import (
    LogRaptorArgumentError, LogRaptorOptionError, LogRaptorConfigError,
    LogFormatError, FileMissingError, FileAccessError
)


CONFIG_FILES = ('lograptor.conf', 'test_lograptor.conf')


class TestLograptor(object):
    """
    Test which lograptor application have unparsed line issues.
    """
    cli_parser = lograptor.api.create_argument_parser()

    def setup_method(self, method):
        print("\n%s:%s" % (type(self).__name__, method.__name__))

    def exec_lograptor(self, cmd_line):
        args = self.cli_parser.parse_args(args=cmd_line.split())
        args.cfgfiles = CONFIG_FILES
        args.patterns = [pat.strip('\'') for pat in args.patterns]
        if not args.patterns:
            pat = args.files.pop(0)
            args.patterns.append(pat.strip('\''))

        try:
            _lograptor = lograptor.LogRaptor(args)
        except (LogRaptorArgumentError, LogRaptorOptionError, LogRaptorConfigError, LogFormatError,
                FileMissingError, FileAccessError) as err:
            if 'stdout' not in args.channels:
                sys.exit(u"ERROR: {0}\nExiting ...".format(err))
            elif str(err):
                self.cli_parser.error(err)
            else:
                self.cli_parser.print_usage()
                sys.exit(2)
        else:
            print(u"# {} --conf {} {}".format(lograptor.__name__,
                                              _lograptor.config.cfgfile, cmd_line))
            try:
                retval = _lograptor()
            except KeyboardInterrupt:
                print("\nCtrl-C pressed, terminate the process ...")
                sys.exit(1)
            else:
                return 0 if retval else 1

    def test_unparsed(self):
        tests = (
            "-U -s -c --apps postfix -e '' samples/postfix.log",
            "-U -s -c --apps dovecot -e '' samples/dovecot.log",
            "-U -s -c --apps sshd -e '' samples/sshd.log",
        )
        for cmd_line in tests:
            assert self.exec_lograptor(cmd_line) == 1

    def test_threads(self, capsys):
        """
        Tests for threaded searching.
        """
        tests = [
            ("-HnT -a postfix -e stegosaurus samples/postfix.log",
             r' 21\nTotal log events matched: 6\n', 0),
            ("-HnT --apps dovecot '' samples/dovecot.log",
             r' 20\nTotal log events matched: 20\n', 0),
            ("-HnT -a dovecot,postfix -e trice samples/postfix.log samples/dovecot.log",
             r' 41\nTotal log events matched: 5\n', 0),
            ("-T --apps postfix -F from=triceratops.* '' samples/postfix.log",
             r'(Jan .*\n){3}(.*\n){3}.* 21\nTotal log events matched: 3\s*\n', 0)
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_pattern(self, capsys):
        tests = [
            ("-a postfix -c -e triceratops samples/postfix.log",
             r'samples\/postfix\.log\n4\n', 0),
            ("-a dovecot -c -e triceratops samples/dovecot.log",
             r'20\nTotal log events matched: 1\n', 0),
            ("-c -e triceratops samples/postfix.log samples/dovecot.log",
             r'41\nTotal log events matched: 5\n', 0),
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_patfile(self, capsys):
        tests = [
            ("-a postfix -c -s -f ./samples/patterns.txt '' samples/postfix.log",
             r'samples\/postfix\.log\n21\n', 0),
            ("-a dovecot --color=never -H -c -s -f ./samples/patterns.txt '' samples/*",
             r'samples\/dovecot.log\:20\n', 0),
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_period(self, capsys):
        """
        Test the time period parameters (options --date and --last).
        """
        tests = [
            # ("-a postfix --date=20141001,20141002 -c -s samples/*", r'No file found in the '),
            ("-a postfix -c --date=20150101,20150201 '' "
             "samples/postfix.log", r'postfix\(matches\=21', 0),
            # ("-a postfix --last=1d -c -s", r'\.log: NN\n'),
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_time_range(self, capsys):
        """
        Test the time range option (--time).
        """
        tests = [
            ("-a postfix --time=08:00,18:00 -H -c -s -e triceratops samples/postfix.log",
             r"samples\/postfix\.log:4\s*\n", 0),
            ("--time=08:00,09:00 -c -s -e triceratops samples/*.log",
             r"samples\/postfix\.log:0\s*\n", 1),
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_unruled(self, capsys):
        """
        Tests for no-apps searching.
        """
        tests = [
            ('-X -c --date=20150101,20150201 -e triceratops samples/*',
             r' 63\nTotal log events matched: 11\n', 0),
            ('-X -c --date=20160701,20160731 -e triceratops samples/*',
             r'-e triceratops samples\/\*\n0', 1),
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_fileset(self, capsys):
        """
        Test with applications fileset.
        """
        tests = [
            ('-c -a postfix --date=20150130,20150131 -e triceratops',
             r'triceratops\nsamples/postfix.log:4\n', 0),
            ('-c -a dovecot --date=20150401,20150430 -e triceratops',
             r' 20\nTotal log events matched: 1\n', 0),
            ('-c --date=20150101,20150430 -e triceratops',
             r' 77\nTotal log events matched: 12\n', 0)
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_report(self, capsys):
        """
        Test on-line report.
        """
        tests = [
            ('--report -c -a postfix -e triceratops samples/*',
             r': 2015\-01\-31 09:50:08\s*\nLast event: 2015\-01\-31 09:50:08\s*\n', 0),
            ('--report -c -a dovecot -e tarbosa samples/*',
             r': 2015-04-01 10:00:12\s*\nLast event: 2015-04-01 10:00:13\s*\n', 0),
            ('--report -c -e triceratops samples/*',
             r'First event: 2015-01-31 01:51:12\s*\nLast event: 2015-04-01 10:00:03\s*\n', 0)

        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_output(self, capsys):
        """
        Test output to no stdin channels.
        """
        tests = [
            ("-c --report --output mail,file -a dovecot '' samples/dovecot.log",
             r'Mailed the report to: ', 0),
            # ('-c --report --output mail,file '' samples/dovecot.log',
            # r"Mailed the report", 0)
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_filters(self, capsys):
        """
        Test lograptor's filters.
        """
        tests = [
            ("-c -a postfix -F from=\"triceratops.*\" '' samples/*",
             r" 101\s*\nTotal log events matched: 3\s*\n", 0),
            ("-c -a postfix -F rcpt=tarbosaurus.* '' samples/*",
             r" 101\s*\nTotal log events matched: 0\s*\n", 1),
            ("-c -a postfix -F from=tarbosaurus.* -F rcpt=trex.* -e '' samples/*",
             r" 101\s*\nTotal log events matched: 2\s*\n", 0),
            ("-c -F user='triceratops.*' -e '' samples/*.log",
             r" 100\s*\nTotal log events matched: 8\s*\n", 0)
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_quiet(self):
        """
        Test quiet option.
        """
        tests = [
            ('-q -a postfix -e triceratops samples/postfix.log', 0),
            ('-q -a dovecot -e dakjejakjeae samples/dovecot.log', 1),
            ('-q -e triceratops samples/*', 0)
        ]
        for cmd_line, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)

    def test_invert(self, capsys):
        """
        Test inverted matching.
        """
        tests = [
            ('-c -a postfix --invert-match -e triceratops samples/*',
             r' 101\s*\nTotal log events matched: 17\s*\n', 0),
            ('-c -a dovecot --invert-match -e dakjejakjeae samples/*',
             r' 101\s*\nTotal log events matched: 20\s*\n', 0),
            ('-c --invert-match -e tricera* samples/*',
             r' 101\s*\nTotal log events matched: 65\s*\n', 0)
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_case(self, capsys):
        """
        Test case insensitive matching.
        """
        tests = [
            ('-i -c -a postfix -e TriceRatops samples/*',
             r' 101\s*\nTotal log events matched: 4\s*\n', 0),
            ('-ic -a dovecot -e dakjejakjeae samples/dovecot.log',
             r'\nTotal log events matched: 0\s*\n', 1)
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_maxcount(self, capsys):
        """
        Test max_count matches.
        """
        tests = [
            ('-c -a postfix -m 8 -e triceratops samples/*',
             r' 101\s*\nTotal log events matched: 4\s*\n', 0),
            ('-c -a dovecot -m 5 -e triceratops samples/*',
             r' 101\s*\nTotal log events matched: 1\s*\n', 0),
            ('-c -m 13 -e triceratops samples/*',
             r' 101\s*\nTotal log events matched: 12\s*\n', 0)
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_hosts(self, capsys):
        """
        Test hosts parameter.
        """
        tests = [
            ('-c -a postfix --hosts raptor -e triceratops samples/postfix.log',
             r' 21\s*\nTotal log events matched: 4\s*\n', 0),
            ('-c -a dovecot --hosts raptor -e triceratops samples/dovecot.log',
             r' 20\s*\nTotal log events matched: 1\s*\n', 0),
            ('-c --hosts * -e triceratops samples/*',
             r' 101\s*\nTotal log events matched: 12\s*\n', 0),
            ('-c --hosts rapto? -e triceratops samples/*',
             r' 101\s*\nTotal log events matched: 12\s*\n', 0)
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_filenames(self, capsys):
        """
        Test output filenames parameters.
        """
        tests = [
            ('-H -m 3 -e triceratops samples/*.log',
             r'-e triceratops samples\/\*\.log\nsamples\/(.){1,10}\.log', 0),
            ('-h -m 3 -e triceratops samples/*.log',
             r'-e triceratops samples\/\*\.log\nJan 31', 0),
            ('-m 3 -e triceratops samples/*.log',
             r'-e triceratops samples\/\*\.log\nsamples\/(.){1,10}\.log', 0),
            ('-m 3 -e triceratops samples/postfix.log',
             r'-e triceratops samples\/postfix.log\nJan 31', 0)
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False

    def test_anonymize(self, capsys):
        """
        Test anonymized output feature.
        """
        tests = [
            ('--anonymize -a postfix -m 3 -e triceratops samples/dovecot.log samples/postfix.log',
             r'HOST_000\d.*: THREAD_000\d: from=<', 0),
            ('--anonymize -a dovecot -m 3 -e triceratops samples/dovecot.log samples/postfix.log',
             r'HOST_000\d dovecot: imap-login: Login: user=<', 0),
            ('--anonymize -m 3 -e triceratops samples/*.log',
             r'postfix\/pickup\[7350\]: THREAD_000\d: uid=300 ', 0)
        ]
        for cmd_line, result, retval in tests:
            assert retval == self.exec_lograptor(cmd_line)
            out, err = capsys.readouterr()
            if re.search(result, out) is None:
                print(u"\n{0}".format(out))
                assert False
