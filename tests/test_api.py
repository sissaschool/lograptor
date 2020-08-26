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
import pytest
import datetime

import lograptor


class TestCommandLineInterface(object):
    """
    Test which lograptor application have unparsed line issues.
    """
    cli_parser = lograptor.api.create_argument_parser()

    def setup_method(self, method):
        print("\n%s:%s" % (type(self).__name__, method.__name__))

    def test_defaults(self):
        args = self.cli_parser.parse_args([])

        assert args.after_context == 0
        assert args.anonymize is False
        assert args.apps == []
        assert args.before_context == 0
        assert args.cfgfiles is None
        assert args.channels == ['stdout']
        assert args.color == 'auto'
        assert args.context == 0
        assert args.count is False
        assert args.exclude == []
        assert args.exclude_dir == []
        assert args.exclude_from == []
        assert args.files == []
        assert args.files_with_match is None
        assert args.filters == []
        assert args.group_separator == '--'
        assert args.hosts == []
        assert args.ignore_case is False
        assert args.include == []
        assert args.invert is False
        assert args.ip_lookup is False
        assert args.line_number is False
        assert args.loglevel == 2
        assert args.matcher is None
        assert args.max_count == 0
        assert args.only_matching is False
        assert args.pattern_files == []
        assert args.patterns == []
        assert args.quiet is False
        assert args.recursive is False
        assert args.report is False
        assert args.thread is False
        assert args.time_period is None
        assert args.time_range is None
        assert args.uid_lookup is False
        assert args.with_filename is None
        assert args.word is False

    def test_after_context_argument(self):
        args = self.cli_parser.parse_args('-A 10'.split())
        assert args.after_context == 10

        args = self.cli_parser.parse_args('--after-context 5'.split())
        assert args.after_context == 5

    def test_anonymize_argument(self):
        args = self.cli_parser.parse_args('--anonymize'.split())
        assert args.anonymize is True

    def test_app_argument(self):
        args = self.cli_parser.parse_args('-a postfix'.split())
        assert args.apps == ['postfix']
        args = self.cli_parser.parse_args('--apps postfix,dovecot'.split())
        assert args.apps == ['postfix', 'dovecot']

    def test_before_context_argument(self):
        args = self.cli_parser.parse_args('-B 10'.split())
        assert args.before_context == 10
        args = self.cli_parser.parse_args('--before-context 5'.split())
        assert args.before_context == 5

        with pytest.raises(SystemExit) as exc_info:
            self.cli_parser.parse_args('-B ten'.split())
        assert exc_info.value.args[0] == 2

        with pytest.raises(SystemExit) as exc_info:
            self.cli_parser.parse_args('--before-context=-5'.split())
        assert exc_info.value.args[0] == 2

        with pytest.raises(SystemExit) as exc_info:
            self.cli_parser.parse_args('--before-context 5.0'.split())
        assert exc_info.value.args[0] == 2

    def test_cfgfiles_argument(self):
        args = self.cli_parser.parse_args('--conf file1'.split())
        assert args.cfgfiles == ['file1']
        args = self.cli_parser.parse_args('--conf file1 --conf file2'.split())
        assert args.cfgfiles == ['file1', 'file2']

    def test_channels_argument(self):
        args = self.cli_parser.parse_args('--output channel1'.split())
        assert args.channels == ['channel1']
        args = self.cli_parser.parse_args('--output channel1,channel2'.split())
        assert args.channels == ['channel1', 'channel2']

    def test_count_argument(self):
        args = self.cli_parser.parse_args('-c'.split())
        assert args.count is True
        args = self.cli_parser.parse_args('--count'.split())
        assert args.count is True

    def test_color_argument(self):
        args = self.cli_parser.parse_args('--color auto'.split())
        assert args.color == 'auto'
        args = self.cli_parser.parse_args('--color always'.split())
        assert args.color == 'always'
        args = self.cli_parser.parse_args('--color never'.split())
        assert args.color == 'never'

        with pytest.raises(SystemExit) as exc_info:
            self.cli_parser.parse_args('--color black'.split())
        assert exc_info.value.args[0] == 2

    def test_context_argument(self):
        args = self.cli_parser.parse_args('-C 10'.split())
        assert args.context == 10
        args = self.cli_parser.parse_args('--context 5'.split())
        assert args.context == 5

    def test_exclude_argument(self):
        args = self.cli_parser.parse_args('--exclude *.log'.split())
        assert args.exclude == ['*.log']
        args = self.cli_parser.parse_args('--exclude bar-*.log --exclude=foo.log'.split())
        assert args.exclude == ['bar-*.log', 'foo.log']

    def test_exclude_from_argument(self):
        args = self.cli_parser.parse_args('--exclude-from=foo.log'.split())
        assert args.exclude_from == ['foo.log']
        args = self.cli_parser.parse_args('--exclude-from bar.log --exclude-from=foo.log'.split())
        assert args.exclude_from == ['bar.log', 'foo.log']

    def test_exclude_dir_argument(self):
        args = self.cli_parser.parse_args('--exclude-dir=foo*/'.split())
        assert args.exclude_dir == ['foo*/']
        args = self.cli_parser.parse_args('--exclude-dir=bar/ --exclude-dir=foo'.split())
        assert args.exclude_dir == ['bar/', 'foo']

    def test_files_argument(self):
        args = self.cli_parser.parse_args('foo*.log'.split())
        assert args.files == ['foo*.log']
        args = self.cli_parser.parse_args('foo*.log bar*.log'.split())
        assert args.files == ['foo*.log', 'bar*.log']

    def test_files_with_match_argument(self):
        args = self.cli_parser.parse_args('-L'.split())
        assert args.files_with_match is False
        args = self.cli_parser.parse_args('--files-without-match'.split())
        assert args.files_with_match is False
        args = self.cli_parser.parse_args('-l'.split())
        assert args.files_with_match is True
        args = self.cli_parser.parse_args('--files-with-match'.split())
        assert args.files_with_match is True

    def test_filters_argument(self):
        args = self.cli_parser.parse_args('--filter mail=foo*'.split())
        assert args.filters == [{'mail': 'foo*'}]
        args = self.cli_parser.parse_args('-F mail=foo*,uid=bar'.split())
        assert args.filters == [{'mail': 'foo*', 'uid': 'bar'}]
        args = self.cli_parser.parse_args('-F mail=foo* -F uid=bar'.split())
        assert args.filters == [{'mail': 'foo*'}, {'uid': 'bar'}]

    def test_group_separator_argument(self):
        args = self.cli_parser.parse_args('--group-separator=---'.split())
        assert args.group_separator == '---'
        args = self.cli_parser.parse_args('--no-group-separator'.split())
        assert args.group_separator == ''

    def test_hosts_argument(self):
        args = self.cli_parser.parse_args('--hosts foo.test'.split())
        assert args.hosts == ['foo.test']
        args = self.cli_parser.parse_args('--hosts=bar.test,foo.test'.split())
        assert args.hosts == ['bar.test', 'foo.test']

    def test_ignore_case_argument(self):
        args = self.cli_parser.parse_args('-i'.split())
        assert args.ignore_case is True
        args = self.cli_parser.parse_args('--ignore-case'.split())
        assert args.ignore_case is True

    def test_include_argument(self):
        args = self.cli_parser.parse_args('--include foo*.log'.split())
        assert args.include == ['foo*.log']
        args = self.cli_parser.parse_args('--include foo*.log --include bar*.log'.split())
        assert args.include == ['foo*.log', 'bar*.log']

    def test_invert_match_argument(self):
        args = self.cli_parser.parse_args('-v'.split())
        assert args.invert is True
        args = self.cli_parser.parse_args('--invert-match'.split())
        assert args.invert is True

    def test_ip_lookup_argument(self):
        args = self.cli_parser.parse_args('--ip-lookup'.split())
        assert args.ip_lookup is True

    def test_line_number_argument(self):
        args = self.cli_parser.parse_args('-n'.split())
        assert args.line_number is True
        args = self.cli_parser.parse_args('--line-number'.split())
        assert args.line_number is True

    def test_loglevel_argument(self):
        args = self.cli_parser.parse_args('-d 4'.split())
        assert args.loglevel == 4

        with pytest.raises(SystemExit) as exc_info:
            self.cli_parser.parse_args('-d 5'.split())
        assert exc_info.value.args[0] == 2

    def test_matcher_argument(self):
        args = self.cli_parser.parse_args('-G'.split())
        assert args.matcher == '--ruled'
        args = self.cli_parser.parse_args('--ruled'.split())
        assert args.matcher == '--ruled'

        args = self.cli_parser.parse_args('-X'.split())
        assert args.matcher == '--unruled'
        args = self.cli_parser.parse_args('--unruled'.split())
        assert args.matcher == '--unruled'

        args = self.cli_parser.parse_args('-U'.split())
        assert args.matcher == '--unparsed'
        args = self.cli_parser.parse_args('--unparsed'.split())
        assert args.matcher == '--unparsed'

    def test_max_count_argument(self):
        args = self.cli_parser.parse_args('-m 3'.split())
        assert args.max_count == 3
        args = self.cli_parser.parse_args('--max-count 1'.split())
        assert args.max_count == 1

    def test_only_matching_argument(self):
        args = self.cli_parser.parse_args('-o'.split())
        assert args.only_matching is True
        args = self.cli_parser.parse_args('--only-matching'.split())
        assert args.only_matching is True

    def test_pattern_files_argument(self):
        args = self.cli_parser.parse_args('-f patterns.txt'.split())
        assert args.pattern_files == ['patterns.txt']
        args = self.cli_parser.parse_args('-f patterns1.txt --file=patterns2.txt'.split())
        assert args.pattern_files == ['patterns1.txt', 'patterns2.txt']

    def test_patterns_argument(self):
        args = self.cli_parser.parse_args('-e .*'.split())
        assert args.patterns == ['.*']
        args = self.cli_parser.parse_args('-e .* -e ^$'.split())
        assert args.patterns == ['.*', '^$']
        args = self.cli_parser.parse_args('--regexp=.* -e ^$'.split())
        assert args.patterns == ['.*', '^$']
        args = self.cli_parser.parse_args('--regexp=.* -e ^$'.split())
        assert args.patterns == ['.*', '^$']

    def test_quiet_argument(self):
        args = self.cli_parser.parse_args('-q'.split())
        assert args.quiet is True
        args = self.cli_parser.parse_args('--quiet'.split())
        assert args.quiet is True

    def test_recursive_argument(self):
        args = self.cli_parser.parse_args('-r'.split())
        assert args.recursive is True
        args = self.cli_parser.parse_args('--recursive'.split())
        assert args.recursive is True

    def test_report_argument(self):
        args = self.cli_parser.parse_args('--report foo.txt'.split())
        assert args.report == 'foo.txt'

    def test_thread_argument(self):
        args = self.cli_parser.parse_args('-T'.split())
        assert args.thread is True
        args = self.cli_parser.parse_args('--thread'.split())
        assert args.thread is True

    def test_time_period_argument(self):
        year = datetime.datetime.now().year
        args = self.cli_parser.parse_args('--date=0825,0826'.split())
        assert args.time_period == (datetime.datetime(year, 8, 25, 0, 0),
                                    datetime.datetime(year, 8, 26, 23, 59, 59))

        dt = datetime.datetime.now().replace(microsecond=0)
        args = self.cli_parser.parse_args('--last day'.split())
        assert args.time_period == (dt - datetime.timedelta(days=1),
                                    dt + datetime.timedelta(hours=1))

    def test_time_range_argument(self):
        args = self.cli_parser.parse_args('--time 10:00,14:30'.split())
        assert args.time_range.h1 == 10
        assert args.time_range.m1 == 0
        assert args.time_range.h2 == 14
        assert args.time_range.m2 == 30

    def test_uid_lookup_argument(self):
        args = self.cli_parser.parse_args('--uid-lookup'.split())
        assert args.uid_lookup is True

    def test_with_filename_argument(self):
        args = self.cli_parser.parse_args('-H'.split())
        assert args.with_filename is True
        args = self.cli_parser.parse_args('--with-filename'.split())
        assert args.with_filename is True
        args = self.cli_parser.parse_args('-h'.split())
        assert args.with_filename is False
        args = self.cli_parser.parse_args('--no-filename'.split())
        assert args.with_filename is False

    def test_word_argument(self):
        args = self.cli_parser.parse_args('-w'.split())
        assert args.word is True
        args = self.cli_parser.parse_args('--word-regex'.split())
        assert args.word is True
