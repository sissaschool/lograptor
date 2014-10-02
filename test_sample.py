#
# Test script for Lograptor.
#
__author__ = 'brunato'

import os
import re
import pytest

from lograptor import Lograptor
from lograptor.exceptions import FileMissingError

# Default options as defined by OptParse of lograptor(.py) script.
DEFAULT_OPTIONS = {
    'timerange': None,
    'period': None,
    'max_count': None,
    'filters': None,
    'out_filenames': None,
    'ip_lookup': False,
    'patterns': None,
    'invert': False,
    'apps': '',
    'publish': None,
    'cfgfile': '/etc/lograptor/lograptor.conf',
    'no_messages': False,
    'count': False,
    'report': False,
    'case': False,
    'thread': False,
    'loglevel': 0, # Program default is 2
    'anonymize': False,
    'quiet': None,
    'uid_lookup': False,
    'hosts': '*',
    'pattern_file': None,
    'unparsed': False
}

TESTDIR = './test_samples/'

LOG_SAMPLES = {
    'aironet' : 'aironet_sample.log',
    'apache2' : ['apache2_sample.log', 'apache2_access_sample.log', 'apache2_error_sample.log',],
    'asa': 'asa_sample.log',
    'barracuda' : 'barracuda_sample.log',
    'catalyst' : 'catalyst_sample.log',
    'cron' : 'cron_sample.log',
    'dovecot' : ['dovecot1_sample.log', 'dovecot2_sample.log'],
    'postfix' : 'postfix_sample.log',
    'radius' : 'radius_dhcp_ntp_sample.log',
    'rfc5424' : 'rfc5424_sample',
    'sshd' : 'sshd_sample.log',
    '': ['postfix_sample.log', 'dovecot1_sample.log', 'dovecot2_sample.log',],
}

APPLIST = ['sshd', 'dovecot', 'postfix',]


def pytest_report_header(config):
    return "Lograptor test"


def get_args_for_apps(app):
    """ Return list of arguments for apps names """
    sample_files = LOG_SAMPLES[app]
    if type(sample_files) == str:
        sample_files = [sample_files]
    return [ ''.join([TESTDIR, samplefile]) for samplefile in sample_files]


class TestLograptor(object):
    """
    Test which lograptor applications have unparsed line issues.
    """

    def set_cmdheader(self):
        cfgfile = u'./lograptor.conf'
        if os.path.isfile(cfgfile) and os.path.isfile('./lograptor.py'):
            self.cmdheader = './lograptor.py --conf {0}'.format(cfgfile)
        else:
            self.cmdheader = 'lograptor'

    def setup_method(self, method):
        print "\n%s:%s" % (type(self).__name__, method.__name__)

    def run_lograptor(self, options, args, as_batch=False):
        """
        Create and run a Lograptor instance in order to make a test.
        """
        run_options = DEFAULT_OPTIONS.copy()
        run_options.update(options)

        if self.cmdheader != 'lograptor':
            run_options['cfgfile'] = u'./lograptor.conf'

        try:
            my_raptor = Lograptor(run_options['cfgfile'], options, DEFAULT_OPTIONS, args, as_batch)
            retval = my_raptor.process()
        except FileMissingError as e:
            print(e)
            if 'my_raptor' in locals():
                my_raptor.cleanup()
            return False

        # Publish the report if is requested and it's not empty
        if my_raptor.make_report():
            my_raptor.publish_report()

        my_raptor.cleanup()

        return retval

    @pytest.mark.unparsed
    def test_unparsed(self, capsys):
        self.set_cmdheader()
        for app in APPLIST:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'unparsed' : True,
                'no_messages' : True,
            }
            cmdline = u'--unparsed -s -c -a {0} {1}'.format(app, u' '.join(args))
            out, err = capsys.readouterr()
            print(u"--- Test unparsed strings match for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            print(u"\n{0}".format(out))
            assert not retval

    @pytest.mark.threads
    def test_threads(self, capsys):
        """
        Tests for threaded searching.
        """
        self.set_cmdheader()
        tests = {
            'postfix' : r'Total log events matched: 3\n',
            'dovecot' : r'Total log events matched: 6\n',
            '' : r'65791\nTotal log events matched: 9\n',
        }
        for app in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'patterns' : [u'brunato'],
                'thread': True,
                'max_count': 3,
            }
            cmdline = u'-e \'brunato\' -t -a \'{0}\' -c -m {1} {2}'.format(app, 3, u' '.join(args))
            print("--- Test threaded matching for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval and re.search(tests[app], out) is not None

    @pytest.mark.pattern
    def test_basic_pattern(self, capsys):
        self.set_cmdheader()
        tests = {
            'postfix' : r'\.log: 76\n',
            'dovecot' : r'Total log events matched: 295\n',
            '': r'Total log events matched: 371\n',
        }
        for app in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'patterns' : [u'brunato'],
                #'no_messages' : True,
            }
            cmdline = u'-e \'brunato\' -c -a \'{0}\' {1}'.format(app, u' '.join(args))
            print("--- Test basic pattern matching for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval and re.search(tests[app], out) is not None

    @pytest.mark.file
    def test_pattern_file(self, capsys):
        self.set_cmdheader()
        tests = {
            'postfix' : r'\.log: 196\n',
            'dovecot' : r'\.log: 531\n',
        }
        for app in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'pattern_file' : u'./test_samples/patterns_samples.txt',
                'no_messages' : True,
            }
            cmdline = u'-f {2} -s -c -a {0} {1}'.format(app, u' '.join(args), options['pattern_file'])
            print("--- Test file patterns matching for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval and re.search(tests[app], out) is not None

    @pytest.mark.period
    def test_period(self, capsys):
        """
        Test the period parameter (options --date and --last).
        """
        self.set_cmdheader()
        tests = {
            ('postfix', '20141001,20141002') : r'No file found in the ',
            ('postfix', '20140901,20141002') : r'\.log: 76\n',
            ('postfix', '1d') : r'\.log: 76\n',
        }
        for app, period in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'period' : period,
                'patterns' : [u'brunato'],
                'no_messages' : True,
            }
            cmdline = u'--date={2} -e \'brunato\' -s -c -a {0} {1}'.format(app, u' '.join(args), period)
            print("--- Test basic pattern matching with pediod for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(tests[(app, period)], out) is not None

    @pytest.mark.timerange
    def test_timerange(self, capsys):
        """
        Test the timerange option --time.
        """
        self.set_cmdheader()
        tests = {
            ('postfix', '08:00,18:00') : r'postfix_sample.log: 59\s*\n',
            ('', '08:00,12:00') : r'postfix_sample.log: 59\s*\n',
        }
        for app, timerange in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'timerange' : timerange,
                'patterns' : [u'brunato'],
                'no_messages' : True,
            }
            cmdline = u'--date={2} -e \'brunato\' -s -c -a {0} {1}'.format(app, u' '.join(args), timerange)
            print("--- Test --time option with '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(tests[(app, timerange)], out) is not None

    @pytest.mark.noapps
    def test_noapps(self, capsys):
        """
        Tests for no-apps searching.
        """
        self.set_cmdheader()
        tests = {
            '20141001,20141002' : r'No file found in the ',
            '20140901,20141002' : r'Total log events matched: 226\n',
        }
        args = get_args_for_apps('')

        for period in tests:
            options = {
                'count' : True,
                'period' : period,
                'patterns' : [u'brunato'],
            }
            cmdline = u'--date={0} -e \'brunato\' -c -A {1}'.format(period, u' '.join(args))
            print("--- Test pattern matching with no-apps ---\n")
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(tests[period], out) is not None

    @pytest.mark.fileset
    def test_fileset(self, capsys):
        """
        Test search on application fileset.
        """
        self.set_cmdheader()
        tests = {
            'postfix' : r'\.log: 76\n',
            'dovecot' : r'83678\nTotal log events matched: 150\n',
            '': r'179925\nTotal log events matched: 226\n',
        }
        period = u'20140901,20140930'
        for app in tests:
            options = {
                'apps' : app,
                'count' : True,
                'patterns' : [u'brunato'],
                'period': period,
            }
            cmdline = u'-e \'brunato\' -c -a \'{0}\' --date {1}'.format(app, period)
            print("--- Test fileset for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, [])
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval and re.search(tests[app], out) is not None

    @pytest.mark.report
    def test_report(self, capsys):
        """
        Test on-line report.
        """
        self.set_cmdheader()
        tests = {
            'postfix' : r': 2014\-09\-22 00:06:03\s*\nLast event: 2014\-09\-22 23:52:02\s*\n',
            'dovecot' : r': 2012\-06\-25 00:10:14\s*\nLast event: 2014\-09\-22 23:52:02\s*\n',
            '': (r'Applications: postfix\(93561\), dovecot\(144469\)\s*\n\s*\n'
                 r'First event: 2012\-06\-25 00:10:14\s*\nLast event: 2014\-09\-22 23:52:02\s*\n'),
        }
        for app in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'patterns' : [u'brunato'],
                'report' : True,
                #'no_messages' : True,
            }
            cmdline = u'-e \'brunato\' -r -c -a \'{0}\' {1}'.format(app, u' '.join(args))
            print("--- Test on-line reporting for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval and re.search(tests[app], out) is not None

    @pytest.mark.publish
    def test_publishing(self, capsys):
        """
        Test on-line report publishing. Is not called by default.
        """
        self.set_cmdheader()
        tests = {
            'dovecot' : r'Mailed the report to: brunato@sissa.it\s*\n'
                        r'Report saved in: \.\/var\/www\/lograptor\/',
            '' : r'Mailed the report to: brunato@sissa.it\s*\n'
                 r'Report saved in: \.\/var\/www\/lograptor\/',
        }
        for app in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'publish' : u'mailtest,filetest',
                #'publish' : u'filetest',
                #'no_messages' : True,
            }
            cmdline = u'--publish \'mailtest,filetest\' -c -a \'{0}\' {1}'.format(app, u' '.join(args))
            print("--- Test on-line report publishing for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval and re.search(tests[app], out) is not None

    @pytest.mark.filters
    def test_filters(self, capsys):
        """
        Test Lograptor's filters.
        """
        self.set_cmdheader()
        tests = {
            ('postfix', ("from=brunato.*",)): r'93561\s*\nTotal log events matched: 1\s*\n',
            ('postfix', ("rcpt=brunato.*",)): r'93561\s*\nTotal log events matched: 74\s*\n',
            ('postfix', ("from=brunato.*", "rcpt=brunato.*",)): r'93561\s*\nTotal log events matched: 75\s*\n',
            ('', ("user=brunato.*",)): r'238030\s*\nTotal log events matched: 746\s*\n',
        }
        for app, filters in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'filters': list(filters),
                #'patterns' : [u'brunato'],
                #'no_messages' : True,
            }
            cmdline = u'-F {2} -c -a \'{0}\' {1}'.format(app, u' '.join(args), ' -F '.join(filters))
            print("--- Test filters for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval and re.search(tests[(app, filters)], out) is not None

    @pytest.mark.quiet
    def test_quiet(self, capsys):
        """
        Test quiet option with various patterns.
        """
        self.set_cmdheader()
        tests = {
            ('postfix', r'brunato') : True,
            ('dovecot', r'dakjejakjeae'): False,
            ('', r'brunato.*'): True,
        }
        for app, pattern in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'quiet' : True,
                'patterns' : [pattern],
            }
            cmdline = u'-q -e \'{0}\' -a \'{1}\' {2}'.format(pattern, app, u' '.join(args))
            print("--- Test quiet pattern matching for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval == tests[(app, pattern)]

    @pytest.mark.invert
    def test_invert(self, capsys):
        """
        Test invert matching.
        """
        self.set_cmdheader()
        tests = {
            ('postfix', r'brunato') : r'93561\s*\nTotal log events matched: 93485\s*\n',
            ('dovecot', r'dakjejakjeae'): r'144469\s*\nTotal log events matched: 144950\s*\n',
            ('', r'brunato.*'): r'238030\s*\nTotal log events matched: 238140\s*\n',
        }
        for app, pattern in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'patterns' : [pattern],
                'invert': True,
            }
            cmdline = u'-v -e \'{0}\' -a \'{1}\' {2}'.format(pattern, app, u' '.join(args))
            print("--- Test inverted pattern matching for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval and re.search(tests[(app, pattern)], out) is not None

    @pytest.mark.case
    def test_case(self, capsys):
        """
        Test case insensitive matching.
        """
        self.set_cmdheader()
        tests = {
            ('postfix', r'BrUnaTo') : r'93561\s*\nTotal log events matched: 76\s*\n',
            ('dovecot', r'dakjejakjeae'): r'144469\s*\nTotal log events matched: 0\s*\n',
            #('', r'brunato.*'): r'93561\s*\nTotal log events matched: 1\s*\n',
        }
        for app, pattern in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'patterns' : [pattern],
                'case': True,
            }
            cmdline = u'-i -e \'{0}\' -a \'{1}\' {2}'.format(pattern, app, u' '.join(args))
            print("--- Test inverted pattern matching for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(tests[(app, pattern)], out) is not None

    @pytest.mark.maxcount
    def test_maxcount(self, capsys):
        """
        Test case insensitive matching.
        """
        self.set_cmdheader()
        tests = {
            ('postfix', 8) : r'10419\s*\nTotal log events matched: 8\s*\n',
            ('dovecot', 5): r'4931\s*\nTotal log events matched: 10\s*\n',
            ('', 13): r'35721\s*\nTotal log events matched: 39\s*\n',
        }
        for app, max_count in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'patterns' : ['brunato.*'],
                'max_count': max_count,
            }
            cmdline = u'-m {0} -e \'brunato\' -a \'{1}\' {2}'.format(max_count, app, u' '.join(args))
            print("--- Test max count option with '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(tests[(app, max_count)], out) is not None

    @pytest.mark.hosts
    def test_hosts(self, capsys):
        """
        Test hosts parameter.
        """
        self.set_cmdheader()
        tests = {
            ('postfix', 'posta-01') : r'93561\s*\nTotal log events matched: 0\s*\n',
            ('dovecot', 'posta-02'): r'144469\s*\nTotal log events matched: 150\s*\n',
            ('', '*'): r'238030\s*\nTotal log events matched: 371\s*\n',
            ('', 'posta-0?'): r'238030\s*\nTotal log events matched: 371\s*\n',
        }
        for app, hosts in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'patterns' : ['brunato.*'],
                'hosts': hosts,
            }
            cmdline = u'-H \'{0}\' -e \'brunato\' -a \'{1}\' {2}'.format(hosts, app, u' '.join(args))
            print("--- Test max count option with '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(tests[(app, hosts)], out) is not None

    @pytest.mark.filenames
    def test_filenames(self, capsys):
        """
        Test output filenames parameters.
        """
        self.set_cmdheader()
        tests = {
            ('', True) : r'\n\.\/test_samples\/',
            ('dovecot', False): r'1459\s*\nTotal log events matched: 6\s*\n',
        }
        for app, out_filenames in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'max_count': 3,
                'patterns' : ['brunato.*'],
                'out_filenames': out_filenames
            }
            cmdline = u' {0} -m 3 -e \'brunato\' -a \'{1}\' {2}'\
                .format('-o' if out_filenames else '-O', app, u' '.join(args))
            print("--- Test output filename options with '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(tests[(app, out_filenames)], out) is not None

    @pytest.mark.anonymize
    def test_anonymize(self, capsys):
        """
        Test anonymized output feature.
        """
        self.set_cmdheader()
        tests = {
            'postfix': r'HOST_0001.*: THREAD_0001: to=<RCPT_0001>',
            'dovecot': r'HOST_0002 dovecot: lda\(USER_0001\): sieve: msgid=MSGID_0005',
            '': r'HOST_0002 postfix\/pipe\[16434\]: THREAD_0003: to=<RCPT_0001>,',
        }
        for app in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'max_count': 3,
                'patterns' : ['brunato.*'],
                'anonymize': True
            }
            cmdline = u' --anonymize -m 3 -e \'brunato\' -a \'{0}\' {1}'.format(app, u' '.join(args))
            print("--- Test anonymized output feature with '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert re.search(tests[app], out) is not None
