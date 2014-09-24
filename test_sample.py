#
# Test script for Lograptor.
#
__author__ = 'brunato'

import os
import re
#import pytest

from lograptor import Lograptor

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
    'loglevel': 2,
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

    def run_lograptor(self, options, args):
        """
        Create and run a Lograptor instance in order to make a test.
        """
        run_options = DEFAULT_OPTIONS.copy()
        run_options.update(options)

        if self.cmdheader != 'lograptor':
            run_options['cfgfile'] = u'./lograptor.conf'

        my_raptor = Lograptor(run_options['cfgfile'], options, DEFAULT_OPTIONS, args, is_batch=False)
        retval = my_raptor.process()

        # Publish the report if is requested and it's not empty
        if my_raptor.make_report():
            my_raptor.publish_report()

        return retval


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

    def test_basic_pattern(self, capsys):
        self.set_cmdheader()
        tests = {
            'postfix' : r'\.log: 76\n',
            'dovecot' : r'\.log: 145\n',
        }
        for app in tests:
            args = get_args_for_apps(app)
            options = {
                'apps' : app,
                'count' : True,
                'patterns' : [u'brunato'],
                'no_messages' : True,
            }
            cmdline = u'-e \'brunato\' -s -c -a {0} {1}'.format(app, u' '.join(args))
            print("--- Test basic pattern matching for '{0}' app ---\n".format(app))
            print(u"# {0} {1}".format(self.cmdheader, cmdline))
            retval = self.run_lograptor(options, args)
            out, err = capsys.readouterr()
            print(u"\n{0}".format(out))
            assert retval and re.search(tests[app], out) is not None

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
