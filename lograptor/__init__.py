"""
This module contain core classes and methods for Lograptor package.
"""
##
# Copyright (C) 2011-2014 by SISSA and Davide Brunato
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# @Author Davide Brunato <brunato@sissa.it>
##
from __future__ import print_function

import os
import time
import datetime
import re
import logging
import fileinput
import tempfile
import socket
import string
import sys
import itertools
import fnmatch

from lograptor.application import AppLogParser
from lograptor.configmap import ConfigMap
from lograptor.exceptions import ConfigError, FileMissingError, FormatError, OptionError
from lograptor.logheader import RFC3164_Header, RFC5424_Header
from lograptor.logmap import LogMap
from lograptor.report import Report
from lograptor.timedate import get_interval, parse_date, parse_last, TimeRange
from lograptor.tui import ProgressBar
from lograptor.utils import cron_lock, set_logger

logger = logging.getLogger('lograptor')

class Lograptor:
    """
    This is the main class of Lograptor package.
      - options: contains options. Should be passed with an object (optparse)
        or with a dictionary. Absent options are overrided by defaults, with
        the exception of option 'loglevel' that is required for debugging;
      - args: List with almost one search path and filename paths.
    """

    # Lograptor default configuration
    default_config = {
        'main': {
            'cfgdir': '/etc/lograptor/',
            'logdir': '/var/log',
            'tmpdir': '/var/tmp',
            'pidfile': "/var/run/lograptor.pid",
            'fromaddr': 'root@{0}'.format(socket.gethostname()),
            'smtpserv': '/usr/sbin/sendmail -t',
        },
        'patterns': {
            'rfc3164_pattern': r'^(?:<(?P<pri>[0-9]{1,3})>|)'
                               r'(?P<month>[A-Z,a-z]{3}) (?P<day>(?:[1-3]| )[0-9]) '
                               r'(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}) '
                               r'(?:last message repeated (?P<repeat>[0-9]{1,3}) times|'
                               r'(?P<host>\S{1,255}) (?P<datamsg>(?P<tag>[^ \[\(\:]{1,32}).*))',
            'rfc5424_pattern': r'^(?:<(?P<prix>[0-9]{1,3})>(?P<ver>[0-9]{0,2}) |)'
                               r'(?:-|(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T)'
                               r'(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})(?:|\.(?P<secfrac>[0-9]{1,6}))'
                               r'(?:Z |(?P<offset>(?:\+|-)[0-9]{2}:[0-9]{2}) )'
                               r'(?:-|(?P<host>\S{1,255})) (?P<datamsg>(?:-|(?P<tag>\S{1,48})) .*)',
            'ascii_pattern': r'(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|'
                             r'\\[\x01-\x09\x0b\x0c\x0e-\x7f])*',
            'dnsname_pattern': r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*'
                               r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\b',
            'ipv4_pattern': r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
            'ipv6_pattern': r'(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}'
                            r'(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}'
                            r'(?: (?<=::)|(?<!:)|(?<=:) (?<!::) :)|'
                            r'(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)'
                            r'(?: \.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})',
            'username_pattern': r'[A-Za-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&\'*+/=?^_`{|}~-]+)*',
            'email_pattern': r'(?:|${username_pattern}|"${ascii_pattern}")'
                             r'(?:|@(?:${dnsname_pattern}|\[(?:${ipv4_pattern}|${ipv6_pattern})\]))+',
            'id_pattern': r'[0-9]+',
        },
        'filters': {
            'user': r'${username_pattern}',
            'mail': r'${email_pattern}',
            'from': r'${email_pattern}',
            'rcpt': r'${email_pattern}',
            'client': r'(${dnsname_pattern}|${ipv4_pattern}|'
                      r'${dnsname_pattern}\[${ipv4_pattern}\])',
            'pid': r'${id_pattern}',
            'uid': r'${id_pattern}',
        },
        'report': {
            'title': '$hostname system events: $localtime',
            'html_template': '$cfgdir/report_template.html',
            'text_template': '$cfgdir/report_template.txt',
        },
        'subreports': {
            'logins_report': 'Logins',
            'mail_report': 'Message delivery',
            'command_report': 'System commands',
            'query_report': 'Database & directory lookups',
        },
        None: {
            'method': None,
            'notify': '',
            'format': 'plain',
            # options for mail publisher sections
            'mailto': 'root',
            'include_rawlogs': False,
            'rawlogs_limit': 200,
            'gpg_encrypt': False,
            'gpg_keyringdir': None,
            'gpg_recipients': None,
            # options for file publisher sections
            'pubdir': '/var/www/lograptor',
            'dirmask': '%Y-%b-%d_%a',
            'filemask': '%H%M',
            'save_rawlogs': False,
            'expire_in': 7,
            'pubroot': 'http://localhost/lograptor'
        },
    }

    def __init__(self, cfgfile=None, options=None, defaults=None, args=None):
        """
        Initialize parameters for lograptor instance and load apps configurations.
        """

        # Check arguments. For optional pattern and pathnames (args) checks if are passed
        # with a list. For options try to use them as a dictionary or a class instance.
        if args is None:
            args = list()
        elif not isinstance(args, list):
            raise FormatError('Argument "args" must be a list!!')

        # Update default configuration values with provided defaults
        if defaults is not None:
            if not isinstance(defaults, dict):
                raise FormatError('Argument "defaults" must be a dictionary!!')
            self.default_config.update({'options': defaults})

        # Create the lograptor configuration instance, setting configuration from file
        # and options from passed argument.
        try:
            self.config = ConfigMap(cfgfile, self.default_config, options)
        except IOError as e:
            logger.critical('Configuration file {0} missing or not accessible!'.format(cfgfile))
            logger.critical(e)
            raise FileMissingError('Abort "{0}" for previous errors'.format(__name__))

        # Instance attributes:
        #  headers: cycle iterator of defined header classes
        #  filters: list with passed filter options
        #  hosts: list with host names passed with the option
        #  apps: dictionary with enabled applications
        #  tagmap: dictionary map from syslog tags to apps
        #  _search_flags: flags for re.compile of patterns
        #  rawfh: raw file handler
        #  tmpprefix: location for temporary files
        self.headers = None
        self.filters = []
        self.hosts = list()
        self.apps = dict()
        self.tagmap = dict()
        self._search_flags = re.IGNORECASE if self.config['case'] else 0
        self.rawfh = None
        self.tmpprefix = None
        self.cron = not os.isatty(sys.stdin.fileno())

        # Check and initialize the logger if not already defined. If the program is run
        # by cron and is not a debug loglevel set the logging level to 0 (log only critical messages).
        if self.config['loglevel'] < 0 or self.config['loglevel'] > 4:
            msg = "wrong logging level! (the value of -d parameter must be in [0..4])"
            raise OptionError('-d', msg)

        # Set the logger only if no handler is already defined (from caller method
        # when cfgfile is 4).
        if self.cron and self.config['loglevel'] < 4:
            set_logger(0)
        else:
            set_logger(self.config['loglevel'])

        # Check and initialize pattern options. If both options -e and -f options provided
        # exit with error. Try to set the pattern also if neither -e and -f options are provided.
        if self.config['pattern'] is not None and self.config['pattern_file'] is not None:
            msg = "mutually exclusive options!!"
            raise OptionError('-e, -f', msg)

        if self.config['pattern_file'] is not None:
            logger.info('Import search patterns from file "{0}"'.format(self.config['pattern_file']))
            self.patterns = []
            try:
                for pattern in fileinput.input(self.config['pattern_file']):
                    pattern = pattern.rstrip('\n')
                    logger.info('Import pattern: {0}'.format(pattern))
                    if len(pattern) > 0:
                        self.patterns.append(re.compile(pattern, self._search_flags))
                fileinput.close()
            except IOError:
                raise FileMissingError("Pattern input file \"" + self.config['pattern_file'] + "\" not found!!")
        else:
            if self.config['pattern'] is None:
                try:
                    self.config['pattern'] = args.pop(0)
                    logger.info('No option -e or -f provided, use the first argument: "{0}"'
                                .format(self.config['pattern']))
                except IndexError:
                    self.config['pattern'] = ''

            if self.config['pattern'] is None or len(self.config['pattern']) == 0:
                self.patterns = []
            else:
                self.patterns = [re.compile(self.config['pattern'], self._search_flags)]

        if len(self.patterns) > 0:
            for i in range(len(self.patterns)):
                logger.debug('Search pattern {0}: {1}'.format(i, self.patterns[i].pattern))
        else:
            logger.warning('No patterns provided: matching all strings')

        # Check and clear paths from command line args. Skip the directories, deleting them
        # from input arguments. Exit with an error if a file in the list doesn't exist.
        for index in reversed(range(len(args))):
            if os.path.isdir(args[index]):
                msg = '{0} is a directory, removing from argument list ...'
                logger.error(msg.format(args[index]))
                del args[index]
                continue
            if not os.path.isfile(args[index]):
                raise FileMissingError('{0}: No such file or directory'.format(args[index]))

        if args:
            logger.info('Arguments specify {0} files'.format(len(args)))
        else:
            logger.info('No file list by arguments')

        # Check and initialize date interval to consider. Try first to parse option value
        # as previous time period. If it fails then try to parse as a date.
        period = self.config['period']
        if period is None or period.strip() == '':
            if len(args) > 0 and period is None:
                diff = int(time.time())
                logger.info("No --date/--last provided with args: use Epoch as initial datetime.")
            else:
                diff = 86400    # 24h = 86400 seconds
            self.fin_datetime, self.ini_datetime = \
                get_interval(int(time.time()), diff, 3600)
        else:
            try:
                diff = parse_last(period)
                logger.debug('Option --last: {0}'.format(period))
                self.fin_datetime, self.ini_datetime = \
                    get_interval(int(time.time()), diff, 3600)
            except TypeError:
                try:
                    self.ini_datetime, self.fin_datetime = parse_date(period)
                    logger.debug('Option --date: {0}'.format(period))
                except TypeError:
                    raise OptionError('--date/--last')
                except ValueError as msg:
                    raise OptionError('--date', msg)
        logger.info('Datetime interval to process: ({0}, {1})'.format(self.ini_datetime, self.fin_datetime))

        # Check the -T/--time-range option
        if self.config['timerange'] is not None:
            logger.debug('Option --tr/--time-range: {0}'.format(self.config['timerange']))
            try:
                self.config['timerange'] = TimeRange(self.config['timerange'])
            except ValueError:
                msg = "format error!! Use: --tr=HH:MM,HH:MM"
                raise OptionError('--tr/--time-range', msg)

        # Check --count and --quiet options
        if self.config['count'] and self.config['quiet']:
            msg = "mutually exclusive options!"
            raise OptionError('-c/--count, -q/--quiet', msg)

        # Check -m/--max-count option
        if self.config['max_count'] is not None and self.config['max_count'] <= 0:
            msg = "must be a positive integer!"
            raise OptionError('-m/--max-count', msg)

        # Translate config filter list (-F options)
        if self.config['filters'] is not None:
            for item in self.config['filters']:
                self.filters.append(dict())
                for flt in item.split(','):
                    try:
                        key, value = map(string.strip, flt.split('=', 1))
                        if key.lower() not in self.config.options('filters'):
                            raise OptionError('-F', 'filter \'%s\': not a filter!' % key)
                        key = key.lower()
                        self.filters[-1][key] = value.strip('\'"')
                    except ValueError:
                        raise OptionError('-F', 'filter \'%s\': wrong format!' % flt)
                continue
            logger.debug("Provided filters: {0}".format(self.filters))

        # Setting self.output and self.outstatus options for processing.
        # If the process is a cron-batch the output and the progress status are disabled.
        # The output is disabled also if --quiet is specified: in this case an output of
        # status is produced olny if report is enabled. If --count is provided the
        # output is only a total of matchings for each file.
        # The last case is a configuration error (the application is called
        # without a scope). The fourth case is the classical grep output (
        # output of matching lines).
        if self.cron:
            cron_lock(self.config['pidfile'])
            logger.info('Cron mode: disabling output and status')
            self._output = self._outstatus = False
        elif self.config['quiet'] and self.config['report']:
            logger.info('Quiet option provided: disabling output')
            self._output = False
            self._outstatus = True
        elif self.config['quiet']:
            logger.info('Quiet option provided: disabling output and status')
            self._output = False
            self._outstatus = False
        elif self.config['count']:
            logger.info('Count option provided: disabling output and status')
            self._output = False
            self._outstatus = False
        elif self.filters is None and len(self.patterns) == 0:
            self._output = not self.config['report']
            self._outstatus = self.config['report']
        else:
            self._output = True
            self._outstatus = False

        # Setting the output for filenames:
        #   out_filenames == None --> print only as header
        #   out_filenames == True --> print at each line (no header)
        #   out_filenames == False --> no filename printing
        #
        # If no specific options is provided (options.out_filenames==None)
        # set to self._out_filenames=False if only one CLI file by argument is
        # provided (remember that wildcard name expansion is applied on
        # filenames passed by CLI args).
        if self.config['out_filenames'] is not None:
            self._out_filenames = bool(self.config['out_filenames'])
        elif len(args) == 1:
            self._out_filenames = False
        else:
            self._out_filenames = None

        logger.debug('Set the output of filenames to: {0}'.format(self._out_filenames))

        # Check incompatibilities of -A option
        if self.config['apps'] is None:
            if self.config['report']:
                raise OptionError('-A', 'incompatible with report')
            if self.config['unparsed'] is not None:
                raise OptionError('-A', 'incompatible with unparsed matching')
            if self.filters:
                raise OptionError('-A', 'incompatible with filters')
            if self.config['thread']:
                raise OptionError('-A', 'incompatible with thread matching')
            if not args:
                raise OptionError('-A', 'missing file arguments! (Nothing to process ...)')

        # Set the headers iterator.
        # TODO: extend with modules for other formats
        headers = [RFC3164_Header(self.config['rfc3164_pattern']),
                   RFC5424_Header(self.config['rfc5424_pattern'])]
        self.headers = itertools.cycle(headers)
        self._num_headers = len(headers)
        self._header = next(self.headers)

        # Set the host re objects
        hostset = set(re.split('\s*,\s*', self.config['hosts'].strip()))
        for host in hostset:
            self.hosts.append(re.compile(fnmatch.translate(host)))
        if hostset:
            logger.debug('Process hosts: {0}'.format(hostset))

        # Initalize app parser class and load applications. After applications
        # reassign configuration parameter with the effecti
        if self.config['apps'] is not None:
            AppLogParser.set_options(self.config, self.filters)
            self._load_applications()
            if self.config['filters'] is not None:
                if all([not app.has_filters for key, app in self.apps.items()]):
                    msg = 'No app\'s rules compatible with provided filters!'
                    raise OptionError("-F", msg)
                self.config['apps'] = u', '.join([
                    appname for appname, app in self.apps.items() if app.has_filters
                ])
            else:
                self.config['apps'] = u', '.join([appname for appname in self.apps])

        # Partially disable (enable=None) apps that have no rules or filters,
        # in order to skip app processing and reporting.

        # Initialize the report object if the option is enabled
        if self.config['report'] is not None:
            self.report = Report(self.apps, self.config)

        # Create and configure the log base object, with the list of files to scan.
        # If a list of path is passed as argument, use it and ignore the <files>
        # settings in the apps configurations. The for cycle initialize the
        # regexp objects for specific patterns of enabled apps. At the end
        # set an ordered-by-priority list of enabled apps.
        logger.info('Configure log base iterator')
        self.logmap = LogMap(self.ini_datetime, self.fin_datetime)
        if len(args) > 0:
            self.logmap.add("*", args)
        else:
            for key in self.apps:
                app = self.apps[key]
                self.logmap.add(app.name, app.files, app.priority)

        # Set class instance variables for processing
        self._count = self.config['count']
        self._max_count = self.config['max_count']
        self._first_event = self._last_event = None
        self._debug = (self.config['loglevel'] == 4)
        self._thread = self.config['thread']
        self._useapps = self.config['apps'] is not None
        self._has_args = len(args) > 0

    def get_applist(self):
        """
        Return the list of defined applications. Don't make config checks, simply
        return .conf files in 'conf.d' subdirectory.
        """
        applist = []
        appscfgdir = self.appscfgdir
        for filename in os.listdir(appscfgdir):
            cfgfile = os.path.join(appscfgdir, filename)
            if not os.path.isfile(cfgfile) or cfgfile[-5:] != '.conf':
                logger.debug('Not a config file: {0}'.format(cfgfile))
                continue
            applist.append(filename[0:-5])
        return applist

    def _load_applications(self):
        """
        Read apps configurations from files. If no explicit apps (-a parameter)
        provided get the list from conf.d dir. An app is disabled for missing
        files or errors or for esplicit option in configuration file. Apps passed
        with -a parameter are enabled, ignoring the setting of the configuration
        file. Almost one app must be enabled to run.
        """
        logger.debug('Reading apps configurations ...')
        self.appscfgdir = os.path.join(self.config['cfgdir'], 'conf.d')
        if not os.path.isdir(self.appscfgdir):
            raise ConfigError('conf.d not found in "{0}"'.format(self.config['cfgdir']))

        # Determine the application list
        if self.config['apps'] == '':
            logger.info('Get the applications from conf.d directory ...')
            appset = self.get_applist()
            if not appset:
                raise ConfigError("No application configuration found")
            else:
                logger.info('Found apps: {0}'.format(appset))
        else:
            appset = list(set(re.split('\s*,\s*', self.config['apps'].strip())))
            if not appset:
                raise ConfigError("--apps option has not valid app names")

        # Load applications's configurations
        logger.debug('Load app set: {0}'.format(appset))
        for app in appset:
            cfgfile = os.path.join(self.appscfgdir, "".join([app, ".conf"]))
            if not os.path.isfile(cfgfile):
                logger.error('Skip app "{0}": no configuration file!!'.format(app))
                continue

            try:
                self.apps[app] = AppLogParser(app, cfgfile, self.config)
            except (ConfigError, FormatError) as err:
                logger.error('Skip app "{0}": {1}'.format(app, err))
                continue
            except OptionError as err:
                if self.config['apps'] != '':
                    logger.error('Skip app "{0}": {1}'.format(app, err))
                else:
                    logger.warning('Skip app "{0}": {1}'.format(app, err))
                continue

            if not self.apps[app].enabled:
                logger.info('Skip app "{0}": not enabled'.format(app))
                del self.apps[app]
                continue

            if not self.apps[app].rules:
                logger.warning('Skip app "{0}": no rules defined!'.format(app))
                del self.apps[app]
                continue

        # Exit if no application is enabled
        if not self.apps:
            raise ConfigError('No application configured and enabled! Exiting ...')

        # Set the list of apps, ordered by (priority, name)
        self.applist = sorted(self.apps, key=lambda x: (self.apps[x].priority, x))

        # Set the tagmap dictionary for mapping syslog app-name --> app
        for app in self.applist:
            logger.info('Adding "{0}" tags to tagmap dictionary'.format(app))
            for tag in set(re.split('\s*,\s*', self.apps[app].tags)):
                if tag in self.tagmap:
                    logger.error('Skip app "0": duplicate tag "{1}"'
                                 .format(app, tag))
                    del self.apps[app]
                    break
                if len(tag) == 0:
                    logger.error('Skip empty tag for app "{0}"'.format(app))
                else:
                    logger.info('Add "{0}" to tagmap ...'.format(tag))
                    self.tagmap[tag] = self.apps[app]

        # Exit if no app-name is provided
        if len(self.tagmap) == 0:
            raise ConfigError('No tags for enabled apps! Exiting ...')

        logger.info('Use the applist: {0}'.format(self.apps.keys()))

    def display_configuration(self):
        """
        Display the instance configuration to stdout.
        """
        print("---------------------------\n"
              "| {0} configuration |\n"
              "---------------------------".format(self.__class__.__name__))
        print("Configuration main file: {0}".format(self.config['cfgfile']))
        print("Configuration directory: {0}".format(self.config['cfgdir']))
        print("Enabled applications: {0}".format(', '.join(self.apps.keys())))
        print("Disabled applications: {0}".format(', '.join([
            app for app in self.get_applist() if app not in self.apps])))
        print("Available filters: {0}".format(', '.join([
            opt for opt in self.config.options('filters')])))
        print("Report HTML template file: {0}".format(self.config['html_template']))
        print("Report plain text template file: {0}".format(self.config['text_template']))
        self.report = Report(self.apps, self.config)
        print("Subreports: {0}".format(', '.join([
            subreport.name for subreport in self.report.subreports])))
        print("Report publishers: {0}".format(', '.join([
            pub[:-10] for pub in self.config.parser.sections()
            if pub.endswith('_publisher')])))

    def process(self):
        """
        Log processing main routine. Iterate over the defined LogBase instance,
        calling the processing routine for each logfile.
        """

        logger.info('Start the log processing main routine ...')

        # Local variables
        apps = self.apps
        config = self.config
        make_report = self.config['report']
        _output = self._output
        _out_filenames = self._out_filenames
        _outstatus = self._outstatus
        process_logfile = self.process_logfile
        tot_files = tot_lines = tot_counter = 0
        logfiles = []

        # Create temporary file for matches rawlog
        if make_report and self.report.need_rawlogs():
            self.mktempdir()
            self.rawfh = tempfile.NamedTemporaryFile(mode='w+', delete=False)
            logger.info('RAW strings file created in "{0}"'.format(self.rawfh.name))

        # Iter between log files. The iteration use the log files modified between the
        # initial and the final date, skipping the other files.
        for (logfile, applist) in self.logmap:
            logger.info('Process log {0} for apps {1}.'.format(logfile, applist))

            if _outstatus or (_output and _out_filenames is None):
                print('\n*** Filename: {0} ***'.format(logfile))
            if self.rawfh is not None and _out_filenames is None:
                self.rawfh.write('\n*** Filename: {0} ***\n'.format(logfile))

            # When process CLI paths use the ordered list of apps instead of "*"
            if applist[0] == "*" and self._useapps:
                applist = self.applist

            try:
                logfile = fileinput.input(logfile, openhook=fileinput.hook_compressed)
                num_files, counter = process_logfile(logfile, applist)

                logfiles.append(logfile.filename())

                tot_files += num_files
                tot_lines += logfile.lineno()
                tot_counter += counter

                if self._thread:
                    for app in applist:
                        try:
                            apps[app].purge_unmatched_threads()
                        except UnboundLocalError:
                            break

                # If option count is enabled print number of
                # matching lines for each file.
                if self._count:
                    print('{0}: {1}'.format(logfile.filename(), counter))

            except IOError as msg:
                if not config['no_messages']:
                    logger.error(msg)

            logfile.close()

        if tot_files == 0:
            raise FileMissingError("\nNo file found in the datetime interval [{0}, {1}]!!"
                                   .format(self.ini_datetime, self.fin_datetime))

        logger.info('Total files processed: {0}'.format(tot_files))
        logger.info('Total log lines processed: {0}'.format(tot_lines))

        # Final report processing: purge all unmatched threads and set time stamps
        if make_report:
            try:
                starttime = datetime.datetime.fromtimestamp(self._first_event)
                endtime = datetime.datetime.fromtimestamp(self._last_event)
            except TypeError:
                starttime = endtime = "None"

            self.report.set_stats(
                {
                    'starttime': starttime,
                    'endtime': endtime,
                    'totalfiles': tot_files,
                    'totallines': tot_lines,
                    'logfiles': ', '.join(logfiles)
                })
            if self.rawfh is not None:
                self.rawfh.close()

        return tot_counter > 0

    def process_logfile(self, logfile, applist):
        """
        Process a single log file.

        Variables:
          prev_match: Record previous match to process "last message
                      repeat N times" lines;
        """

        # Load names to local variables to speed-up the run
        header = self._header
        parser = header.parser
        extract = header.extract
        datagid = header.datagid
        headers = self.headers
        num_headers = self._num_headers
        outstatus = self._outstatus
        debug = self._debug
        tagmap = self.tagmap
        max_count = self._max_count
        apps = self.apps
        rawfh = self.rawfh
        useapps = self._useapps
        regex_hosts = self.hosts
        patterns = self.patterns
        thread = self._thread
        output = self._output
        config = self.config
        invert = config['invert']
        match_unparsed = config['unparsed']
        make_report = config['report']
        timerange = config['timerange']

        # Other local variables for the file lines iteration
        fstat = None
        prev_match = None
        app_thread = None
        debug_fmt = "date,time,repeat,host,tag : {0}-{1}-{2},{3},{4},{5},{6}"

        hostlist = []
        counter = 0
        num_files = 0

        readsize = 0
        progressbar = None
        pattern_search = False
        filter_match = False

        ini_datetime = time.mktime(self.ini_datetime.timetuple())
        fin_datetime = time.mktime(self.fin_datetime.timetuple())
        first_event = self._first_event
        last_event = self._last_event

        all_hosts_flag = config.is_default('hosts')
        prefout = ''

        for line in logfile:

            # Counters and status
            filelineno = logfile.filelineno()
            if filelineno == 1:
                num_files += 1
                prefout = '{0}: '.format(logfile.filename()) if self._out_filenames else ''

                fstat = os.fstat(logfile.fileno())
                self._header.set_file_mtime(fstat.st_mtime)

                if outstatus and not debug:
                    progressbar = ProgressBar(sys.stdout, fstat.st_size, "lines parsed")
                    readsize = len(line)
                    progressbar.redraw(readsize, filelineno)
            else:
                if outstatus and not debug:
                    readsize += len(line)
                    progressbar.redraw(readsize, filelineno)

            ###
            # Header matching
            match = parser.search(line)

            if match is None:
                if debug:
                    logger.debug("Change header parser")
                for i in range(num_headers):
                    nextheader = headers.next()
                    if i != num_headers:
                        match = nextheader.parser.search(line)
                        if match is not None:
                            header = nextheader
                            parser = nextheader.parser
                            extract = nextheader.extract
                            datagid = nextheader.datagid
                            break
                else:
                    logger.warning('Unparsable log header: {0}'.format(line))
                    break

            # Extract values from matching object
            pri, ver, year, month, day, ltime, offset, secfrac, repeat, host, tag = extract(match)
            if debug:
                logger.debug(debug_fmt.format(year, month, day, ltime, repeat, host, tag))

            # Converts event time into a timestamp from Epoch to speed-up comparisons
            hour = ltime[:2]
            minute = ltime[3:5]
            second = ltime[6:]
            event_time = time.mktime((int(year), int(month), int(day),
                                      int(hour), int(minute), int(second),
                                      0, 0, -1))

            # Process first 'last message repeated N times' log line only
            # according to the previous match, to avoid oversights.
            if repeat is not None:
                if prev_match is not None:
                    if debug:
                        logger.debug('Repetition: {0}'.format(line[:-1]))
                    tag = prev_match.group('tag')
                    app = tagmap[tag]
                    app.increase_last(repeat)
                    if app_thread is not None:
                        app.cache.add_line(line, app_thread, pattern_search, filter_match, event_time)
                    prev_match = None
                continue
            prev_match = None

            # Skip line if the event is older than the initial datetime of the range
            if event_time < ini_datetime:
                if debug:
                    logger.debug('Skip older line: {0}'.format(line[:-1]))
                continue

            # Break the cycle if event is newer than final datetime of the range
            if event_time > fin_datetime:
                if fstat.st_mtime < event_time:
                    logger.error('Date-time inconsistency in comparison to the last '
                                 'modification of the file: {0}'.format(line[:-1]))
                if debug:
                    logger.debug('Newer line, skip the rest of the file: {0}'.format(line[:-1]))
                break

            # Skip line not in timerange, when option is provided.
            if timerange is not None and not timerange.between(ltime):
                if debug:
                    logger.debug('Skip line not in timerange: {0}'.format(line[:-1]))
                continue

            # Skip lines not related to examined hosts
            if not all_hosts_flag and not host in hostlist:
                for regex in regex_hosts:
                    if regex.search(host) is not None:
                        hostlist.append(host)
                        break
                else:
                    if debug:
                        logger.debug('Skip the line of not selected hosts'.format(line[:-1]))
                    continue

            # Skip lines not related to enabled apps, provided by option
            # or by configuration
            if useapps:
                if tag not in tagmap:
                    if debug:
                        logger.debug('Skip line of another application ({0})'.format(tag))
                    continue
                app = tagmap[tag]

            datamsg = match.group(datagid)

            # Search for provided pattern(s)
            pattern_search = True
            if patterns:
                for regexp in patterns:
                    pattern_match = regexp.search(datamsg)
                    if (pattern_match is not None and not invert) or \
                       (pattern_match is None and invert):
                        break
                else:
                    if not thread:
                        if debug:
                            logger.debug('Unmatched line: {0}'.format(line[:-1]))
                        continue
                    pattern_search = False
            elif invert:
                if not thread:
                    if debug:
                        logger.debug('Unmatched line: {0}'.format(line[:-1]))
                    continue
                pattern_search = False

            # Log message parsing (with config app's rules)
            if useapps and pattern_search:
                result, filter_match, app_thread, groupdict = app.process(host, datamsg, debug)
                if not result:
                    # Log message unparsable by app rules
                    if not match_unparsed:
                        if pattern_search and debug:
                            logger.debug('Unparsable line: {0}'.format(line[:-1]))
                        continue
                elif match_unparsed:
                    # Log message parsed but match_unparsed option
                    continue
                elif app_thread is not None:
                    app.cache.add_line(line, app_thread, pattern_search, filter_match, event_time)
                elif not filter_match and app.has_filters:
                    if pattern_search and debug:
                        print('Filtered line: {0}'.format(line[:-1]))
                    continue

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

            # Record current matching in case the next line is "last message repeat..."
            if pattern_search:
                prev_match = match

            # Increment counters and no threaded output
            if thread:
                if (filelineno % 1000) == 0:
                    for app in applist:
                        apps[app].purge_unmatched_threads(event_time)
                        counter += apps[app].cache.flush_old_cache(output, prefout, event_time)
            else:
                counter += 1
                if debug:
                    logger.debug('Matched line: {0}'.format(line[:-1]))
                if output:
                    print('{0}{1}'.format(prefout, line), end='')

            # Write line to raw file if provided by option
            if rawfh is not None:
                rawfh.write('{0}{1}'.format(prefout, line))

            # Stops iteration if max_count matchings is exceeded
            if max_count is not None and counter >= max_count:
                break

        # End-of file thread matching and output
        if thread:
            for app in applist:
                try:
                    apps[app].purge_unmatched_threads(event_time)
                except UnboundLocalError:
                    break
                counter += apps[app].cache.flush_cache(output, prefout, event_time)

        # Save modificable class variables
        self._header = header
        if make_report:
            self._first_event = first_event
            self._last_event = last_event
        return num_files, counter

    def make_report(self):
        """
        Create the report based on the result of Lograptor run
        """
        if not self.config['report']:
            return False

        if self.report.make():
            self.report.make_format(self.config['format'])
            return True
        return False

    def publish_report(self):
        """
        Publish the report
        """
        self.report.publish(self.rawfh)

    def mktempdir(self):
        """
        Set up a safe temp dir
        """
        logger.info('Setting up a temporary directory')

        tmpdir = self.config['tmpdir']
        logger.debug('tmpdir={0}'.format(tmpdir))
        if tmpdir != "":
            tempfile.tempdir = tmpdir
        logger.info('Creating a safe temporary directory')
        tmpprefix = tempfile.mkdtemp('.LOGRAPTOR')

        try:
            pass
        except:
            msg = 'Could not create a temp directory in "{0}"'.format(tmpprefix)
            raise ConfigError(msg)

        self.tmpprefix = tmpprefix
        tempfile.tempdir = tmpprefix

        logger.info('Temporary directory created in "{0}"'.format(tmpprefix))

    def cleanup(self):
        """
        Clean up after ourselves.
        """
        logger.info('Cleanup routine called')

        if self.rawfh is not None:
            print("Close rawlogs file ...")
            self.rawfh.close()

        if self.tmpprefix is not None:
            from shutil import rmtree

            logger.info('Removing the temp dir "{0}"'.format(self.tmpprefix))
            rmtree(self.tmpprefix)
