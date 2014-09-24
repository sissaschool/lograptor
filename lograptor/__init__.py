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
from sre_constants import error as RegexpCompileError

from lograptor.application import AppLogParser
from lograptor.configmap import ConfigMap
from lograptor.exceptions import ConfigError, FileMissingError, FormatError, OptionError
from lograptor.logparser import LogParser, RFC3164_Parser, RFC5424_Parser
from lograptor.logmap import LogMap
from lograptor.outmap import OutMap
from lograptor.report import Report
from lograptor.timedate import get_interval, parse_date, parse_last, TimeRange
from lograptor.tui import ProgressBar
from lograptor.utils import set_logger

logger = logging.getLogger('lograptor')

# Map for month field from any admitted representation to numeric.
MONTHMAP = { 'Jan':'01', 'Feb':'02', 'Mar':'03',
             'Apr':'04', 'May':'05', 'Jun':'06',
             'Jul':'07', 'Aug':'08', 'Sep':'09',
             'Oct':'10', 'Nov':'11', 'Dec':'12',
             '01':'01', '02':'02', '03':'03',
             '04':'04', '05':'05', '06':'06',
             '07':'07', '08':'08', '09':'09',
             '10':'10', '11':'11', '12':'12' }

# The RFC5424 no-value
NILVALUE = '-'

# Cleans the thread caches every time you process a certain number of lines.
PURGE_THREADS_LIMIT = 1000


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
            'fromaddr': 'root@{0}'.format(socket.gethostname()),
            'smtpserv': '/usr/sbin/sendmail -t',
            'mapexp': 4,
        },
        'patterns': {
            'rfc3164_pattern': r'^(?:<(?P<pri>[0-9]{1,3})>|)'
                               r'(?P<month>[A-Z,a-z]{3}) (?P<day>(?:[1-3]| )[0-9]) '
                               r'(?P<ltime>[0-9]{2}:[0-9]{2}:[0-9]{2}) '
                               r'(?:last message repeated (?P<repeat>[0-9]{1,3}) times|'
                               r'(?P<host>\S{1,255})\s+'
                               r'(?P<message>(?P<apptag>[^ \[\(\:]{1,32})(?:[\[\(\:])?.*))',
            'rfc5424_pattern': r'^(?:<(?P<pri>[0-9]{1,3})>(?P<ver>[0-9]{0,2}) |)'
                               r'(?:-|(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})T)'
                               r'(?P<ltime>[0-9]{2}:[0-9]{2}:[0-9]{2})(?:|\.(?P<secfrac>[0-9]{1,6}))'
                               r'(?:Z |(?P<offset>(?:\+|-)[0-9]{2}:[0-9]{2}) )'
                               r'(?:-|(?P<host>\S{1,255})) (?:-|(?P<apptag>\S{1,48})) '
                               r'(?:-|(?P<procid>\S{1,128})) (?:-|(?P<msgid>\S{1,32})) '
                               r'(?P<message>.*)',
            'ascii_pattern': r'[\x01-\x7f]*',
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
            'msgid': r'${ascii_pattern}',
        },
        'report': {
            'title': '$host system events: $localtime',
            'html_template': '$cfgdir/report_template.html',
            'text_template': '$cfgdir/report_template.txt',
        },
        'subreports': {
        },
        None: {
            'method': None,
            'formats': 'plain',
            # options for mail publisher sections
            'mailto': 'root',
            'include_rawlogs': False,
            'rawlogs_limit': 200,
            'gpg_encrypt': False,
            'gpg_keyringdir': None,
            'gpg_recipients': None,
            # options for file publisher sections
            'notify': '',
            'pubdir': '/var/www/lograptor',
            'dirmask': '%Y-%b-%d_%a',
            'filemask': '%H%M',
            'save_rawlogs': False,
            'expire_in': 7,
            'pubroot': 'http://localhost/lograptor'
        },
    }

    def __init__(self, cfgfile=None, options=None, defaults=None, args=None, is_batch=False):
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
        #  parsers: cycle iterator of defined LogParser classes
        #  filters: list with passed filter options
        #  hosts: list with host names passed with the option
        #  apps: dictionary with enabled applications
        #  tagmap: dictionary map from syslog tags to apps
        #  _search_flags: flags for re.compile of patterns
        #  rawfh: raw file handler
        #  tmpprefix: location for temporary files
        self.parsers = None
        self.patterns = []
        self.filters = []
        self.hosts = list()
        self.apps = dict()
        self.extra_tags = set()
        self.known_tags = set()
        self.tagmap = dict()
        self._search_flags = re.IGNORECASE if self.config['case'] else 0
        self.rawfh = None
        self.tmpprefix = None
        self.prefix = None
        self.is_batch = is_batch

        # Check and initialize the logger if not already defined. If the program is run by cron-batch
        # and is not a debug loglevel set the logging level to 0 (log only critical messages).
        if self.config['loglevel'] < 0 or self.config['loglevel'] > 4:
            msg = "wrong logging level! (the value of -d parameter must be in [0..4])"
            raise OptionError('-d', msg)

        # Set the logger only if no handler is already defined (from caller method
        # when cfgfile is 4).
        if self.is_batch and self.config['loglevel'] < 4:
            set_logger(0)
        else:
            set_logger(self.config['loglevel'])

        # Check and initialize pattern options. If both options -e and -f options provided
        # exit with error. Try to set the pattern also if neither -e and -f options are provided.
        if self.config['patterns'] is not None and self.config['pattern_file'] is not None:
            msg = "mutually exclusive options!!"
            raise OptionError('-e, -f', msg)

        if self.config['pattern_file'] is not None:
            logger.info('Import search patterns from file "{0}"'.format(self.config['pattern_file']))
            try:
                pattern_file = fileinput.input(self.config['pattern_file'])
                for pattern in pattern_file:
                    pattern = pattern.rstrip('\n')
                    if len(pattern) > 0:
                        logger.info('Import search pattern: {0}'.format(pattern))
                        try:
                            self.patterns.append(re.compile(pattern, self._search_flags))
                        except RegexpCompileError:
                            msg = 'Wrong regex syntax for search pattern!: "%s"'
                            raise OptionError("-f", msg % pattern)
                    else:
                        logger.warning('Skipped an empty search pattern.')
                fileinput.close()
            except IOError:
                raise FileMissingError("Pattern input file \"" + self.config['pattern_file'] + "\" not found!!")
        elif self.config['patterns'] is not None:
            for pattern in self.config['patterns']:
                pattern = pattern.rstrip('\n')
                if len(pattern) > 0:
                    logger.info('Import pattern: {0}'.format(pattern))
                    try:
                        self.patterns.append(re.compile(pattern, self._search_flags))
                    except RegexpCompileError:
                        msg = 'Wrong regex syntax for search pattern!: "%s"'
                        raise OptionError("-e", msg % pattern)
                else:
                    logger.warning('Skipped an empty search pattern.')

        if len(self.patterns) > 0:
            for i in range(len(self.patterns)):
                logger.debug('Search pattern {0}: {1}'.format(i, self.patterns[i].pattern))
        elif self.config['patterns'] or self.config['pattern_file'] is not None:
            logger.warning('Only empty patterns provided: matching all strings.')

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
            msg = "counting mode is incompatible with quiet option!"
            raise OptionError('-c/--count, -q/--quiet', msg)

        # Check -m/--max-count option
        if self.config['max_count'] is not None and self.config['max_count'] <= 0:
            msg = "must be a positive integer!"
            raise OptionError('-m/--max-count', msg)

        # Translate config filter list (-F options)
        if self.config['filters'] is not None:
            if self.config['unparsed'] is True:
                raise OptionError('-F, -u/--unparsed', 'unparsed matching is incompatible with filters!')
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

        # Setting self.print_out_lines and self.print_out_status for processing.
        if self.is_batch:
            logger.info('Batch mode: disabling output and status')
            self.print_out_lines = self.print_out_status = False
        elif self.config['quiet']:
            logger.info('Quiet option provided: disabling output and status')
            self.print_out_lines = False
            self.print_out_status = False
        elif self.config['count']:
            logger.info('Count option provided: disabling output and status')
            self.print_out_lines = False
            self.print_out_status = False
        elif self.filters is None and len(self.patterns) == 0:
            self.print_out_lines = not self.config['report']
            self.print_out_status = self.config['report']
        else:
            self.print_out_lines = True
            self.print_out_status = False

        # Setting the output for filenames:
        #   print_out_filenames == None --> print as header at start of each file processing
        #   print_out_filenames == True --> print as prefix for each matched line (no header)
        #   print_out_filenames == False --> no filename printing
        if self.config['out_filenames'] is not None:
            self.print_out_filenames = bool(self.config['out_filenames'])
        elif len(args) == 1:
            self.print_out_filenames = False
        else:
            self.print_out_filenames = None

        logger.debug('Output of filenames: {0}'.format(self.print_out_filenames))

        if self.print_out_filenames:
            self.getline = self._get_prefixed_line
        else:
            self.getline = self._get_line

        # Create an output mapping instance only when is asked by options
        if self.config['anonymize'] or self.config['uid_lookup'] or self.config['ip_lookup']:
            self.outmap = OutMap(self.config)
        else:
            self.outmap = None

        # Check incompatibilities of -A option
        if self.config['apps'] is None:
            if self.config['report']:
                raise OptionError('-A, -r/--report', 'applications processing is needed for report making!')
            if self.config['publish'] is not None:
                raise OptionError('-A, --publish', 'applications processing is needed for report making!')
            if self.config['unparsed'] is True:
                raise OptionError('-A, --unparsed', 'unparsed matching require applications processing!')
            if self.filters:
                raise OptionError('-A, -F', 'filtering require applications processing!')
            if self.config['thread']:
                raise OptionError('-A, --thread', 'thread matching require applications processing!')
            if not args:
                raise OptionError('-A', 'no-application mode require file arguments!')

        # Set the host re objects
        hostset = set(re.split('\s*,\s*', self.config['hosts'].strip()))
        for host in hostset:
            self.hosts.append(re.compile(fnmatch.translate(host)))
        if hostset:
            logger.debug('Process hosts: {0}'.format(hostset))

        # Initalize app parser class and load applications. After applications
        # reassign configuration parameter with the effecti
        if self.config['apps'] is not None:
            AppLogParser.set_options(self.config, self.filters, self.outmap)
            self._load_applications()

        # Initialize the report object if the option is enabled
        if self.config['report'] is not None:
            self.report = Report(self.patterns, self.apps, self.config)

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

        # Set the parsers iterator with admitted formats.
        # TODO: Extend with other syslog formats using base LogParser class
        parsers = [RFC3164_Parser(self.config['rfc3164_pattern']),
                   RFC5424_Parser(self.config['rfc5424_pattern'])]
        self.parsers = itertools.cycle(parsers)
        self._num_parsers = len(parsers)
        self._parser = next(self.parsers)

        # Set class instance variables for processing
        self._count = self.config['count']
        self._max_count = self.config['max_count'] if not self.config['quiet'] else 1
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

    def _get_line(self, line):
        return line

    def _get_prefixed_line(self, line):
        return '{0}: {1}'.format(self.prefix, line)

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
                raise ConfigError("No app configuration found")
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

        # If filters then reduce the app set to the ones with at least a filter.
        if self.config['filters'] is not None:
            if all([not app.has_filters for key, app in self.apps.items()]):
                msg = 'No app\'s rules compatible with provided filters!'
                raise OptionError("-F", msg)
            for app in self.apps.keys():
                if not self.apps[app].has_filters:
                    del self.apps[app]

        # Set the configuration paramater to the effective list of apps.
        self.config['apps'] = u', '.join([appname for appname in self.apps])

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

        # Set the known_tags dictionary final checks of extra_tags
        self.known_tags = set(self.tagmap.keys())
        for app in self.get_applist():
            if app in self.applist:
                continue

            cfgfile = os.path.join(self.appscfgdir, "".join([app, ".conf"]))
            try:
                unused_app = AppLogParser(app, cfgfile, self.config)
            except (OptionError, ConfigError, FormatError) as err:
                logger.debug('Skip misconfigured app "{0}": {1}'.format(app, err))
                continue
            for tag in set(re.split('\s*,\s*', unused_app.tags)):
                if len(tag) != 0:
                    logger.debug('Add "{0}" to known tags ...'.format(tag))
                    self.known_tags.add(tag)
        logger.debug("Known app's tags: {0}".format(self.known_tags))

        # Exit if no app-name is provided
        if len(self.tagmap) == 0:
            raise ConfigError('No tags for enabled apps! Exiting ...')

        logger.info('Use the applist: {0}'.format(self.apps.keys()))

    def get_configuration(self):
        """
        Return a formatted text with main configuration parameters.
        """
        # Create a dummy report object if necessary
        if not hasattr(self, 'report'):
            self.report = Report(self.patterns, self.apps, self.config, True)
        publishers = self.config.get_all_publishers()
        return u'\n'.join([
            u"\n--- {0} configuration ---".format(self.__class__.__name__),
            u"Configuration main file: {0}".format(self.config['cfgfile']),
            u"Configuration directory: {0}".format(self.config['cfgdir']),
            u"Enabled applications: {0}".format(', '.join(self.apps.keys())),
            u"Disabled applications: {0}".format(', '.join([
                app for app in self.get_applist() if app not in self.apps])),
            u"Available filters: {0}".format(', '.join([
                opt for opt in self.config.options('filters')])),
            u"Report HTML template file: {0}".format(self.config['html_template']),
            u"Report plain text template file: {0}".format(self.config['text_template']),
            u"Subreports: {0}".format(', '.join([
                subreport.name for subreport in self.report.subreports])),
            u"Report publishers: \n    {0}\n".format('\n    '.join([
                repr(pub) for pub in publishers])) if publishers else u'No publisher configured\n',
            ])

    def get_run_summary(self, run_stats):
        """
        Produce a summary from run statistics.

        :return: Formatted multiline string
        """
        tot_counter = run_stats['tot_counter']
        tot_files = run_stats['tot_files']
        tot_lines = run_stats['tot_lines']
        tot_unparsed = run_stats['tot_unparsed']
        unknown_tags = run_stats['unknown_tags']
        summary = u'\n--- {0} run summary ---'.format(self.__class__.__name__)
        if not self._has_args:
            summary = '{0}\nNumber of processed files: {1}'.format(summary, tot_files)
        summary = u'{0}\nTotal lines read: {1}'.format(summary, tot_lines)
        summary = u'{0}\nTotal log events matched: {1}'.format(summary, tot_counter)
        if not self._debug and tot_unparsed > 0:
            summary = u'{0}\nWARNING: Found {1} unparsed log header lines'.format(summary, tot_unparsed)
        if self._useapps:
            if any([ app.counter > 0 for app in self.apps.values() ]):
                proc_apps = [ app for app in self.apps.values() if app.counter > 0 ]
                summary = u'{0}\nTotal log events for apps: {1}'.format(summary, u', '.join([
                    u'%s(%d)' % (app.name, app.counter)
                    for app in proc_apps
                ]))

                if len(proc_apps) == 1 and self._count:
                    rule_counters = dict()
                    for rule in proc_apps[0].rules:
                        rule_counters[rule.name] = sum( [ val for val in rule.results.values() ] )
                    summary = u'{0}\nApp rules counters: {1}'.format(
                        summary,
                        u', '.join([
                            u'{0}({1})'.format(rule, rule_counters[rule])
                            for rule in sorted(rule_counters, key=lambda x: rule_counters[x], reverse=True)
                        ]))
            if unknown_tags:
                summary = u'{0}\nFound unknown app\'s tags: {1}'.format(summary, u', '.join(unknown_tags))

            if any([ app.unparsed_counter > 0 for app in self.apps.values() ]):
                summary = u'{0}\nFound unparsed log lines for apps: {1}'.format(summary, u', '.join([
                    u'%s(%d)' % (app.name, app.unparsed_counter)
                    for app in self.apps.values() if app.unparsed_counter > 0
                ]))
        return summary

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
        print_out_filenames = self.print_out_filenames
        print_out_header = self.print_out_status or \
                           (self.print_out_lines and print_out_filenames is None)
        process_logfile = self.process_logfile
        tot_files = tot_lines = tot_counter = tot_unparsed = 0
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

            if print_out_header:
                print('\n*** Filename: {0} ***'.format(logfile))
            if self.rawfh is not None and print_out_filenames is None:
                self.rawfh.write('\n*** Filename: {0} ***\n'.format(logfile))

            # When process CLI paths use the ordered list of apps instead of "*"
            if applist[0] == "*" and self._useapps:
                applist = self.applist

            try:
                logfile = fileinput.input(logfile, openhook=fileinput.hook_compressed)
                num_files, counter, unparsed_counter, extra_tags = process_logfile(logfile, applist)

                logfiles.append(logfile.filename())

                tot_files += num_files
                tot_lines += logfile.lineno()
                tot_counter += counter
                tot_unparsed += unparsed_counter
                self.extra_tags = self.extra_tags.union(extra_tags)

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
            raise FileMissingError("No file found in the date-time interval [{0}, {1}]!!"
                                   .format(self.ini_datetime, self.fin_datetime))

        logger.info('Total files processed: {0}'.format(tot_files))
        logger.info('Total log lines processed: {0}'.format(tot_lines))

        # Save run stats
        try:
            starttime = datetime.datetime.fromtimestamp(self._first_event)
            endtime = datetime.datetime.fromtimestamp(self._last_event)
        except TypeError:
            starttime = endtime = "None"

        run_stats = {
            'starttime': starttime,
            'endtime': endtime,
            'tot_counter': tot_counter,
            'tot_files': tot_files,
            'tot_lines': tot_lines,
            'tot_unparsed': tot_unparsed,
            'logfiles': ', '.join(logfiles),
            'unknown_tags': set([ tag for tag in self.extra_tags if tag not in self.known_tags ]),
        }

        # If final report is requested then purge all unmatched threads and set time stamps.
        # Otherwise print a final run summary if messages are not disabled.
        if make_report:
            self.report.set_stats(run_stats)
            if self.rawfh is not None:
                self.rawfh.close()
        elif not config['no_messages'] and not config['quiet']:
            print(u'%s\n' % self.get_run_summary(run_stats))

        return tot_counter > 0

    def process_logfile(self, logfile, applist):
        """
        Process a single log file.

        Variables:
          prev_result: Record previous line result to process "last message
                       repeat N times" lines;
        """

        # Load names to local variables to speed-up the run
        logparser = self._parser
        header_gids = logparser.parser.groupindex
        parsers = self.parsers
        num_parsers = self._num_parsers
        outmap = self.outmap
        outstatus = self.print_out_status
        debug = self._debug
        tagmap = self.tagmap
        max_count = self._max_count
        apps = self.apps
        rawfh = self.rawfh
        useapps = self._useapps
        regex_hosts = self.hosts
        patterns = self.patterns
        thread = self._thread
        print_out_lines = self.print_out_lines
        config = self.config
        invert = config['invert']
        match_unparsed = config['unparsed']
        make_report = config['report']
        timerange = config['timerange']

        # Other local variables for the file lines iteration
        fstat = None
        prev_data = None
        app = None
        app_thread = None
        hostlist = []
        counter = 0
        unparsed_counter = 0
        num_files = 0

        readsize = 0
        progressbar = None
        pattern_search = False
        filter_match = False
        extra_tags = set()

        ini_datetime = time.mktime(self.ini_datetime.timetuple())
        fin_datetime = time.mktime(self.fin_datetime.timetuple())
        first_event = self._first_event
        last_event = self._last_event

        all_hosts_flag = config.is_default('hosts')

        for line in logfile:

            ###
            # Set counters and status
            filelineno = logfile.filelineno()
            if filelineno == 1:
                num_files += 1
                if self.print_out_filenames:
                    self.prefix = logfile.filename
                fstat = os.fstat(logfile.fileno())
                file_mtime = datetime.datetime.fromtimestamp(fstat.st_mtime)
                file_year = file_mtime.year
                file_month = file_mtime.month
                prev_year = file_year - 1 
            
                if outstatus and not debug:
                    progressbar = ProgressBar(sys.stdout, fstat.st_size, "lines parsed")
                    readsize = len(line)
                    progressbar.redraw(readsize, filelineno)
            else:
                if outstatus and not debug:
                    readsize += len(line)
                    progressbar.redraw(readsize, filelineno)

            ###
            # Parses the log line. If the regular expression of the parser doesn't match
            # the log line (result=None) changes the active log parser, trying the different
            # parsers configured.
            header_match = logparser.match(line)

            if header_match is None:
                if debug:
                    logger.debug("Change log parser")
                for i in range(num_parsers):
                    nextparser = parsers.next()
                    if i != num_parsers:
                        header_match = nextparser.match(line)
                        if header_match is not None:
                            logparser = nextparser
                            header_gids = logparser.parser.groupindex
                            break
                else:
                    unparsed_counter += 1
                    if debug:
                        logger.debug('Unparsable log line: {0}'.format(line))
                        break
                    continue

            # Extract log data tuple from named matching groups
            logdata = logparser.LogData(*map(header_match.group, logparser.fields))
            if debug:
                logger.debug(logdata)

            ###
            # Process first RFC 3164 'last message repeated N times' log lines
            repeat = getattr(logdata, 'repeat', None)
            if repeat is not None:
                repeat = int(repeat)
                if prev_data is not None:
                    if debug:
                        logger.debug('Repetition: {0}'.format(line[:-1]))
                    apptag = prev_data.apptag
                    app = tagmap[apptag]
                    counter += repeat
                    app.increase_last(repeat)
                    app.counter += 1
                    if app_thread is not None:
                        app.cache.add_line(self.getline(line), app_thread,
                                           pattern_search, filter_match, event_time)
                    prev_data = None
                elif app is not None:
                    app.counter += 1
                continue
            prev_data = logdata

            ###
            # Get and check timestamp. Converts log's timestamp into a value from Epoch to
            # increase the speed of comparisons. Skip lines not included in date/time ranges.
            month = int(MONTHMAP[logdata.month])
            day = int(logdata.day)
            ltime = logdata.ltime
            hour = int(ltime[:2])
            minute = int(ltime[3:5])
            second = int(ltime[6:])
            year = int(getattr(
                logdata, 'year', prev_year if month != 1 and file_month == 1 else file_year
                ))

            event_time = time.mktime((year, month, day, hour, minute, second, 0, 0, -1))

            # Skip the lines older than the initial datetime
            if event_time < ini_datetime:
                if debug:
                    logger.debug('Skip older line: {0}'.format(line[:-1]))
                prev_data = None
                continue

            # Skip the rest of the file if the event is newer than the final datetime
            if event_time > fin_datetime:
                if fstat.st_mtime < event_time:
                    logger.error('Date-time inconsistency in comparison to the last '
                                 'modification of the file: {0}'.format(line[:-1]))
                if debug:
                    logger.debug('Newer line, skip the rest of the file: {0}'.format(line[:-1]))
                prev_data = None
                break

            # Skip the lines not in timerange (if the option is provided).
            if timerange is not None and not timerange.between(ltime):
                if debug:
                    logger.debug('Skip line not in timerange: {0}'.format(line[:-1]))
                prev_data = None
                continue

            ###
            # Check the hostname. If log line format don't
            # include host information, the host is None and consider the line as matched.
            host = getattr(logdata, 'host', None)
            if not all_hosts_flag and host is not None and not host in hostlist:
                for regex in regex_hosts:
                    if regex.search(host) is not None:
                        hostlist.append(host)
                        break
                else:
                    if debug:
                        logger.debug('Skip the line of not selected hosts'.format(line[:-1]))
                    prev_data = None
                    continue

            ###
            # Get the app-tag related to the log line. Then get the app from the tag, if any.
            # Skip the lines not related to the selected apps.
            if useapps:
                apptag = getattr(logdata, 'apptag', None)
                if apptag is not None:
                    # Try the exact match
                    if apptag not in tagmap:
                        # Try the partial match
                        for tag in tagmap:
                            if apptag.startswith(tag):
                                app = tagmap[tag]
                                break
                        else:
                            #Tag unmatched, skip the line
                            extra_tags.add(apptag)
                            prev_data = None
                            if debug:
                                logger.debug('Skip line of another application ({0})'.format(apptag))
                            continue
                    else:
                        app = tagmap[apptag]
                else:
                    app = logparser.app
                app.counter += 1


            ###
            # Process the message part of the log line. First search for provided pattern(s)
            # then process with app rules if the app processing is enabled.
            pattern_search = True
            if patterns:
                for regexp in patterns:
                    pattern_match = regexp.search(logdata.message)
                    if (pattern_match is not None and not invert) or \
                       (pattern_match is None and invert):
                        break
                else:
                    if not thread:
                        if debug:
                            logger.debug('Unmatched line: {0}'.format(line[:-1]))
                        prev_data = None
                        continue
                    pattern_search = False
            elif invert:
                if not thread:
                    if debug:
                        logger.debug('Unmatched line: {0}'.format(line[:-1]))
                    prev_data = None
                    continue
                pattern_search = False

            # Log message parsing with app's rules
            if useapps and pattern_search:
                rule_match, filter_match, app_thread, map_dict = app.process(logdata)
                if not rule_match:
                    # Log message unparsable by app rules
                    if not match_unparsed:
                        if pattern_search and debug:
                            logger.debug('Unparsable line: {0}'.format(line[:-1]))
                        prev_data = None
                        continue
                    if map_dict is not None:
                        line = outmap.map2str(header_gids, header_match, map_dict)
                elif match_unparsed:
                    # Log message parsed but match_unparsed option
                    prev_data = None
                    continue
                elif app_thread is not None:
                    if map_dict is not None:
                        line = outmap.map2str(header_gids, header_match, map_dict)
                    app.cache.add_line(self.getline(line), app_thread,
                                       pattern_search, filter_match, event_time)
                elif not filter_match and app.has_filters:
                    if pattern_search and debug:
                        print('Filtered line: {0}'.format(line[:-1]))
                    prev_data = None
                    continue
                elif map_dict is not None:
                    line = outmap.map2str(header_gids, header_match, map_dict)

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
            # Increment counters and send to output. Purge thread every
            # PURGE_THREADS_LIMIT processed lines.
            if thread:
                if (filelineno % PURGE_THREADS_LIMIT) == 0:
                    for app in applist:
                        apps[app].purge_unmatched_threads(event_time)
                        counter += apps[app].cache.flush_old_cache(event_time, print_out_lines)
            else:
                counter += 1
                if debug:
                    logger.debug('Matched line: {0}'.format(line[:-1]))
                if print_out_lines:
                    print(self.getline(line), end='')

            # Write line to raw file if provided by option
            if rawfh is not None:
                rawfh.write(self.getline(line))

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
                counter += apps[app].cache.flush_cache(event_time, print_out_lines)

        # Save modificable class variables
        self._parser = logparser
        if make_report:
            self._first_event = first_event
            self._last_event = last_event
        return num_files, counter, unparsed_counter, extra_tags

    def make_report(self):
        """
        Create the report based on the results of Lograptor run
        """
        if not self.config['report']:
            return False

        if self.report.make():

            if self.config['publish'] is None:
                formats = ['plain']
            else:
                formats = set()
                for publisher in self.report.publishers:
                    formats = formats.union(publisher.formats)
            logger.debug('Creating report formats: {0}'.format(formats))
            self.report.make_formats(formats)
            return True
        return False

    def publish_report(self):
        """
        Publish the report
        """
        self.report.publish(self.apps, self.rawfh)

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
