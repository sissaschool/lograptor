"""
This module contain core classes and methods for Lograptor package.
"""
##
# Copyright (C) 2011-2012 by SISSA
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
import sys
import itertools
import fnmatch

import lograptor.configmap
import lograptor.application
import lograptor.logheader
import lograptor.logmap
import lograptor.timedate
import lograptor.utils
import lograptor.report
import lograptor.tui

__author__ = "Davide Brunato"
__copyright__ = "Copyright 2011-2012, SISSA"
__credits__ = ["Davide Brunato"]
__license__ = "GPLv2+"
__version__ = "Lograptor-0.8.1"
__maintainer__ = "Davide Brunato"
__email__ = "brunato@sissa.it"
__status__ = "Production"
__description__ = """Command-line utility for searching into 
log files. Produces matching outputs and reports.
"""

logger = logging.getLogger('lograptor')

###############################################
# Lograptor module exceptions
###############################################

class FormatError(Exception):
    """
    This exception is raised when there are errors with the
    format of syslog file processed.
    """
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!FormatError: {0}'.format(message))

class ConfigError(Exception):
    """
    This exception is raised when there are errors in a configuration
    file or when there are misconfiguration problems.
    """
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!ConfigError: {0}'.format(message))


class OptionError(Exception):
    """
    This exception is raised when there is a wrong option values or
    when there are conflicts between options.
    """
    def __init__(self, option, message=None):
        if message is None:
            message = 'syntax error for option "{0}"'.format(option)
        else:
            message = 'option "{0}": {1}'.format(option,message)
        Exception.__init__(self, message)
        logger.debug('!OptionError: {0}'.format(message))


class FileMissingError(Exception):
    """
    This exception is raised when a file is missing.
    """
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!FileMissingError: {0}'.format(message))


class FileAccessError(Exception):
    """
    This exception is raised when Lograptor has problem to access to a file.
    """
    def __init__(self, message):
        Exception.__init__(self, message)
        logger.debug('!FileAccessError: {0}'.format(message))


###############################################
# Lograptor main class
###############################################

class Lograptor:
    """
    This is the main class of Lograptor package.
      - options: contains options. Should be passed with an object (optparse)
        or with a dictionary. Absent options are overrided by defaults, with
        the exception of option 'loglevel' that is required for debugging;
      - args: List with almost one search path and filename paths.
    """            

    # List of options that define filters
    filter_options = tuple(['user', 'from', 'rcpt', 'client', 'pid'])

    def __init__(self, cfgfile=None, options=None, args=[]):
        """
        Initialize parameters for lograptor instance and load apps configurations.
        """            

        # Check arguments. For optional pattern and pathnames (args) checks if are passed
        # with a list. For options try to use them as a dictionary or a class instance.
        if not isinstance(args, list):
            raise FormatError('Argument "args" must be a list!!')

        # Create the lograptor configuration instance, setting configuration from file
        # and options from passed argument.
        try:
            self.config = configmap.ConfigMap(cfgfile, options)
        except IOError as e:
            logger.critical('Configuration file {0} missing or not accessible!'.format(cfgfile))
            logger.critical(e)
            raise FileMissingError('Abort "{0}" for previous errors'.format(__name__))
        
        # Instance attributes:
        #  headers: cycle iterator of defined header classes
        #  filters: dictionary with passed filter options
        #  hosts: list with host names passed with the option
        #  apps: dictionary with enabled applications
        #  tagmap: dictionary map from syslog tags to apps
        #  unparsed: list of unparsed lines
        #  _search_flags: flags for re.compile of patterns
        #  rawfh: raw file handler
        #  tmpprefix: location for temporary files
        self.headers = None
        self.filters = dict()
        self.hosts = list()
        self.apps = dict()
        self.tagmap = dict()
        self.unparsed = list()
        self._search_flags = re.IGNORECASE if self.config['case'] else 0
        self.rawfh = None
        self.tmpprefix = None
        
        # Check and initialize the logger if not already defined. If the program is run
        # by cron and is not a debug loglevel set the logging level to 0 (log only critical messages).
        if (self.config['loglevel'] < 0 or self.config['loglevel'] > 4):
            msg = "wrong logging level! (the value of -d parameter must be in [0..4])"
            raise OptionError('-d', msg)

        # Set the logger only if no handler is already defined (from caller method
        # when loglevel is 4).
        if self.config['cron'] and self.config['loglevel'] < 4:
            lograptor.utils.set_logger(0)
        else:
            lograptor.utils.set_logger(self.config['loglevel'])

        # Check and initialize pattern options. If both options -e and -f options provided
        # exit with error. Try to set the pattern also if neither -e and -f options are provided.
        if self.config['pattern'] is not None and self.config['pattern_file'] is not None:
            msg ="mutually exclusive options!!"
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
                    raise OptionError('-e, -f', "you must provide a pattern!")

            if self.config['pattern'] is None or len(self.config['pattern']) == 0:
                self.patterns = []
            else:
                self.patterns = [re.compile(self.config['pattern'], self._search_flags)]

        if len(self.patterns) > 0:
            for i in range(len(self.patterns)):
                logger.debug('Search pattern {0}: {1}'.format(i, self.patterns[i].pattern))
        else:
            logger.warning('Empty pattern(s) provided: matching all strings')

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

        # Check and initialize date interval to consider. Only one option between --last,
        # and --date should be provided. 
        if ( self.config['last'] is not None and self.config['date'] is not None):
            msg = "mutually exclusive options!"
            raise OptionError('--last, --date', msg)

        if self.config['date'] is not None:
            logger.debug('Option --date: {0}'.format(self.config['date']))
            try:
                self.ini_datetime, self.fin_datetime = timedate.parse_date(self.config['date'])
            except TypeError:
                raise OptionError('--date')
            except ValueError as msg:
                raise OptionError('--date', msg)
                
        else:
            if self.config['last'] is not None:
                logger.debug('Option --last: {0}'.format(self.config['last']))    
                try:
                    diff = timedate.parse_last(self.config['last'])
                except TypeError:
                    raise OptionError('--last')
            elif len(args) == 0:
                logger.info("No --date/--last provided. Consider last 24h.") 
                diff = 86400    # 24h = 86400 seconds 
            else:
                logger.info("No --date/--last provided with args: use Epoch as initial datetime.") 
                diff = int(time.time())
                
            now = int(time.time())
            self.fin_datetime = datetime.datetime.fromtimestamp(now + 3600) # 1h advance for open log files
            self.ini_datetime = datetime.datetime.fromtimestamp(now - diff)
            del now,diff
        
        logger.info('Datetime interval to process: ({0}, {1})'.format(self.ini_datetime, self.fin_datetime))    

        # Check the -T/--time-range option 
        if self.config['timerange'] is not None:
            logger.debug('Option --tr/--time-range: {0}'.format(self.config['timerange']))    
            try:                
                self.config['timerange'] = timedate.TimeRange(self.config['timerange'])
            except ValueError:
                msg = "format error!! Use: --tr=HH:MM,HH:MM"
                raise OptionError('--tr/--time-range', msg)

        # Check --count and --quiet options 
        if self.config['count'] and self.config['quiet']:
            msg = "mutually exclusive options!"
            raise OptionError('-c/--count, -q/--quiet', msg)

        # Check -r and -R options 
        if self.config['report'] and self.config['format'] is not None:
            msg = "mutually exclusive options!"
            raise OptionError('-r, -R/--report', msg)

        # Check and adjust the report options
        if self.config['format'] is not None:
            self.config['format'] = self.config['format'].lower()
            if not self.config['format'] in ['csv', 'html', 'plain']:
                msg = "value must be 'csv', 'html' or 'plain'"
                raise OptionError('-R/--report', msg)
            self.config['report'] = True

        # Check filters 
        for key in self.filter_options:
            if not self.config.is_default(key):
                self.filters[key] = False
        logger.info("Provided filters: {0}".format(self.filters.keys()))
                
        # Setting self.output and self.outstatus options for processing.
        # If --cron option is provided the output and the progress status are disabled.
        # The output is disabled if --quiet is specified: in this case an output of
        # status is produced olny if report is enabled. If --count is provided the
        # output is only a total of matchings for each file.
        # The last case is a configuration error (the application is called
        # without a scope). The fourth case is the classical grep output (
        # output of matching lines).
        if self.config['cron']:
            utils.cron_lock(self.config['pidfile'])
            logger.info('Cron mode: disabling output and status')
            self._output = self._outstatus = False
            self.config['report'] = True
            if self.config['format'] is None:
                self.config['format'] = 'html'
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
        elif not self.filters and len(self.patterns)==0:
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
        if self.config['noapps']:
            if self.config['applications'] is not None:
                msg = "mutually exclusive options!"
                raise OptionError('-A/--no-apps, -a/--app', msg)
            if self.config['report']:
                raise OptionError('-A/--no-apps', 'incompatible with report')
            if self.filters:
                raise OptionError('-A/--no-apps', 'incompatible with filters')
            if self.config['thread']:
                raise OptionError('-A/--no-apps', 'incompatible with thread option')
            if not args:
                raise OptionError('-A/--no-apps', 'no file provided')

        # Set the headers iterator.
        # TODO: extend with modules for other formats
        headers = [lograptor.logheader.RFC3164_Header(self.config['rfc3164_pattern']),
                   lograptor.logheader.RFC5424_Header(self.config['rfc5424_pattern'])]
        self.headers = itertools.cycle(headers)    
        self._num_headers = len(headers)
        self._header = next(self.headers)

        # Set the host re objects
        hostset = set(re.split('\s*,\s*', self.config['hostnames'].strip()))
        for host in hostset:
            self.hosts.append(re.compile(fnmatch.translate(host)))
        if hostset:
            logger.debug('Process hosts: {0}'.format(hostset))
            
        # Load and init applications and check filters usage        
        if not self.config['noapps']:
            application.AppLogParser.set_options(self.config, self.filters)
            self._load_applications()

            for opt in self.filters:
                if not self.filters[opt]:
                    msg = 'The filter --{0} is not used by any application'
                    logger.warning(msg.format(opt))

        # Initialize the report object if the option is enabled
        if self.config['report']:
            self.report = report.Report(self.apps, self.config)

        # Create and configure the log base object, with the list of files to scan.
        # If a list of path is passed as argument, use it and ignore the <files>
        # settings in the apps configurations. The for cycle initialize the
        # regexp objects for specific patterns of enabled apps. At the end
        # set an ordered-by-priority list of enabled apps.
        logger.info('Configure log base iterator')
        self.logmap = logmap.LogMap(self.ini_datetime, self.fin_datetime)
        if len(args) > 0:
            self.logmap.add("*", args)
        else:
            for key in self.apps:                
                app = self.apps[key]
                self.logmap.add(app.name, app.files, app.priority)

    def _load_applications(self):
        """
        Read apps configurations from files. If no explicit apps (-a parameter)
        provided get the list from conf.d dir. An app is disabled for missing
        files or errors or for esplicit option in configuration file. Apps passed
        with -a parameter are enabled, ignoring the setting of the configuration
        file. Almost one app must be enabled to run.
        """
        logger.debug('Reading apps configurations ...')
        appscfgdir = os.path.join(self.config['cfgdir'], 'conf.d')
        logger.debug('appscfgdir={0}'.format(appscfgdir))

        if not os.path.isdir(appscfgdir):
            raise ConfigError('conf.d not found in "{0}"'.format(appscfgdir))

        # Determine the application list
        if self.config['applications'] is None:
            appset = []
            logger.info('Get the applications from conf.d directory ...')
            for filename in os.listdir(appscfgdir):
                cfgfile = os.path.join(appscfgdir, filename)
                if not os.path.isfile(cfgfile) or cfgfile[-5:] != '.conf':
                    logger.debug('Not a config file: {0}'.format(cfgfile))
                    continue
                logger.info('Found application config file: {0}'.format(cfgfile))
                appset.append(filename[0:-5])
            if not appset:
                raise ConfigError("No application configuration found")
        else:
            appset = list(set(re.split('\s*,\s*', self.config['applications'].strip())))
            if not appset:
                raise ConfigError("-a parameter provides an empty set of applications")

        # Load applications's configurations
        logger.debug('Load app set: {0}'.format(appset))
        for app in appset:
            cfgfile = os.path.join(appscfgdir, "".join([app,".conf"]))
            if not os.path.isfile(cfgfile):
                logger.error('Skip app "{0}": no configuration file!!'.format(app))
                continue
            
            try:
                self.apps[app] = application.AppLogParser(app, cfgfile, self.config)
            except (ConfigError, FormatError) as err:
                logger.error('Skip app "{0}": {1}'.format(app, err))
                continue
            except OptionError as err:
                if self.config['applications'] is not None:
                    logger.error('Skip app "{0}": {1}'.format(app, err))
                else:
                    logger.warning('Skip app "{0}": {1}'.format(app, err))
                continue

            if not self.apps[app].enabled:
                logger.info('Skip app "{0}": not enabled'.format(app))
                del self.apps[app]

        # Exit if no application is enabled
        if not self.apps:
            raise ConfigError('No application configured and enabled! Exiting ...')

        # Set the list of apps, ordered by (priority, name)
        self.applist = sorted(self.apps, key=lambda x:(self.apps[x].priority,x))

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

        # Partially disable (enable=None) apps that have no rules or filters,
        # in order to skip app processing and reporting. 
        for key,app in self.apps.items():
            if not app.rules:
                logger.warning('No rules for app "{0}": disable processing/report '
                             'for this app'.format(key))
                app.enabled = None

    def process(self):
        """
        Log processing main routine. Iterate over the defined LogBase instance,
        calling the processing routine for each logfile.
        """

        logger.info('Start the log processing main routine ...')

        # Local variables
        apps = self.apps
        config = self.config
        _output = self._output
        _out_filenames = self._out_filenames
        _outstatus = self._outstatus
        _process_logfile = self._process_logfile
        tot_files = tot_lines = tot_counter = 0
        logfiles = []
        
        # Class instance internal variables for processing
        self._count = config['count']
        self._counter = 0
        self._first_event = self._last_event = None
        self._debug = (config['loglevel'] == 4)
        self._thread = config['thread']
        self._useapps = not config['noapps']

        # Set unparsed lines counter at max value if report is requested
        # and '-u/--unparsed' option is passed.
        if config['report'] and config['unparsed']:
            self._include_unparsed = config['max_unparsed']
        else:
            self._include_unparsed = 0

        # Create temporary file for matches rawlog
        if config['format'] is not None and self.report.need_rawlogs():
            self.mktempdir()
            self.rawfh = tempfile.NamedTemporaryFile(mode='w+', delete=False)
            logger.info('RAW strings file created in "{0}"'.format(self.rawfh.name))
        
        # Iter between log files. The iteration use the log files modified between the
        # initial and the final date, skipping the other files.
        for (logfile, applist) in self.logmap:
            self._num_files = self._num_lines = 0
            
            logger.info('Process log {0} for apps {1}.'.format(logfile, applist))
            
            if ((_output and _out_filenames is None) or _outstatus):
                print('\n*** Filename: {0} ***'.format(logfile))
            if self.rawfh is not None and _out_filenames is None:
                self.rawfh.write('\n*** Filename: {0} ***\n'.format(logfile))
            
            # When process CLI paths use the ordered list of apps instead of "*"
            if applist[0] == "*" and self._useapps:
                applist = self.applist

            try:
                logfile = fileinput.input(logfile, openhook=fileinput.hook_compressed)
                _process_logfile(logfile, applist)
            except IOError as msg:    
                if not config['no_messages']:
                    logger.error(msg)

            logfiles.append(logfile.filename())
                    
            logger.info('Processed {0} files.'.format(self._num_files))            
            tot_files += self._num_files
            tot_lines += logfile.lineno()
            tot_counter += self._counter

            if self._thread:
                for app in applist:
                    try:
                        apps[app].purge_unmatched_threads()
                    except UnboundLocalError:
                        break

            # If option count is enabled print number of
            # matching lines for each file.
            if self._count:
                print('{0}: {1}'.format(logfile.filename(), self._counter))
  
            logfile.close()

        if tot_files==0:
            raise FileMissingError("\nNo file found in the datetime interval [{0},{1}]!!"
                                   .format(self.ini_datetime, self.fin_datetime))

        logger.info('Total files processed: {0}'.format(tot_files))
        logger.info('Total log lines processed: {0}'.format(tot_lines))

        # Final report processing: purge all unmatched threads and set time stamps
        if self.config['report']:
            try:
                starttime = datetime.datetime.fromtimestamp(self._first_event)
                endtime = datetime.datetime.fromtimestamp(self._last_event)
            except TypeError:
                starttime = endtime = "None"
                
            self.report.set_stats(
                {
                    'starttime'  : starttime,
                    'endtime'    : endtime,
                    'totalfiles' : tot_files,
                    'totallines' : tot_lines,
                    'logfiles'   : ', '.join(logfiles)
                })
            if self.rawfh is not None:
                self.rawfh.close()
        
        return tot_counter>0

    def _process_logfile(self, logfile, applist):
        """
        Process a single log file.
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
        include_unparsed = self._include_unparsed
        unparsed = self.unparsed
        apps = self.apps
        rawfh = self.rawfh
        useapps = self._useapps
        regex_hosts = self.hosts
        patterns = self.patterns
        thread = self._thread
        output = self._output
        invert = self.config['invert']
        report = self.config['report']
        timerange = self.config['timerange']

        # Other local variables for the file lines iteration
        prec_match = None
        debug_fmt = "date,time,repeat,host,tag : {0}-{1}-{2},{3},{4},{5},{6}"

        hostlist = []
        counter = 0
        
        ini_datetime = time.mktime(self.ini_datetime.timetuple())
        fin_datetime = time.mktime(self.fin_datetime.timetuple())
        first_event = self._first_event
        last_event = self._last_event

        all_hosts_flag = self.config.is_default('hostnames')
        prefout = ''
        
        for line in logfile:
            
            # Counters and status
            filelineno = logfile.filelineno()
            if filelineno == 1:
                self._num_files += 1
                prefout = '{0}: '.format(logfile.filename()) if self._out_filenames else ''

                fstat = os.fstat(logfile.fileno())
                self._header.set_file_mtime(fstat.st_mtime)
                
                if outstatus and not debug:
                    progressbar = tui.ProgressBar(sys.stdout, fstat.st_size, "lines parsed")
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
                if debug: logger.debug("Change header parser")
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

            # Skip line if the event is older than the initial datetime of the range
            if event_time < ini_datetime:
                if debug: logger.debug('Skip older line: {0}'.format(line[:-1]))
                prec_match = None
                continue

            # Break the cycle if event is newer than final datetime of the range
            if event_time > fin_datetime:
                print("Break", datetime.datetime.fromtimestamp(event_time))
                if debug: logger.debug('Newer line, skip the rest of the file: {0}'.format(line[:-1]))
                prec_match = None
                break

            # Skip line not in timerange, if the option is provided.
            if timerange is not None and not timerange.between(ltime):
                if debug: logger.debug('Skip line not in timerange: {0}'.format(line[:-1]))
                prec_match = None
                continue

            # Process 'last message repeated N times' log line
            if repeat is not None:
                if debug: logger.debug('Repetition: {0}'.format(line[:-1]))
                if prec_match is None:
                    continue
                tag = prec_match.group('tag')
                tagmap[tag].increase_last(repeat)
                prec_match = None
                continue
            
            # Skip lines not related to examined hosts
            if not all_hosts_flag and not host in hostlist:
                for regex in regex_hosts:
                    if regex.search(host) is not None:
                        hostlist.append(host)
                        break
                else:
                    if debug: logger.debug('Skip the line not selected hosts'.format(line[:-1]))
                    prec_match = None
                    continue

            # Skip lines not related to any app (by options or config file)
            if useapps:
                if tag not in tagmap:
                    if debug: logger.debug('Skip line of another application ({0})'.format(tag))
                    prec_match = None
                    continue
                app = tagmap[tag]

            datamsg = match.group(datagid)
            
            ###
            # Search for pattern(s)
            pattern_search = True
            if patterns:
                for regexp in patterns:
                    pattern_match = regexp.search(datamsg)
                    if (pattern_match is not None and not invert) or \
                       (pattern_match is None and invert):
                        break                 
                else:
                    if not thread:
                        if debug: logger.debug('Unmatched line: {0}'.format(line[:-1]))
                        prec_match = None
                        continue
                    pattern_search = False
            elif invert:
                if not thread:
                    if debug: logger.debug('Unmatched line: {0}'.format(line[:-1]))
                    prec_match = None
                    continue
                pattern_search = False
                                    
            ###
            # Application message parsing:
            if useapps:
                result, rule_filters, app_thread = app.process(host, datamsg, debug)

                if result is None:
                    if debug: logger.debug('Unparsable line: {0}'.format(line[:-1]))
                    prec_match = None
                    if include_unparsed > 0:
                        unparsed.append(line)
                        include_unparsed -= 1
                    continue
                elif not result and not thread:
                    if debug: logger.debug('Filtered line: {0}'.format(line[:-1]))
                    prec_match = None
                    continue
                                
                ###
                # Handle timestamps
                if report or thread:
                    if first_event is None:
                        first_event = event_time
                        last_event = event_time
                    else:
                        if first_event > event_time:
                            first_event = event_time
                        if last_event < event_time:
                            last_event = event_time

                if app_thread is not None:
                    app.cache.add_line(line, app_thread, pattern_search, result, rule_filters, event_time)

                prec_match = match
                        

            ###
            # Increment line matched counter 
            if thread:
                if (filelineno % 1000) == 0:
                    for app in applist:
                        apps[app].purge_unmatched_threads(event_time)
                        counter += apps[app].cache.flush_old_cache(output, prefout, event_time)                        
            else:
                counter += 1
                if debug: logger.debug('Matched line: {0}'.format(line[:-1]))
                if output: print('{0}{1}'.format(prefout, line), end='')
                
            if rawfh is not None:
                rawfh.write('{0}{1}'.format(prefout, line))

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
        self._counter = counter
        self._first_event = first_event
        self._last_event = last_event
        self._include_unparsed = include_unparsed
            
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
        Publish the report.
        """
        self.report.publish(self.unparsed, self.rawfh)

    def mktempdir(self):
        """
        Set up a safe temp dir
        """
        logger.info('Setting up a temporary directory')

        tmpdir = self.config['tmpdir']
        logger.debug('tmpdir={0}'.format(tmpdir))
        if tmpdir != "": tempfile.tempdir = tmpdir

        logger.info('Creating a safe temporary directory')
        tmpprefix = tempfile.mkdtemp('.LOGRAPTOR')
        
        try:
            pass
        except:
            msg = 'Could not create a temp directory in "{0}"'.format(tmpprefix)
            raise ConfigError(msg)

        self.tmpprefix   = tmpprefix
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
