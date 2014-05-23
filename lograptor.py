#!/usr/bin/python
"""
Search utility for syslog files written in Python.
Try `lograptor --help' for more information.
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
import contextlib
import errno
import optparse
import os
import sys

from lograptor import (__version__, __description__, Lograptor, ConfigError,
                       OptionError, FormatError, FileMissingError, FileAccessError)

CFGFILE_DEFAULT = '/etc/lograptor/lograptor.conf'

#####################################
# Stdout redirection
#####################################
class DummyFile(object):
    def write(self,x): pass

    def flush(self): pass

@contextlib.contextmanager
def nostdout():
    save_stdout = sys.stdout
    sys.stdout = DummyFile()
    yield
    sys.stdout = save_stdout


#####################################
# Command line options parsing
#####################################
def parse_args(cli_parser):
    """
    Command line options and arguments parsing. This function return
    a list of options and the list of arguments (pattern, filenames).
    """
    
    cli_parser.set_usage(""" %prog [options] [PATTERN] [FILE ...]   
    %prog [options] [ -e PATTERN | -f FILE ] [FILE ...]
    Try `%prog --help' for more information.""")

    ### Define the options for the group "General Options"                      
    group = optparse.OptionGroup(cli_parser, "General Options")
    group.add_option("--conf", dest="cfgfile", type="string",
                     default=CFGFILE_DEFAULT, metavar="<CONFIG_FILE>",
                     help="Provide a different configuration to Lograptor, "
                          "alternative to the default file located in {0}."
                     .format(CFGFILE_DEFAULT))
    group.add_option("-d", dest="loglevel", default=1, type="int", metavar="[0-4]",
                     help="Logging level. The default is 1. Level 0 log only "
                     "critical errors, higher levels show more informations.")
    cli_parser.add_option_group(group)

    ### Define the options for the group "Scope Options"                      
    group = optparse.OptionGroup(cli_parser,"Scope Options")
    group.add_option("-H", "--hosts", metavar="HOST/IP[,HOST/IP...]",
                     action="store", type="string", dest="hosts", default='*',
                     help="Will analyze only log lines related to comma separated list "
                     "of hostnames and/or IP addresses. File path wildcards can be used "
                     "for hostnames.")
    cli_parser.set_defaults(apps='')
    group.add_option('-a', "--apps", metavar='APP[,APP...]',
                     action="store", type="string", dest="apps",
                     help="Analyze only log lines related to a comma separated list of applications. "
                     "An app is valid when a configuration file is defined. For default the program "
                     "process all enabled apps.")
    group.add_option("-A", action="store_const", dest="apps", const=None,
                     help="Skip application processing. The searches are performed only "
                     "with pattern(s) matching. This option is incompatible with report and "
                     "matching options related to app's rules.")
    group.add_option("--last", action="store", type="string", dest="period", default=None,
                     metavar="[hour|day|week|month|Nh|Nd|Nw|Nm]",
                     help="Restrict search scope to a previous time period.")
    group.add_option("--date", metavar="[YYYY]MMDD[,[YYYY]MMDD]",
                     action="store", type="string", dest="period", default=None,
                     help="Restrict search scope to a date or an interval of dates.")
    group.add_option("--time", metavar="HH:MM,HH:MM", action="store",
                     type="string", dest="timerange", default=None,
                     help="Restrict search scope to a time range.")
    cli_parser.add_option_group(group)

    ### Define the options for the group "Matching Control"                      
    group=optparse.OptionGroup(cli_parser,"Matching Control")
    group.add_option("-e", "--regexp", dest="pattern", default=None,
                      help="The search pattern. Useful to specify multiple search "
                      "patterns or to protect a pattern beginning with a hypen (-).")
    group.add_option("-f", "--file", dest="pattern_file", default=None, metavar="FILE",
                      help="Obtain patterns from FILE, one per line.")
    group.add_option("-i", "--ignore-case", action="store_true", dest="case", default=False,
                     help="Ignore case distinctions in matching.")        
    group.add_option("-v", "--invert-match", action="store_true", dest="invert", default=False,
                     help="Invert the sense of matching, to select non-matching lines.")    
    group.add_option("-F", metavar="FILTER=PATTERN[,FILTER=PATTERN...]",
                     action="append", type="string", dest="filters", default=None,
                     help="Refine the search with a comma separated list of app's filters. "
                     "The filter list are applied with logical disjunction (OR). "
                     "Providing more --filter options perform logical conjunction filtering (AND).")
    group.add_option("-t","--thread", dest="thread", action="store_true", default=False,
                     help="Perform matching at application's thread level. "
                     "The thread rules are defined in app's configuration file.")
    group.add_option("-u", "--unparsed", action="store_true", dest="unparsed",
                     default=False, help="Match lines that are unparsable by app's rules. "
                     "Useful for finding anomalies and for application's rules debugging.")
    cli_parser.add_option_group(group)

    ### Define the options for the group "Output Control"
    group=optparse.OptionGroup(cli_parser,"Output Control")
    group.add_option("-c", "--count", action="store_true", default=False,
                    help="Suppress normal output; instead print a count of matching "
                    "lines for each input file.  With  the  -v, --invert-match "
                    "option, count non-matching lines.")
    group.add_option("-m", "--max-count", metavar='NUM',
                     action="store", type="int", dest="max_count", default=None,
                     help="Stop reading a file after NUM matching lines. When the -c "
                     "or --count option is also used, lograptor does not output a "
                     "count greater than NUM.")
    group.add_option("-q", "--quiet", action="store_true", default=None,
                     help="Quiet; do not write anything  to standard output. Exit "
                     "immediately with zero status if any match  is found, even "
                     "if an error was detected. Also see the -s or --no-messages "
                     "option.")
    group.add_option("-s", "--no-messages", action="store_true", default=False,
                     help="Suppress error messages about nonexistent or unreadable files.")
    group.add_option("-o", "--with-filename", action="store_true", dest="out_filenames",
                    default=None, help="Print the filename for each matching line.")        
    group.add_option("-O", "--no-filename", action="store_false", dest="out_filenames",
                     default=None, help="Suppress the default headers with filenames on "
                     "output. This is the default behaviour for output also when "
                     "the search is in only one file.")
    group.add_option("-r", "--report", dest="report", action="store_true", default=False,
                     help="Make a report at the end of processing and display on console.")
    cli_parser.add_option_group(group)

    ### Define the options for the group "Publishing Control"
    group=optparse.OptionGroup(cli_parser,"Publishing Control")
    group.add_option("--publish", dest="publish", default=None,
                     metavar='PUBLISHER[,PUBLISHER...]',
                     help="Make a report and publish it using a comma separated list of "
                     "publishers, "
                     "choosed from the ones defined in the configuration file. You have to "
                     "define your publishers in the main configuration file.")
    group.add_option("--ip", action="store_true", dest="ip_lookup",
                     default=False, help="Do a reverse lookup translation for the IP addresses "
                     "contained in the final report. The lookups use the DNS resolve "
                     "facility of the running host.")
    group.add_option("--uid", action="store_true", dest="uid_lookup",
                     default=False, help="Translate numeric UIDs into corresponding names. "
                     "The local system authentication is used for lookups, therefore its "
                     "configuration must be congruent with the UIDs of the log files.")
    group.add_option("--anonymize", action="store_true", dest="anonymize",
                     default=False, help="Anonymize report UIDs, hostnames and IPs.")
    cli_parser.add_option_group(group)

    return cli_parser.parse_args()


#########################################################################
# Main function: create the Lograptor instance and manages the phases of
# processing calling the main methods in sequence.
##########################################################################
def main(options, args):
    """
    Main routine: create the Lograptor instance, call processing of log
    files and manage exception errors.
    """

    # If a debug level activate logger immediately
    if options.loglevel == 4:    
        import lograptor.utils
        lograptor.utils.set_logger(options.loglevel)
 
    # Create the Lograptor class, exit if there are configuration errors
    try:
        my_raptor = Lograptor(options.cfgfile, options, args)
    except OptionError as e:
        cli_parser.error(e)
    except (ConfigError, FormatError, FileMissingError, FileAccessError) as e:
        sys.exit(e)
    except KeyboardInterrupt:
        print("\nCtrl-C pressed, terminate the process ...")
        my_raptor.cleanup()
        sys.exit(1)

    # Display configuration and exit when the program is called without
    # options and arguments (at limit with only --conf).
    if len(sys.argv) == 1 or ( len(sys.argv)==2 and sys.argv[1].startswith('--conf=')):
        my_raptor.display_configuration()
        my_raptor.cleanup()
        sys.exit(0)
        
    try:
        # Call the log processing method
        retval = my_raptor.process()

        # Publish the report if is requested and it's not empty
        if my_raptor.make_report():
            my_raptor.publish_report()
    except FileMissingError as e:
        print(e)
        my_raptor.cleanup()
        sys.exit(1)
    except Exception as e:        
        my_raptor.cleanup()
        raise
    except KeyboardInterrupt:
        print("\nCtrl-C pressed, terminate the process ...")
        my_raptor.cleanup()
        sys.exit(1)

    # Cleanup (remove temporary files/directories)
    my_raptor.cleanup()
    
    # Return value 0 if there was almost a matching
    sys.exit(0 if retval else 1)


if __name__ == '__main__':
    
    if sys.version_info < (2,6,0):
        sys.stderr.write("You need python 2.6 or later to run this program\n")
        sys.exit(1)
      
    # Get command line options and arguments 
    cli_parser = optparse.OptionParser(version=__version__, description=__description__)
    cli_parser.disable_interspersed_args()
    (options, args) = parse_args(cli_parser)
    
    if os.isatty(sys.stdout.fileno()):
        main(options, args)
    else:
        with nostdout():
            main(options, args)
