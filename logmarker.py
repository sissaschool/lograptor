#!/usr/bin/python
"""
Log timestamp marker utility for Lograptor.
Try `logmarker --help' for more information.
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

try:
    import configparser
except ImportError:
    # Fall back for Python 2.x
    import ConfigParser as configparser

import lograptor.logmap
import lograptor.utils

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
    group.add_option("-n", dest="maxfiles", default=5, type="int",
                     help="Max number or file timestamp marking operations. The default is 5.")

    cli_parser.add_option_group(group)
    return cli_parser.parse_args()


class LogMarker():
    """
    Create a timestamp for a limited number of log files.
    Select files from the ones that hasn't a timestamp yet.
    Limit to a maximum of processed files per running (default=5)
    to not overload the configured TSA with requests.
    """

    # Configuration sections and options to read with defaults.
    # A "None" value means that the option has no default (is required).
    cfgfile_defaults = {
        'main' : {
            'cfgdir': '/etc/lograptor/',
        },
        'tsa_service' : {
            'enabled' : None,
            'hash_algorithm' : 'SHA256',
            'service_url' : None
        }
    }

    def __init__(self, options, args):
        """
        Create the LogMarker instance.
        """

        print(vars(options))
        # Check options values
        parser = configparser.RawConfigParser()
        try:
            parser.read(options.cfgfile)
        except configparser.ParsingError:
            raise FormatError('Could not parse configuration file {0}'.format(options.cfgfile))
        except IOError as e:
            logger.critical('Configuration file {0} missing or not accessible!'
                            .format(options.cfgfile))
            logger.critical(e)
            raise FileMissingError('Abort "{0}" for previous errors'.format(__name__))

        if (options.loglevel < 0 or options.loglevel > 4):
            msg = u"wrong logging level! (the value of -d parameter must be in [0..4])"
            raise OptionError('-d', msg)

        if (options.maxfiles <= 0):
            msg = u"must be a positive integer!"
            raise OptionError('-n', msg)

        lograptor.utils.set_logger(options.loglevel)

        # Read options from configuration file
        for cfg_section, cfg_options in self.cfgfile_defaults.items():
            for cfg_option, default_value in cfg_options.items():
                try:
                    setattr(self, cfg_option, parser.get(cfg_section, cfg_option))
                except configparser.NoSectionError:
                    raise ConfigError(u"Missing a required section: '{0}'".format(cfg_section))
                except configparser.NoOptionError as e:
                    if default_value is None:
                        raise ConfigError(e)
                    else:
                        setattr(self, cfg_option, default_value)


        # Create log base iterator. If args are provided then consider them
        # as a list of log files to process. Otherwise use all existing app
        # configuration files.
        logger.info('Configure log base iterator')
        self.logmap = logmap.LogMap(self.ini_datetime, self.fin_datetime)
        if len(args) > 0:
            self.logmap.add("*", args)
        else:
            logger.debug('Reading apps configurations ...')

            appscfgdir = os.path.join(self.config['cfgdir'], 'conf.d')
            if not os.path.isdir(appscfgdir):
                raise ConfigError('conf.d not found in "{0}"'.format(self.config['cfgdir']))


            for key in self.apps:
                self.logmap.add(app.name, app.files, app.priority)


def main(options, args):


    # Create the LogMarker class, exiting if there are configurations errors
    try:
        log_marker = LogMarker(options, args)
    except OptionError as e:
        cli_parser.error(e)
    except (ConfigError, FormatError, FileMissingError, FileAccessError) as e:
        sys.exit(e)
    except KeyboardInterrupt:
        print("\nCtrl-C pressed, terminate the process ...")
        sys.exit(0)

    try:
        # Request to TSA for files that have not yet timestamp.
        retval = log_marker.make_timestamps()
    except FileMissingError as e:
        print(e)
        sys.exit(1)
    except Exception as e:
        raise
    except KeyboardInterrupt:
        print("\nCtrl-C pressed, terminate the process ...")
        sys.exit(1)

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
    print(cli_parser.option_list)

    if os.isatty(sys.stdout.fileno()):
        main(options, args)
    else:
        with nostdout():
            main(options, args)


"""
EXAMPLES FOR TIMESTAMPS

    >>> import rfc3161
    >>> certificate = file('data/certum_certificate.crt').read()
    >>> rt = rfc3161.RemoteTimestamper('http://time.certum.pl', certificate=certificate)
    >>> tst = rt.timestamp(data='John Doe')
    >>> tst
    ('...', '')
    >>> rt.check(tst[0], data='John Doe')
    (True, '')
    >>> rfc3161.get_timestamp(tst[0])
    datetime.datetime(2014, 4, 25, 9, 34, 16)



import httplib, urllib
import hashlib

h = hashlib.sha1("dupa").hexdigest()
print "sha=", h
params = urllib.urlencode({'sha1' : h, })
headers = {}
conn = httplib.HTTPConnection('time.certum.pl')
conn.request("POST", "/", params, headers)
response = conn.getresponse()

print response.status, response.reason
data = response.read()
conn.close()

print "tsp=", data.encode('hex')

f = open('response.tsp', 'w')
f.write(data)
f.close()
"""