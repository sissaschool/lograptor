Use lograptor command
=====================

NAME
----
**lograptor** - Search and reporting tool for syslog files.

SYNOPSIS
--------
**lograptor** [options] [PATTERN] [FILE ...]

**lograptor** [options] [ **-e** PATTERN | **-f** FILE ] [FILE ...]

DESCRIPTION
-----------
Lograptor is a search tool for system logs saved with legacy BSD syslog format
(RFC 3164) or IETF syslog format (RFC 5424).
It is developed as a compact and highly configurable CLI tool for analysis and
reporting of system logs. Lograptor is derived from ideas and partly
from the code of Epylog, merged with older code written by the author for parsing
a Postfix email server logs.

The program mix a classical pattern search as the UNIX command "grep" with
additional filters and parameters, taylored to restrict and retrieve relevant
informations from log files. For example you could restrict a search to an
hostname or to a date. Configurable filters can be applied on message data.
Each application is defined with a configuration file.
Lograptor can also produce reports and publish them in a directory or send
by e-mail. The report may be a general or a specific report taylored for
some accounts/hosts. With cron you could run Lograptor to produce general
reports.

Lograptor log analysis is based on application or device that originated the
message. This reflect the structure of syslog lines, as described in details
by RFC 5424 (see paragraph 6.2.5 APP-NAME).

OPTIONS
-------
**--version** show program's version number and exit

**-h**, **--help** show this help message and exit

General Options
^^^^^^^^^^^^^^^

**--conf**\=FILE
    Provide a different configuration to Lograptor, alternative to
    the default file located in /etc/lograptor/lograptor.conf.
**-d [0-4]**
    Logging level. The default is 1. Level 0 log only critical errors,
    higher levels show more informations.
**--cron**
    Run as a batch/cron job, with no output and enabling reporting, plus it
    will create a lock file that will not allow more than one cron instance
    of lograptor to run.

Scope Options
^^^^^^^^^^^^^
**-H** HOST/IP[,HOST/IP...], **--host**\=HOST/IP[,HOST/IP...]
    Will analyze only log lines related to comma separated list of hostnames and/or IP addresses.
    File path wildcards can be used for hostnames.
**-a** APP[,APP...], **--apps**\=APP[,APP...]
    Will analyze only log lines related to a specific application.
    An application list should be passed between quotes, separated by
    commas or spaces.
**-A**
    Skip application processing. The searches are performed only
    with pattern(s) matching. This option is incompatible with
    report, filtering and thread matching options.
**--last**\=[hour|day|week|month|Nh|Nd|Nw|Nm]
    Will analyze strings from the past [time period] specified.
**\-\-date**\=[YYYY]MMDD[,[YYYY]MMDD]
    Will analyze only log lines related to a date. You should provide a
    date interval, with consecutive dates separated by a comma.
**\-\-time**\=HH:MM,HH:MM
Will analyze only log lines related to a time range.

Matching Control
^^^^^^^^^^^^^^^^
**-e** PATTERN, **--regexp**\=PATTERN
    The search pattern. Useful to protect a pattern beginning with a hypen (-).
**-f** FILE, **--file**\=FILE
    Obtain multiple patterns from FILE, one per line.
**\-i**, **--ignore-case**
    Ignore case distinctions in matching.
**\-v**, **--invert-match**
    Invert the sense of matching, to select non-matching lines.
**-F** FILTER\=PATTERN[,FILTER\=PATTERN...]
    Refine the search with a comma separated list of app's filters.
    The filter list are applied with logical conjunction (AND).
    Providing more --filter options perform logical conjunction filtering (OR).
**-t**, **--thread**
    Perform matching at application's thread level.
    The thread rules are defined in app's configuration file.
**-u**, **--unparsed**
    Match lines that are unparsable by app's rules.
    Useful for finding anomalies and for application's rules debugging.

Output Control
^^^^^^^^^^^^^^
**-c**, **--count**
    Suppress normal output; instead print a count of matching lines
    for each input file. With the -v, --invert-match option,
    count non-matching lines.
**-m** NUM, **--max-count**=NUM
    Stop reading a file after NUM matching lines. When the
    -c or --count option is also used, lograptor does not
    output a count greater than NUM.
**-q**, **--quiet**
    Quiet; do not write anything to standard output. Exit immediately
    with zero status if any match is found, even if an error was
    detected. Also see the -s or --no-messages option.
**-s**, **--no-messages**
    Suppress error messages about nonexistent or unreadable files.
**-o**, **--with-filename**
    Print the filename for each match line, instead print filename ad the
    beginning of file analysis.
**-O**, **--no-filename**
    Don't print filenames at the beginning of each file parsing process. This is the
    default behaviour also when is passed only one file with the arguments.

Report Control
^^^^^^^^^^^^^^
**-r**, **--report**
    Make a report at the end of processing. For default
    the report is dumped as formatted plain text on
    console at the end of log processing. You should
    provide different format and publishing methods using
    --format and --publish options.
**--format**\=[html|csv|pdf]
    Use a different format to publish the report (default
    is formatted plain text).
**--publish**\=PUBLISHER[,PUBLISHER...]
    Publish the report using a comma separated list of
    publishers. A publisher is defined in the configuration file.
**--ip**
    Do a reverse lookup for IP addresses. Nothing is done if the no report is required.
**--uid**
    Translate uids with system interface. Nothing is done if no report is required.

FEATURES
--------
Lograptor is written in python. It is compahandles things like
timestamp lookups, unwrapping of "last message repeated" lines,
handling of rotated files, preparing and publishing the reports, etc.

Lograptor is derived from the ideas and the code of Epylog package and
from a small search utility for email servers logfiles. It was developed
 with python 2.6+ and python 3, in order to be projected for future improvements.

The application are simply a configuration files added in a specific
configuration directory. Application's configuration files containg rules
for log parsing and for composing reports. For more info see
:ref:`lograptor-apps(5)`.

FILES
-----
*/etc/lograptor/lograptor.conf*

*/etc/lograptor/conf.d/\*.conf*

*/usr/bin/lograptor*

EXAMPLES
--------
Basic pattern search
""""""""""""""""""""
Search a pattern in specific log file::

    lograptor "hello" /var/log/messages

Same search but ignoring characters case::

    lograptor -i "hello" /var/log/messages

Search a string in postfix's log files of the last 3 days::

    lograptor --last=3d -a postfix "example.com"

Search of mail sent by an address, with match at connection thread level::

    lograptor -t -F user=user@example.com "" /var/log/maillog

""""""""""""""
Making reports
""""""""""""""
Produce a report on console for application "crond"::

    lograptor -ra crond "" /var/log/cron

The same but produce an HTML report and publish it with default publishers, including unparsed logs::

    lograptor -R html -ua crond "" /var/log/cron
