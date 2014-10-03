=================
Lograptor command
=================


SYNOPSIS
--------

::

    lograptor [options] [FILE ...]
    lograptor [options] [-e PATTERN | -f PATTERNS_FILE ] [FILE ...]


DESCRIPTION
-----------
Lograptor is a search tool for system logs saved with legacy BSD syslog format (RFC 3164) or
IETF syslog format (RFC 5424).

It's developed as a compact and configurable CLI tool, usable for raw or refined searches and
to create specific or periodic reports on system logs. The application mix classical pattern
matching features with scope parameters and a configurable set of filters.
You can define application filtering rule using the classical regexp syntax.
Lograptor can also produce and publish reports in various formats.
Reporting could be automated using cron.

To understand Lograptor's configuration see `lograptor-conf(5) <lograptor-conf.html>`_.

For more informations on adding and configuring applications see `lograptor-apps(5) <lograptor-apps.html>`_.


OPTIONS
-------

.. option:: --version

    Show program\'s version number and exit.

.. option:: -h, --help

    Show this help message and exit.

General Options
^^^^^^^^^^^^^^^

.. option:: --conf=<CONFIGFILE>

    Provide a different configuration to Lograptor (default is /etc/lograptor/lograptor.conf).
    If you call the program from the command line without options and arguments, or with only
    this option, a summary of configuration settings is dumped to stdout and then the process
    exit successfully.

.. option:: -d [0..4]

    Logging level. The default is 2 (warning). Level 0 log only critical errors, higher
    levels show more informations.

Scope Options:
^^^^^^^^^^^^^^

.. option:: -H HOST[,HOST...], --hosts=HOST[,HOST...]

    Restrict the analysis to log lines related to comma separated
    list of hostnames and/or IP addresses. File path wildcards can be used for hostnames.

.. option:: -a APP[,APP...], --apps=APP[,APP...]

    Analyze only log lines related to a comma separate list of applications.
    An app is valid when a configuration file is defined.
    As default all apps defined and enabled are processed.

.. option:: -A

    Skip applications processing and works only with pattern(s) matching.
    This option is incompatible with report and filtering options.

.. option:: --last=[hour|day|week|month|Nh|Nd|Nw|Nm]

    Restrict search scope to a previous date/time period.

.. option:: --date=[YYYY]MMDD[,[YYYY]MMDD]

    Restrict search scope to a date or an interval of dates.

.. option:: --time=HH:MM,HH:MM

    Restrict search scope to a time range.

Matching Control:
^^^^^^^^^^^^^^^^^

.. option:: -e PATTERN, --regexp=PATTERN

    The search pattern. Use the option more times to specify multiple search patterns.
    Empty patterns are skipped.

.. option:: -f FILE, --file=FILE

    Obtain patterns from FILE, one per line. Empty patterns are skipped.

.. option:: -i, --ignore-case

    Ignore case distinctions in matching.

.. option:: -v, --invert-match

    Invert the sense of matching, to select non-matching lines.

.. option:: -F FILTER=PATTERN[,FILTER=PATTERN...]

    Apply a list of filters to the search. The filters specified within a single
    option are applied with logical conjunction (AND): only the app's rules that
    contain all the filters, as Python regex's named groups, are considered.
    Multiple -F options are used with logical disjunction (OR).

.. option:: -t, --thread

    Perform matching at application's thread level. The thread rules are defined in app's configuration file.

.. option:: -u, --unparsed

    Match only lines that are unparsable by app's rules. This option is useful for
    finding anomalies and for application's rules debugging. This option is incompatible
    with filters (`option -F <lograptor.html#cmdoption-F>`_).

.. option:: --anonymize

    Anonymize output for values connected to provided filters. Translation tables are
    built in volatile memory for each run. The anonymous tokens have the format FILTER_NN.
    This option overrides --ip, --uid.

Output Control:
^^^^^^^^^^^^^^^

.. option:: -c, --count

    Suppress normal output; instead print a count of matching lines for each input file.
    With  the  -v, --invert-match option, count non-matching lines.

.. option:: -m NUM, --max-count=NUM

    Stop reading a file after NUM matching lines. When -c/--count option is also used,
    lograptor does not output a count greater than NUM.
    When using `-t/--thread option <lograptor.html#cmdoption-t>`_ the limit is related
    to the number of threads and not to the number of lines matched.

.. option:: -q, --quiet

    Quiet; do not write anything  to standard output. Exit immediately with zero
    status if any match  is found, even if an error was detected.
    Also see the -s or --no-messages option.

.. option:: -s, --no-messages

    Suppress final run summary and error messages about nonexistent or unreadable files.

.. option:: -o, --with-filename

    Print the filename for each matching line.

.. option:: -O, --no-filename

    Suppress the default headers with filenames on output. This is the default behaviour
    for output also when searching in a single file.

.. option:: --ip

    Do a reverse lookup translation for the IP addresses. Use a DNS local caching
    to improve the speed of the lookups and reduce the network service's load.

.. option:: --uid

    Map numeric UIDs to usernames. The configured local system authentication is
    used for lookups, so it must be inherent to the UIDs that have to be resolved.

Report Control:
^^^^^^^^^^^^^^^

.. option:: -r, --report

    Make a formatted text report at the end of processing and display on console.

.. option:: --publish=PUBLISHER[,PUBLISHER...]

    Make a report and publish it using a comma separated list of publishers.
    You have to define your publishers in the main configuration file to use this option.


FILES
-----

``/etc/lograptor/lograptor.conf``

``/etc/lograptor/conf.d/*.conf``

``/usr/bin/lograptor``


AUTHORS
-------
Davide Brunato <`brunato@sissa.it <mailto:brunato@sissa.it>`_>


SEE ALSO
--------

`lograptor.conf(5) <lograptor-conf.html>`_,
`lograptor-apps(5) <lograptor-apps.html>`_,
`lograptor-examples(5) <lograptor-examples.html>`_,
