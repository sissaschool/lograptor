=====================
The lograptor command
=====================


********
SYNOPSIS
********

::

    lograptor [options] [FILE ...]
    lograptor [options] [-e PATTERN | -f PATTERNS_FILE ] [FILE ...]


***********
DESCRIPTION
***********

lograptor is a search tool for system logs saved with legacy BSD syslog format (RFC 3164)
or IETF syslog format (RFC 5424).

It's developed as a compact and configurable GREP-like tool, usable for raw or refined
searches and to create customizable reports on system logs. The application mixes regex pattern
matching search with scope delimiters and a configurable set of filters.
You can configure additional application pattern rules using the classical regexp syntax.
lograptor can also produce and publish reports in various formats.
Reporting can be automated using cron.

For lograptor's configuration see `lograptor-conf(5) <lograptor-conf.html>`_.

For more information on adding and configuring applications see `lograptor-apps(5) <lograptor-apps.html>`_.


*******
OPTIONS
*******

Positional Arguments
--------------------

.. option:: [FILE ...]

    Input files. Each argument can be a file path or a glob pathname. A "-" stands
    for standard input. If no arguments are given then processes all the files
    included within the scope of the selected applications.

General Options
---------------

.. option:: --conf FILE

    Use a specific configuration file. For default try to find and use a *lograptor.conf*
    file located in the current directory, in the *~/.config/lograptor/* directory, in the
    *~/.local/etc/lograptor/* directory or in the */etc/lograptor/* directory.
    If you call the program from the command line without other options and arguments a
    summary of configuration settings is dumped to stdout.

.. option:: -d [0-4]

    Logging level (default is 2, use 4 for debug). A level of 0 suppress also error messages
    about nonexistent or unreadable files.

.. option:: -V, --version

    Show program's version number and exit.

.. option:: --help

    Show an help page about program options and exit.


Scope Selection
---------------

.. option:: -a APP[,APP...], --apps APP[,APP...]

    Process the log lines related to an application. An app name is valid when a
    configuration file is defined. For default all apps defined and enabled are processed.

.. option:: --hosts HOSTNAME/IP[,HOSTNAME/IP...]

    Process the log lines related to a comma separated list of hostnames and/or IP addresses.
    File path wildcards can be used for hostnames.

.. option:: -F FIELD=PATTERN[,FIELD=PATTERN...], --filter FIELD=PATTERN[,FIELD=PATTERN...]

    Process the log lines that match all the conditions for pattern rule's field values.
    The filters within a single option are applied with logical conjunction (AND).
    Multiple -F options are used with logical disjunction (OR).

.. option:: --time HH:MM,HH:MM

    Process the log lines related to a time range.

.. option:: --date [YYYY]MMDD[,[YYYY]MMDD]

    Restrict the search scope to a date or a date interval.

.. option:: --last [hour|day|week|month|Nh|Nd|Nw|Nm]

    Restrict the search scope to a previous time period.


Matcher Selection
-----------------

.. option:: -G, --ruled

    Use patterns and application rules matching. This is the default.

.. option:: -X, --unruled

    Use patterns only. Application pattern rules are skipped.
    This option is incompatible with report and filtering options.

.. option:: -U, --unparsed

    Match the patterns but select the lines that don't match any application rule.
    This option is useful for finding anomalies and for application's rules debugging.
    This option is incompatible with filters (`option -F <lograptor.html#cmdoption-F>`_).


Matching Control
----------------

.. option:: -e PATTERN, --regexp=PATTERN

    The search pattern. Use the option more times to specify multiple search patterns.
    Empty patterns are skipped.

.. option:: -f FILE, --file=FILE

    Obtain patterns from FILE, one per line. Blank lines are skipped. If this option is
    used multiple times or is combined with the -e (--regexp) option, search for all
    patterns given. An empty file contains zero patterns, and therefore matches nothing.

.. option:: -i, --ignore-case

    Ignore case distinctions in matching, so that characters that differ only in case
    match each other.

.. option:: -v, --invert-match

    Invert the sense of matching, to select non-matching lines.

.. option:: -w, --word-regexp

    Force PATTERN to match only whole words. The matching substring must either be at
    the beginning of the line, or preceded by a non-word  constituent  character.
    Similarly, it  must be either at the end of the line or followed by a non-word
    constituent character.
    Word-constituent characters are letters, digits, and the underscore.


General Output Control
----------------------

.. option:: --output CHANNEL[,CHANNEL...]

    Send output to a comma separated list of channels. Channels have to be defined
    in the configuration file. For default the output is sent to *stdout* channel.

.. option:: -c, --count

    Suppress normal output; instead print a count of matching lines for each input file.
    With the -v/--invert-match option count non-matching lines.

.. option:: --color [(auto|always|never)]

    Use markers to highlight the matching strings. The colors are defined by the environment
    variable LOGRAPTOR_COLORS.

.. option:: -L, --files-without-match

    Print only names of FILEs containing no match.

.. option:: -l, --files-with-match

    Print only names of FILEs containing matches. The scanning will stop on the first match.

.. option:: -m NUM, --max-count NUM

    Stop reading a file after NUM matching lines. When -c/--count option is also used,
    lograptor does not output a count greater than NUM.
    When using `-t/--thread option <lograptor.html#cmdoption-t>`_ the limit is related
    to the number of threads and not to the number of lines matched.

.. option:: -o, --only-matching

    Print only the matched (non-empty) parts of a matching line, with each such part on
    a separate output line.

.. option:: -q, --quiet

    Quiet; do not write anything  to standard output. Exit immediately with zero
    status if any match  is found, even if an error was detected.

.. option:: -s, --no-messages

    Suppress error messages about nonexistent or unreadable files. Equivalent to -d 0.


Output Data Control
-------------------

.. option:: --report [NAME]

    Produce a report at the end of processing. If NAME is omitted that use
    the *default* report defined in the lograptor configuration file.

.. option:: --ip-lookup

    Translate IP addresses to DNS names. Use a DNS local cache to improve the speed
    of the lookups and reduce the network service's load.

.. option:: --uid-lookup

    Translate UIDs to usernames. The configured local system authentication is
    used for lookups, so it must be inherent to the UIDs that have to be resolved.

.. option:: --anonymize

    Anonymize defined application rule's fields value. Translation tables are built
    in volatile memory for each run. The anonymous tokens have the format FILTER_NNN.
    This option overrides --ip-lookup and --uid-lookup options. WARNING: this is an
    experimental feature.


Output Line Prefix Control
--------------------------

.. option:: -n, --line-number

    Prefix each line of output with the line number within its input file.

.. option:: -H, --with-filename

    Print the file name for each match. This is the default when there is more than
    one file to search.

.. option:: -h, --no-filename

    Suppress the prefixing of file names on output. This is the default when there
    is only one file (or only standard input) to search.


Context Line Control
--------------------

.. option:: -T, --thread

    The context is the log thread of the application. The thread rules defined in
    application configuration files are used.

.. option:: -A NUM, --after-context NUM

    Print NUM lines of trailing context after matching lines. Places a line containing
    a group separator (described under --group-separator option) between contiguous
    groups of matches.
    With the -o or --only-matching option, this has no effect and a warning is given.

.. option:: -B NUM, --before-context NUM

    Print NUM lines of leading context before matching lines. Places a line containing
    a group separator (described under --group-separator) between contiguous groups of
    matches.
    With the -o or --only-matching option, this has no effect and a warning is given.

.. option:: -C NUM, --context NUM

    Print NUM lines of output context. Places a line containing a group separator
    (described under --group-separator) between contiguous groups of matches.
    With the -o or --only-matching option, this has no effect and a warning is given.

.. option:: --group-separator SEP

    Use SEP as a group separator. By default SEP is double hyphen (--).

.. option:: --no-group-separator

    Use empty string as a group separator.


File and Directory Selection
----------------------------

.. option:: -r, --recursive

    Read all files under each directory, recursively, following symbolic links only if
    they are on the command line.

.. option:: -R, --dereference-recursive

    Read all files under each directory, recursively. Follow all symbolic links, unlike -r.

.. option:: --exclude GLOB

    Skip any file with a name suffix that matches the pattern GLOB, using wildcard matching;
    a name suffix is either the whole name, or any suffix starting after a / and before a
    +non-/. When searching recursively, skip any subfile whose base name matches GLOB;
    the base name is the part after the last /.
    A pattern can use *, ?, and [...]  as wildcards, and \ to quote a wildcard or backslash
    character literally.

.. option:: --exclude-from FILE

    Skip files whose base name matches any of the file-name globs read from FILE (using
    wildcard matching as described under --exclude).

.. option:: --exclude-dir DIR

    Skip any command-line directory with a name suffix that matches the pattern GLOB.
    When searching recursively, skip any subdirectory whose base name matches GLOB.
    Ignore any redundant trailing slashes in GLOB.

.. option:: --include GLOB

    Search only files whose base name matches GLOB (using wildcard matching as described
    under --exclude).


*****
FILES
*****

``/etc/lograptor/lograptor.conf``

``/etc/lograptor/conf.d/*.conf``

``/usr/bin/lograptor``


*******
AUTHORS
*******
Davide Brunato <`brunato@sissa.it <mailto:brunato@sissa.it>`_>


********
SEE ALSO
********

`lograptor.conf(5) <lograptor-conf.html>`_,
`lograptor-apps(5) <lograptor-apps.html>`_,
`lograptor-examples(5) <lograptor-examples.html>`_,
