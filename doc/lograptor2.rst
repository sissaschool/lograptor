    parser = argparse.ArgumentParser(prog='lograptor', description=__description__, add_help=False)
    parser.usage = """ %(prog)s [options] [PATTERN] [FILE ...]
    %(prog)s [options] [ -e PATTERN | -f FILE ] [FILE ...]
    Try '%(prog)s --help' for more information."""
    parser.add_argument('--help', action='help', help="show this help message and exit")
    parser.add_argument('-V', '--version', action='version', version=__version__)

    group = parser.add_argument_group("Matcher Selection")
    group.add_argument(
        "--use-rules", action="store_true", default=False,
        help="Use patterns and app rules. This is the default."
    )
    group.add_argument(
        "-X", "--exclude-rules", action="store_true", default=False,
        help="The match is based only on the pattern without consider the application rules."
    )
    group.add_argument(
        "-T", "--thread", action="store_true", default=False,
        help="The match of the pattern is performed not line by line but on groups of "
             "lines formed by application rules that contain a thread specification."
    )
    group.add_argument(
        "-U", "--unparsed", action="store_true", default=False,
        help="Match the lines that match the pattern but that are not parsable by any application rule. "
             "Useful for finding anomalies and for extending application rules."
    )

    group = parser.add_argument_group("Scope Selection")
    group.add_argument(
        "--apps", metavar='APP-NAME[,APP-NAME...]', action="store", dest="apps", default='',
        help="Analyze only log lines related to a comma separated list of applications. "
             "An app name is accepted when a configuration file is defined. "
             "For default the program process all the defined and enabled apps."
    )
    group.add_argument(
        "--host", metavar="HOSTNAME/IP", action="append", dest="hosts",
        help="Will analyze only log lines related to an hostname or an IP address. "
             "The argument can be expressed using wildcards or a regular expression. "
             "If this option is used multiple times then selects all the arguments given."
    )
    group.add_argument(
        "--filter", metavar="FIELD-NAME=PATTERN[,FIELD-NAME=PATTERN...]",
        action="append", dest="filters", default=None,
        help="Restrict the search with a comma separated list of matching patterns for fields, "
             "applying them with logical conjunction (AND). A field name can be one of the "
             "default fields of the program or an additional one defined for the application. "
             "If this option is used multiple times then selects with all filters given, "
             "equivalently to a logical disjunction (OR)."
    )
    group.add_argument(
        "--time", metavar="HHMM,HHMM", type=timerange, action="store", dest="timerange",
        help="Restrict search scope to a time range. If this option is used "
             "multiple times then selects all the time ranges given."
    )
    group.add_argument(
        "--date", metavar="[YYYY]MMDD[,[YYYY]MMDD]", action="store", dest="period", default=None,
        help="Restrict search scope to a date or an interval of dates."
    )
    group.add_argument(
        "--last", action="store", dest="period", default=None,
        metavar="[hour|day|week|month|Nh|Nd|Nw|Nm]",
        help="Restrict search scope to a previous time period."
    )

    group = parser.add_argument_group("Matching Control")
    group.add_argument(
        "-e", "--regexp", metavar="PATTERN", dest="patterns", default=None, action="append",
        help="The search pattern. Use the option more times to specify multiple "
             "search patterns. Empty patterns are skipped."
    )
    group.add_argument(
        "-f", "--file", dest="pattern_file", default=None, metavar="FILE",
        help="Obtain patterns from FILE, one per line. If this option is used multiple times "
             "or is combined with the -e (--regexp) option, search for all patterns given. "
             "The empty file contains zero patterns, and therefore matches nothing."
    )
    group.add_argument(
        "-i", "--ignore-case", action="store_true", dest="case", default=False,
        help="Ignore case distinctions in matching."
    )
    group.add_argument(
        "-v", "--invert-match", action="store_true", dest="invert", default=False,
        help="Invert the sense of matching, to select non-matching lines."
    )
    group.add_argument(
        "-w", "--word-regexp", action="store_true", dest="word", default=False,
        help="Select only those lines containing matches that form whole words. "
    )

    group = parser.add_argument_group("Output Control")
    group.add_argument(
        "--output", default='stdout', metavar='OUTPUT-DESTINATION',
        help="Send output to a specific destination (stdout for default)."
    )
    group.add_argument(
        "-c", "--count", action="store_true", default=False,
        help="Suppress normal output; instead print a count of matching lines for each input file. "
             "With  the  -v/--invert-match option, counts non-matching lines. When -m/--max-count "
             "argument is also used, the program does not output a count greater than NUM."
    )
    group.add_argument(
        "-m", "--max-count", metavar='NUM', action="store", type=positive_integer, default=None,
        help="Stop input source processing after NUM matching events."
    )

    group.add_argument(
        "-L", "--files-without-match", action="store_false", dest="files_with_match",
        help="Suppress normal output; instead print the name of each input file from which no output "
             "would normally have been printed.  The scanning will stop on the first match."
    )
    group.add_argument(
        "-l", "--files-with-match", action="store_true", dest="files_with_match",
        help="Suppress normal output; instead print the name of each input file from which output "
             "would normally have been printed. The scanning will stop on the first match."
    )
    group.add_argument(
        "-q", "--quiet", action="store_true", default=None,
        help="Quiet; do not write anything  to standard output. Exit immediately with zero status "
             "when a match is found, even if an error was detected. See also the -s or --no-messages options."
    )
    group.add_argument(
        "-s", "--no-messages", action="store_true", default=False,
        help="Suppress error messages about nonexistent or unreadable input sources."
    )
    group.add_argument(
        "--report", dest="report", action="store_true", default=False,
        help="Suppress normal output; instead produce a report at the end of processing."
    )

    group = parser.add_argument_group("Output Data Control")
    group.add_argument(
        "-h", "--with-source", action="store_true", dest="print_source", default=None,
        help="Include information of the input source for each matching event."
    )
    group.add_argument(
        "-H", "--no-source", action="store_false", dest="print_source", default=None,
        help="Suppress the default headers with filenames on output. This is the default "
             "behaviour for output also when searching in a single file."
    )

    group.add_argument(
        "--ip", action="store_true", dest="ip_lookup", default=False,
        help="Do a reverse lookup translation for the IP addresses for report data. Use a DNS local "
             "caching to improve the speed of the lookups and reduce the network service's load."
    )
    group.add_argument(
        "--uid", action="store_true", dest="uid_lookup", default=False,
        help="Map numeric UIDs to usernames for report data. The configured local system authentication "
             "is used for lookups, so it must be inherent to the UIDs that have to be resolved."
    )
    group.add_argument(
        "--anonymize", action="store_true", dest="anonymize", default=False,
        help="Anonymize output for values connected to provided filters. Translation tables are built "
             "in volatile memory for each run. The anonymous tokens have the format FILTER_NN. "
             "This option overrides --ip, --uid."
    )

    group = parser.add_argument_group("File and Directory Selection")
    group.add_argument(
        "--tsa", action="store_true", default=False,
        help="Use only files with a verified timestamp. A warning message "
             "is displayed for unverifiable inputs sources."
    )
    group.add_argument(
        "--exclude", metavar='GLOB',
        help="Skip files whose base name matches GLOB (using wildcard matching). "
             "A file-name glob can use *, ?, and [...] as wildcards, and \ to "
            "quote a wildcard or backslash character literally."
    )
    group.add_argument(
        "--exclude-from", metavar='FILE',
        help="Skip files whose base name matches any of the file-name globs read "
             "from FILE (using wildcard matching as described under --exclude)."
    )
    group.add_argument(
        "--exclude-dir", metavar='DIR',
        help="Exclude directories matching the pattern DIR from recursive searches."
    )
    group.add_argument(
        "--include", metavar='GLOB',
        help="Search only files whose base name matches GLOB (using wildcard matching "
             "as described under --exclude)."
    )
    group.add_argument(
        "-r", "--recursive", action="store_true", default=False,
        help="Read all files  under each directory, recursively, following symbolic "
             "links only if they are on the command line.  Note that if no file operand "
             "is given, grep searches the working directory."
    )
    group.add_argument(
        "-R", "--dereference-recursive", action="store_true", default=False,
        help="Read all files under each directory, recursively.  Follow all symbolic links, unlike -r."
    )

    group = parser.add_argument_group("Other Options")
    group.add_argument(
        "--conf", dest="cfgfile", type=str, default=cfgfile_default, metavar="<CONFIG_FILE>",
        help="Use a specific configuration file for Lograptor, instead of the "
             "default file located in {0}. Calling the program without other "
             "options and arguments produce a dump of the configuration settings "
             "to stdout.".format(cfgfile_default)
    )
    group.add_argument(
        "-d", dest="loglevel", default=2, type=int, metavar="[0-4]", choices=range(5),
        help="Logging level. The default is 2 (warning). Level 0 log only "
             "critical errors, higher levels shows more information."
    )

    parser.add_argument('files', metavar='[FILE...]', nargs='*', help="Input filename/s.")
    return parser
