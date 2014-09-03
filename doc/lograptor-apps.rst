==================================
Configure Lograptor's applications
==================================


CONFIGURATION FILES
-------------------

**/etc/lograptor/conf.d/*.conf**

Lograptor uses regexp rules sets, defined in apps configuration files,
to extract informations from system logs.
Each application is defined with a configuration file placed in the configuration
subdirectory ``conf.d``, usually in  ``/etc/lograptor/conf.d``.
A configuration file name coincides with the name of the application followed by the
suffix ``.conf``. Files without  ``.conf``  suffix are ignored.


DESCRIPTION
-----------

An application's configuration file use the
`Python's ConfigParser <https://docs.python.org/2/library/configparser.html>`_
format which provides a structure similar to Microsoft Windows INI files.
A configuration file consists of sections and option entries. A section start with a ''[section]'' header.
Each section can have different ``name=value`` (``name: value`` is also accepted) option entries, with
continuations in the style of `RFC 822 <https://www.ietf.org/rfc/rfc0822.txt>`_
(see section 3.1.1, “LONG HEADER FIELDS”).
Note that leading whitespace is removed from values.

The configuration file must contain two sections:

    **main**
        This section include general parameters for the application.

    **rules**
        This section contains rules for application's logs analisys.
        Those rules are called *report rules* for our scope.

Other sections can be defined to describe rules for report composition.
Those sections will be referred hereafter as “report sections”.


[main] SECTION
^^^^^^^^^^^^^^

**desc**
    Put here a fully comprehensive description of the application.

**files**
    Log files for the application. You can specify multiple entries separated by commas.
    Lograptor use configuration variable string interpolation to obtain the effective list
    of files to be included in the run.
    Typically use the string ``$logdir`` (or ``${logdir}``) to shorten the paths that have
    the same common root.
    You can also use other variables related to program options, such as ``$hostname``, that
    is linked to `option -H/--hosts <lograptor.html#cmdoption-H>`_.

    On filenames, you can use wildcard characters typical of
    command line (eg. ?, \*, +), in order to include also the log file
    rotated periodically.

    You can also use variable strings related to dates:

     **%Y**
        specifies the year

     **%m** 
        specifies the month as a number with 2 digits (01..12)

     **%d** 
        specifies the day with 2 digits (01..)

    At now, only these formats are supported to specify the dates,
    but others ought to be included in future versions.
    Filenames that include variables related to dates are expanded by
    the program according to the date range required
    (options `--last <lograptor.html#cmdoption-last>`_ or `--date <lograptor.html#cmdoption-date>`_).

**enabled**
    It can be either "yes" or "no." If "no", the program ignores the app.
    If the application is invoked explicitly using the option -a/--app
    then the value of this parameter is ignored.
    This allows you to schedule reports with a favorite set of applications
    and still be able to use the program for analyze logs of all the applications defined.

**priority**
    It's an unsigned integer that indicates the priority of the application. commonly
    is a value from 0 to 10. Lower values indicate higher priority
    in the composition of the final report, ie report elements
    produced by the application will appear before those of other applications.
    The priority also relates to the processing order of log files.


[rules] SECTION
^^^^^^^^^^^^^^^

This section contains rules written as regular expressions, according to the syntax of
`Python's re module <https://docs.python.org/2/library/re.html>`_, and so will be called
*"pattern rules"*.
Those rules are used by the program to analyze application's log lines and to extract
information  from matched events.
For clarity each regular expression must be written between double quotes.
Each rule is identified with the option name, so must be unique within application.
You should not use names already used by other options of the program for naming a rule,
in order to avoid ambiguity or incompatibility.


Symbolic groups
...............

Lograptor makes use of symbolic groups to extract informations from logs.
A pattern rule must contain at least one symbolic group to be accepted by the program.
For example if a rule is::

    SMTPD_Warning = ": warning: (?P<reason>.+)"

The program extract information about group *"reason"* and is able to use those informations
during reporting stage. Of course you are free to use more symbolic groups within a rule::

    Mail_Resent = ": (?P<thread>[A-Z,0-9]{9,14}): resent-message-id=<(?P<reason>.+)>"


The "thread" symbolic group is used to extract thread information from log lines, in
order to perform thread matching (see `option -t/--thread <lograptor.html#cmdoption-t>`_).


Variables related to filters
............................

An app pattern rule can also contain variables ($VARNAME or ${VARNAME}) related to a
`Lograptor's filter <lograptor.html#cmdoption-F>`_.
At the run each variable is substituted with the corresponding filter's pattern.
This makes sense when you pair a variable with a symbolic group, as in this example:

    Mail_Client = ": (?P<thread>[A-Z,0-9]{9,14}): client=(?P<client>${client})"

If you use `filter options <lograptor.html#cmdoption-F>`_ the program discard the
rules logically excluded by filters.


Dictionary of results
.....................

Each rule produces a table of results as a Python dictionary.
This dictionary have tuples as keys and integers as values.
The values record the number of events associated with each tuple.
For example with the following rule::

        Mail_Received = ": (?P<thread>[A-Z,0-9]{9,14}): from=<(?P<from>${from})>, size=(?P<size>\d+)"

a tuple key will consists of three elements, positionally related to fields <hostname>, <from> and <size>.
In this example a tuple maybe::

        ('smtp.example.com', 'postmaster@example.com', '4827')

Of course inserting more symbolic groups increase the complexity of the results and the
number of elements of the dictionary. So if you don't need details you could semplify
default pattern rules.


Order of pattern rules
......................

The sequence of the rules in the configuration also determines the order of execution
during the process of log analysis.
The order are important to reduce execution total time.
Generally is better to put first the rules corresponding to more numerous log lines.


REPORT SECTIONS
^^^^^^^^^^^^^^^

These optional sections defines elements for composing the report.
For brevity we will refer to these sections as "report sections".
These sections have some fixed options and one or more options that
describe the usage of application's pattern rules, hereafter referred
as "report rules".


Fixed options
.............

**subreport**
    Indicates in which subreport insert the element. It must be the name of one
    of the subreports specified in the main configuration file.

**title**
    Header to be included in the report.

**color**
    Optional alternative color for the header (names or codes defined in the
    specifications of HTML and CSS).

**function**
    Function to be applied on results extracted from the pattern rules of the application.
    There are 3 different functions definable, each one for a different representation of results:

    ``total(), total``
        A function that allows you to create lists with total values from the results.

    ``top(<num>, <header>)``
        A function that allows you to create a ranking of maximum values.
        The <num> parameter is a positive integer that indicating how many maximum values
        to be taken into account.
        The third parameter is a description for the field, which will appear
        in the report on the right column of the table.

    ``table(<header 1>, .. <header K>)``
        A function that allows you to create a table from a result set.
        The parameters are the descriptions that have to be included in the
        headers of the table.
        The number of descriptions determines the number of columns of the table.
        Report tables, also when generated from logs of different applications,
        can be compacted into a single table under specific conditions.
        For this topic read `REPORT OPTIMIZATION <lograptor-apps.html#report-optimization>`_
        paragraph.


Report rules
............

A report section must include at least a rule to The remaining options of a report section must all be report rules.
These options must be named identical to one of the pattern rules defined in
the  section [rules] of the configuration.
If you need to refer twice to a pattern rule in the same section you can use
a numeric suffix for differentiate the options names.
The order of options is important because it is maintained in composition
of the report.

The syntax of a report rule depends by the function type specified in the "function" option.

Report rules with function "total"
..................................

In case of function *total* the syntax of the report rules is::

    <report_rule> = (<filter>, "<description>"[:[+]<counter_field>[<unit>])

Where the parameter <filter> can have the following values:

    ``*``
        Computes the total on all results.

    ``<field>=<pattern>``
        Considers only the tuples of results for which the specified field satisfies the
        constraint described by the pattern.
        The value <field> must be the name of a symbolic group present in all the
        report rules specified below for the section.

    ``<field>!=<pattern>``
        Consider only the results that do not satisfy the constraint specified by the pattern.
        The value <field> must be the name of a symbolic group present in all the
        report rules specified below for the section.

The description is associated to columns of the results.

The optional *<counter_field>* is used to calculate the total value.
For default, the count is done on the value associated with the tuple-key of
the dictionary of results, ie the number of events extracted  for the particular
combination of values. If you specify a <counter_field> the counting is done using
tuple's values related to the field. The <counter_field> must take only
numeric values, otherwise it will generate a configuration error.

If <counter_field> is preceded by a "+" the total sum is calculated using field values
times the number of events.

<counter_field> should be followed by a measurement unit specification of bits or bytes.
This specification have to be enclosed between square brackets and could be prefixes by
K, M, G, T for multiples.
The value is calculated according to the JEDEC specification, ie 1Kbit = 1024 bits.
The numerical results in bytes or bits are then normalized to the multiple unit best
suited for report presentation.
For example "[Kb]" or "[Kbits]" means kilobits and "[GB]" or "[Gbytes]" means gigabytes.

For example, having the pattern rule::

   Mail_Received = ": (?P<thread>[A-Z,0-9]{9,14}): from=<(?P<from>${from})>, size=(?P<size>\d+)"

and defining the corresponding report rule::

   Mail_Received = (*, "Total Messages Processed")

you will produce a report that contains the count of total messages received.
Instead, using the following option::

   Mail_Received = (*, "Total Transferred Size":+size)

a count of the total number of bytes received will be made.
Adding a memory measurement unit specification::

   Mail_Received = (*, "Total Transferred Size":+size[B])

you can afford a better understanding of the results.


Report rules with function "top"
................................

In case of function *top* the syntax the report rules is::

   <report_rule> = (<filter>, <field>[:[+]<counter_field>[<unit>])

All the parameters except <field> have the same syntax and meaning as
in the case of function "total". The <field> parameter can be *hostname*
or the name of a symbolic group belonging to the pattern rule associated,
with the exception of *thread* that is a reserved group.

For example, having this pattern rule::

   Mail_Received = ": (?P<thread>[A-Z,0-9]{9,14}): from=<(?P<from>${from})>, size=(?P<size>\d+)"

you can define a report rule to create the list of servers that have sent more mail::

   Mail_Received = (*, hostname)

Instead, with the following report rule::

   Mail_Received = (*, from)

you create the ranking of email accounts that have sent more messages.

As in the case of "total", you can specify a <counter_field> for counting
alternative values.
For example with this report rule::

   Mail_Received = (*, from:size[B])

you obtain the ranking of the largest e-mails sent during the period:
Instead, inserting the prefix "+"::

   Mail_Received = (*, from:+size[B])

the program computes the list of senders that have high traffic during
the period.


Report rules with function "table"
..................................

In case of function *table* the syntax of a report rule is::

   <report_rule> = (<filter>, <field>, ... <field>)

The <filter> parameter has the same syntax and effect as that of the report rules
of functions "total" and "top".

The <field> parameters are strings enclosed in double quotes, or
*hostname* (without quotes) or in alternative the name of a symbolic group
belonging to the associated pattern rule (except *thread* that is a reserved).

The number of <field> parameters cannot be less than the number of columns
of the table, as defined in the section's option "function".
When the number of parameters of the report rule is greater than
the number of columns of the table, the program collapses the remaining
values in the last column of the table, forming a comma-separated list.

If <field> is a string enclosed between double quotes it will be used
as fixed value in the corresponding column, in order to decorate the data
and distinguish results from those extracted by other rules or other
applications.

The first <field> parameter is used for sorting the table, so is probably
better if you use a reference to a symbolic group instead of a quoted string.

When multiple report rules are provided the results are merged in a
single table, so use multiple report rule in the same report section
only when these have sense.


WRITING PATTERN RULES
---------------------

A simple method to write new pattern rules is make some Lograptor runs limited
to extract unparsed strings for a single application, e.g.::

  # lograptor -a dovecot --unparsed -m 1 /var/log/dovecot.log
  ....
  ....

Then write down the new rule:


Repeat the steps until lograptor doesn't found any unparsed strings in your file. Take
a significantly long log file as input file.

Whith this tecnique you can easily write down all the report rules for an application
in some minutes.


REPORT OPTIMIZATION
-------------------

The program automatically merge tables produced from logs of different
applications when the tables belong to the same subreport.
Table merging is done when if there is an exact matching between titles and headers.
The correspondence of the headers is performed on names, total number and position.
This feature is useful for example if you want to produce a single
table with all user logins. The result is a smaller and more readable reports.


COMMENTS
--------

Lines starting with "#" or ';' are ignored and may be used to provide comments.


AUTHORS
-------

Davide Brunato <`brunato@sissa.it <mailto:brunato@sissa.it>`_>


SEE ALSO
--------
`lograptor(8) <lograptor.html>`_,
`lograptor.conf(5) <lograptor-conf.html>`_,
`lograptor-examples(5) <lograptor-examples.html>`_,
