==================================
Configure lograptor's applications
==================================

*******************
CONFIGURATION FILES
*******************

**${confdir}/*.conf**

*Lograptor* defines his applications by configuration files. An application configuration
filename is the name of the application followed by the suffix ``.conf``.
Each file that is located in the configuration  directory that has this suffix has to be
an application configuration file for lograptor.

An application's configuration file uses the
`Python's ConfigParser <https://docs.python.org/2/library/configparser.html>`_
format which provides a structure similar to Microsoft Windows INI files.
A configuration file consists of sections and option entries. A section start with a ''[section]'' header.
Each section can have different ``name=value`` (``name: value`` is also accepted) option entries, with
continuations in the style of `RFC 822 <https://www.ietf.org/rfc/rfc0822.txt>`_
(see section 3.1.1, “LONG HEADER FIELDS”).
Note that leading and trailing whitespaces are removed from values.


***********
DESCRIPTION
***********

An application configuration file for *lograptor* must contains two sections:

**main**
        Contains the parameters of the application. Includes log app-tags, log files
        locations, priority and enabling status.

    **rules**
        This section contains the *pattern rules* for the analysis of application's logs.
        Those regexp rules are used by the engines of *lograptor*.

Optional additional sections can be defined to define report data composition.


**************
[main] SECTION
**************

**desc**
    A fully comprehensive description of the application.

**files**
    Log files of the application. You can specify multiple entries separated by commas.
    Entries can be GLOB filename patterns, so you can use the wildcard characters *?*, *\**,
    *+* in filenames.
    String interpolation is done on entries just before processing, so you can use obtain the
    effective list of files to be included in the run.
    Typically the string ``$logdir`` (or ``${logdir}``) is used to shorten paths that have
    the same common root.
    You can also use other variables related to program options, such as ``$hostname``, that
    is linked to the `option --hosts <lograptor.html#cmdoption-H>`_.

    Finally you can also use some wildcards related to dates:

    **%Y**
        specifies the year

    **%m** 
        specifies the month as a number with 2 digits (01..12)

    **%d** 
        specifies the day with 2 digits (01..)

    Currently only these formats are supported to specify the dates. Filenames that include
    variables related to dates are expanded by the program according to the date range provided
    (options `--last <lograptor.html#cmdoption-last>`_ or `--date <lograptor.html#cmdoption-date>`_).

**enabled**
    It can be either "yes" or "no." If "no", the program ignores the app.
    If the application is invoked explicitly using the option -a/--app
    then the value of this parameter is ignored.
    This allows you to schedule reports with a favorite set of applications
    and still be able to use the program for analyze logs of all the applications defined.

**priority**
    It's an unsigned integer that indicates the priority of the application, commonly
    a value from 0 to 10. A lower value indicates an higher priority in the composition
    of the final report, ie report data elements produced by the application will appear
    before those of other applications with an higher value.
    The priority also conditions the processing order of the log files.


***************
[rules] SECTION
***************

This section contains pattern rules written as regular expressions, according to the syntax of
`Python's re module <https://docs.python.org/2/library/re.html>`_.
Those rules are used by the program to analyze application's log lines and to extract
information  from matched events.
Each rule is identified with the option name, so must be unique within application.
Don't use names already used by other options of the program for defining a pattern rule,
in order to avoid ambiguities.


Symbolic Groups
---------------

Lograptor makes use of Python's regex
`symbolic groups <https://docs.python.org/2/library/re.html#regular-expression-syntax>`_
to extract information from logs.
A pattern rule must contain at least one symbolic group in order to be accepted by the program.
For example if a rule is::

    SMTPD_Warning = ": warning: (?P<reason>.+)"

the program extract information about group *"reason"* and is able to use those information
during reporting stage.
You can use more symbolic groups within a rule for detailing the structure of extracted data::

    Mail_Resent = ": (?P<thread>[A-Z,0-9]{9,14}): resent-message-id=<(?P<reason>.+)>"

The "thread" symbolic group is used to extract thread information from log lines, in
order to perform thread matching (see `option -T/--thread <lograptor.html#cmdoption-T>`_).


Pattern Rules and Filters
-------------------------

An app pattern rule can also contain variables ($VARNAME or ${VARNAME}) related to a
`lograptor's filter <lograptor.html#cmdoption-F>`_.
At the run each variable is substituted with the corresponding filter's pattern.
This feature has sense when you pair a variable with a symbolic group, as in this example::

    Mail_Client = ": (?P<thread>[A-Z,0-9]{9,14}): client=(?P<client>${client})"

If you use `filter options <lograptor.html#cmdoption-F>`_ the program discards the
rules logically excluded by filters (*unused rules*).


Dictionary of Results
---------------------

Each rule produces a table of results as a Python dictionary. This dictionary has tuples
as keys and integers as values. The values record the number of events associated with
each tuple. For example with the following rule::

    Mail_Received = ": (?P<thread>[A-Z,0-9]{9,14}): from=<(?P<from>${from})>, size=(?P<size>\d+)"

the tuple key consists of three elements, positionally related to fields *<hostname>*,
*<from>* and *<size>*::

    ('smtp.example.com', 'postmaster@example.com', '4827')

Of course inserting more symbolic groups increase the complexity of the results and
the number of elements of the dictionary. So if you don't need details you could
simplify the default pattern rules.


Order of Pattern Rules
----------------------

The sequence of the rules in the configuration also determines the order of execution
during the process of log analysis. The order are important to reduce execution total time.
Generally is better to put first the rules corresponding to more numerous log lines.


Writing Pattern Rules
---------------------

A simple method to write new pattern rules is to use the lograptor unparsed engine for
each application, in order to verify which lines are not matched by any pattern rule, e.g.::

    # lograptor -a dovecot --unparsed -m 1 /var/log/dovecot.log
    ...
    ...

If the search is not empty start to write a new detailed rule until the match is done and
the line disappear from the above search command. Repeat these steps until lograptor
doesn't found any unparsed string in your file.

With this technique you can easily write down all the report rules for an application
in some minutes.


********************
REPORT DATA SECTIONS
********************

Additional configuration sections define the data elements for composing the report.
These sections have some mandatory options and one or more options that define the
usage of application's pattern rules.


Mandatory Options
-----------------

**subreport**
    Indicates in which subreport insert the element. It has to match the name of one
    of the subreports specified in the main configuration file.

**title**
    Header to be included in the report.

**color**
    Color to be used for the header (use the names or the codes defined for HTML and CSS
    specifications).

**function**
    Function to apply on the results extracted from the pattern rules of the application.
    There are three different functions definable, each one lead to a different
    representation of the results:

    ``total(), total``
        Creates lists with total values from the results.

    ``top(<num>, <header>)``
        Creates a ranking of maximum values.

        The <num> parameter is a positive integer that indicating how many maximum values
        to be taken into account. The third parameter is a description for the field, which
        will appear on the right column of a two-column table.

    ``table(<header 1>, .. <header K>)``
        Create a table from a result set.

        The arguments are the descriptions that have to be included in the
        headers of the table.
        The number of arguments determines the number of columns of the table. These tables,
        also when generated from logs of different applications, are compacted into a single
        table under specific conditions. For this topic read the
        `REPORT OPTIMIZATION <lograptor-apps.html#report-optimization>`_ paragraph.


Pattern Rules Related Options
-----------------------------

A report data section must includes at least an option that refers to a pattern rule of the application.
For doing this simply add the name of a pattern rule as option of the report data section.
If you need to refer twice to a pattern rule in the same section you can use a numeric suffix
for differentiate the options names.
The order of those additional options is important because it is maintained when composing the report.

The syntax of a report rule depends by the function type specified in the "function" option.


Report data sections with function "total"
..........................................

In case of defining a report data section that uses the *total* function the syntax of an
additional option must be::

    <pattern_rule_name> = (<filter>, "<description>"[:[+]<counter_field>[<unit>])

The parameter *<filter>* can have the following values:

    ``*``
        Computes the total on all results.

    ``<field>=<pattern>``
        Consider only the tuples of results for which the specified field satisfies the
        constraint described by *<pattern>*. The value *<field>* must be the name of a
        symbolic group and must be defined in all the pattern rules provided for the section.

    ``<field>!=<pattern>``
        Consider only the results that don't satisfy the constraint specified by *<pattern>*.
        The value *<field>* must be the name of a symbolic group present in all the pattern
        rules provided for the section.

The *<description>* will be the header of the column of the results.

The optional *<counter_field>* is used to calculate the total value from result values.
For default, the count is done on the value associated with the tuple-key of
the dictionary of results, ie the number of events extracted  for the particular
combination of values. If you specify a *<counter_field>* the count is computed using
tuple's values related to the field. Fill *<counter_field>* with the name of the symbolic
group that you want to use for calculate the total value. If *<counter_field>* is preceded
by a "+" the total sum is calculated using field values times the number of events.

The *<counter_field>* can be followed by a measurement *<unit>* specification of bits or
bytes. This specification have to be enclosed between square brackets and can have one of
the metric prefixes K, M, G, or T.
The value is calculated according to the JEDEC specification, ie 1Kbit = 1024 bits.
For example "[Kb]" or "[Kbits]" means kilobits and "[GB]" or "[Gbytes]" means gigabytes.
The numerical results in bytes or bits are then normalized to the multiple unit best
suited for report presentation.

As a full example, having the pattern rule::

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


Report data section with function "top"
.......................................

In case of function *top* the syntax of an additional option must be::

   <pattern_rule_name> = (<filter>, <field>[:[+]<counter_field>[<unit>])

All the parameters except *<field>* have the same syntax and meaning as have
for the function *total*. The *<field>* parameter can be *hostname* or the name
of a symbolic group belonging to the pattern rule associated, with the exception
of the *thread* symbolic group that is reserved.

For example, having this pattern rule::

   Mail_Received = ": (?P<thread>[A-Z,0-9]{9,14}): from=<(?P<from>${from})>, size=(?P<size>\d+)"

you can define a report data option that creates the list of servers that have sent more mail::

   Mail_Received = (*, hostname)

Instead, with the following report data option::

   Mail_Received = (*, from)

a ranking of email accounts that have sent more messages is created.

As in the case of the *total* function, you can specify a *<counter_field>* for
count alternative values.
For example with this report rule::

   Mail_Received = (*, from:size[B])

you obtain the ranking of the largest e-mails sent during the period:
Instead, inserting the prefix "+"::

   Mail_Received = (*, from:+size[B])

the program computes the list of senders that had the most high traffic during
the period.


Report rules with function "table"
..................................

In case of function *table* the syntax of an additional option must be::

   <report_rule> = (<filter>, <field>, ... <field>)

The *<filter>* parameter has the same syntax and effect as that has in the
case of functions "total" and "top".

The *<field>* parameters are literal strings enclosed in double quotes, or
*hostname* (without quotes) or in alternative the name of a symbolic group
belonging to the associated pattern rule (except *thread* that is a reserved).

The number of *<field>* parameters cannot be less than the number of columns
of the table, that is defined by the section's option "function".
When the number of parameters of the report rule is greater than the number of
columns of the table, the program collapses the remaining values in the last
column of the table, forming a comma-separated list.

If *<field>* is a string enclosed between double quotes it will be used as fixed
value in the corresponding column, in order to decorate the data and distinguish
results from those extracted by other rules or different applications.

The first *<field>* parameter is used for sorting the table, so is usually better
if you use for this a reference to a symbolic group instead of a quoted string.

When multiple report data options are configured the results are merged in a
single table, so use multiple report data options only if mixing these results
is significant.


Report Optimization
-------------------

The program automatically merge tables produced from logs of different applications
when the tables belong to the same subreport.
Table merging is done when if there is an exact matching between titles and headers.
The correspondence of the headers is performed on names, total number and position.
This feature is useful for example if you want to produce a single table with all
user logins. The resulting reports are smaller and more readable.


********
COMMENTS
********

Lines starting with "#" or ';' are ignored and may be used to provide comments.


*******
AUTHORS
*******

Davide Brunato <`brunato@sissa.it <mailto:brunato@sissa.it>`_>


********
SEE ALSO
********
`lograptor(8) <lograptor.html>`_,
`lograptor.conf(5) <lograptor-conf.html>`_,
`lograptor-examples(5) <lograptor-examples.html>`_,
