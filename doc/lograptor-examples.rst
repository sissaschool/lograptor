========================
Lograptor usage examples
========================

DESCRIPTION
-----------

Lograptor usage examples describe the simplicity.

BASIC PATTERN SEARCH
--------------------

Search a pattern in specific log file::

    lograptor -e "hello" /var/log/messages

Same search but ignoring characters case::

    lograptor -i -e "hello" /var/log/messages

Search a string in postfix's log files of the last 3 days::

    lograptor --last=3d -a postfix -e "example.com"


SEARCHING WITH FILTERS
----------------------

Search of mail sent by an address, with match at connection thread level::

    lograptor -t -F from=user@example.com /var/log/maillog


GENERATING REPORTS
------------------
Produce a report on console for application "crond"::

    lograptor -ra crond /var/log/cron

The same but produce an HTML report and publish it with default publishers, including unparsed logs::

    lograptor -R html -ua crond "" /var/log/cron

SCRIPTING AND CRON
------------------

Lograptor can be easily called by a script and put in cron execution.

