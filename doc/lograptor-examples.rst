========================
Lograptor usage examples
========================

DESCRIPTION
-----------

This chapter describes simple cases usage and some advanced ones.

BASIC PATTERN SEARCH
--------------------

Search a pattern in specific log file::

    lograptor -e 'hello' /var/log/messages

Same search but ignoring characters case::

    lograptor -i -e 'hello' /var/log/messages

Search a string in Postfix's log files of the last 3 days::

    lograptor --last=3d -a postfix -e 'example.com'


SEARCHING WITH FILTERS
----------------------

Search of e-mails sent by an address, with match at connection thread level::

    lograptor -T -F from=user@example.com -e '' /var/log/maillog

Search of e-mail messages sent by a domain::

    lograptor -F from=.*@example.com /var/log/maillog

Search of e-mail messages sent by a domain to another domain::

    lograptor -T -F from=.*@example.com -e 'to=<.*@example2.org>' /var/log/maillog

Search of e-mail messages sent by our domain to external domains::

    lograptor -T -F from=.*@example.com -e 'to=<.*@(?!example.org>)' /var/log/maillog

GENERATING REPORTS
------------------
Produce a default report on console for application *crond*::

    lograptor --report -a crond -e '' /var/log/cron

On a custom report saved on a file::

    lograptor --report my_report --output file -a crond -e '' /var/log/cron


SCRIPTING AND CRON
------------------

lograptor can be easily called by a script and put in a cron execution.
For example you can run a daily batch to all logs at midnight::

    # crontab -l
    0 0 * * * lograptor --output=mail,file

Running as a batch makes sense if you send the output to not-stdout channels.


DEFINING APP RULES
------------------

When you need to define a new application or to update the configuration of
an already defined application the main problem is generally the definition
of app's rules. An app rule is essentially a regular expression template,
that is transformed into one or several regular expressions at runtime.

To define rules for an application use those steps:

#. Use the *unparsed* matcher to find the first unparsed line in your log::

    # lograptor -U -s -a dovecot -m 1 -e '' /var/log/dovecot.log
    Sep 22 00:00:04 ockham dovecot: imap-login: Login: user=<brunato>, PID=23892,
    method=PLAIN, rip=192.168.107.132, lip=192.168.1.174, secured

#. Build a regex pattern and put it in the "rules" section of your application configuration
   (eg. /etc/lograptor/conf.d/dovecot.conf)::

    IMAP_Logins = dovecot: imap-login: Login: user=<(?P<user>${user})>,\s
                  PID=(?P<thread>(?P<pid>${pid})),\s(\S+),\srip=(?P<client>${client})

#. Repeat steps 1 and 2 until there are no more unparsed lines.

Into an app's pattern rule you have to define some named groups to retrieve the relevant
information and to permit to some program features to works (eg. filters, report, anonymization).
