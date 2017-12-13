****************
Lograptor README
****************

Lograptor is a GREP-like search tool for system logs written in legacy BSD
syslog format RFC 3164 and for IETF syslog protocol RFC 5424.

The program can perform searches in syslog files like as the UNIX command
"grep", but with the addition of some filters and parameters, useful to
restrict the search field and retrieve the relevant information from log
files. You could specify parameters like hostname, application, date,
time range, plus a set of filters on message data.

Lograptor can also produce reports and publish them into a directory or send
them by e-mail. The report may be a general or a specific report tailored
for some accounts or hosts.

The basic idea is to have a compact and highly configurable CLI tool for
system logs analysis. The log analysis is based on application or device
that originated the message, using a set of rules for matching and for
report composition.

The project uses parts of Epylog under LGPL terms with author's permission.

Please send feedback for bugs, feature requests, suggestions, comments and
criticism.

INSTALL
-------

Installing from package::

    sudo pip install lograptor    # System wide installation, require root access.
    pip install --user lograptor  # Installation into the user space.

Installing from source::

    git clone https://github.com/brunato/lograptor
    cd lograptor/
    python setup.py install
    python setup.py install_data

To verify if the program is installed type *lograptor* without arguments on the command
line. The default configuration location and settings will be shown.

CONFIGURE
---------
After the installation copy the default configuration files of the package source into
*/etc/lograptor* to define your custom configurations::

  /etc/lograptor/lograptor.conf        Default main configuration file
  /etc/lograptor/report_template.html  Report HTML template
  /etc/lograptor/report_template.txt   Report plain text template
  /etc/lograptor/conf.d/*.conf         Configuration files for applications

For more info about main configuration file please see "man lograptor.conf".
For each application a configuration file is needed. Logs of unconfigured
applications are simply ignored by the program. For more info please see
"man lograptor-apps".

USAGE
-----
::

  lograptor [options] PATTERN [FILE ...]
  lograptor [options] [-e PATTERN | -f PATTERNS_FILE ] [FILE ...]

Lograptor has many CLI options. Some options are identical to those of
UNIX command "grep". If FILE arguments list is empty the program
processes the log files of the last 24 hours.
For more information on usage options see "lograptor --help" or
"man lograptor".

LICENSE
-------
Copyright (C), 2011-2017, by SISSA - International School for Advanced Studies.

Lograptor is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
file 'LICENSE' in the root directory of the present distribution
for more details.

AUTHOR
------
Davide Brunato <brunato@sissa.it>,
SISSA - Scuola Internazionale Superiore di Studi Avanzati/International School for Advanced Studies, Trieste, ITALY

ROADMAP
-------

- Adding other log formats and output channels
- Accepting Logstash's Grok syntax in application pattern rules
- Completing the develop of a library interface
- Completing the anonymized output feature, that is still an experimental feature
