=======================
Lograptor configuration
=======================


CONFIGURATION FILE
------------------

**/etc/lograptor/lograptor.conf**

Lograptor will look for `/etc/lograptor/lograptor.conf` as default configuration file,
but you can override that by passing ``--conf`` switch on the command line.


DESCRIPTION
-----------

Lograptor configuration file use the
`Python's ConfigParser <https://docs.python.org/2/library/configparser.html>`_
format which provides a structure similar to Microsoft Windows INI files.
A configuration file consists of sections and option entries. A section start with a ''[section]'' header.
Each section can have different ``name=value`` (``name: value`` is also accepted) option entries, with
continuations in the style of `RFC 822 <https://www.ietf.org/rfc/rfc0822.txt>`_
(see section 3.1.1, “LONG HEADER FIELDS”).
Note that leading whitespace is removed from values.

The configuration file include five fixed-named sections. Extra sections can be added in order to
define report's publishers. A publisher can be of two types: *Mail Publisher* or *File Publisher*.
The publisher type is defined with the option **method**. The names of the publishers are then
used in `--publish option <lograptor.html#cmdoption--publish>`_.
Other sections are ignored.

[main] SECTION
^^^^^^^^^^^^^^

.. envvar:: cfgdir

    This is where lograptor should look for apps configuration information,
    most notably, *conf.d* directory. See `lograptor-apps(5) <lograptor-apps.html>`_
    for more info on apps configuration.

.. envvar:: logdir

    Where the system logs are located. Useful to shortening log path
    specification in application's configuration files.

.. envvar:: tmpdir

    Where to create temporary directories and put temporary files. Note
    that log files can grow VERY big and lograptor might need similar
    space for processing purposes. Make sure there is no danger
    of filling up that partition. A good place on a designated loghost is
    /var/tmp, since that is usually a separate partition dedicated
    entirely for logs.

.. envvar:: fromaddr

    Use a specific sender address when sending reports or notifications.
    Defaults to address *root@<HOST_FQDN>*.

.. envvar:: smtpserv

    Use this smtp server when sending notifications. Can be either a hostname
    of an SMTP server to use, or the location of a sendmail binary.
    If the value starts with a "/" is considered a path.
    E.g. valid entries::

        smtpserv = mail.example.com

        smtpserv = /usr/sbin/sendmail -t

.. envvar:: mapexp

    The dimension of translation tables for
    `--anonymize <lograptor.html#cmdoption--anonymize>`_ option. The number is
    the power of 10 that represents the maximum extension of each table (default is 4).


[patterns] SECTION
^^^^^^^^^^^^^^^^^^

Basic pattern rules. Those rules are essential for correct program execution.
All the patterns could be commented out because are also defined in Lograptor's code.
It's possible to customize patterns, but you have to make sure the new patterns
are conform with regexp syntax to avoid execution errors.
Pattern customization is useful to match non-ortodox log elements or if you want to
simplify the patterns to slightly speed-up the processing.

.. envvar:: rfc3164_pattern

    This is the path for legacy BSD log header searches, compliant to
    RFC 3164 specifications.

.. envvar:: rfc5424_pattern

    This is the path for IETF log header searches, compliant to
    RFC 5424 specifications.

.. envvar:: ipaddr_pattern

    This is the pattern for IP addresses matching.

.. envvar:: dnsname_pattern

    This is the pattern for DNS names matching.

.. envvar:: email_pattern

    This is the pattern for RFC824 e-mail address matching.

.. envvar:: username_pattern

    This is the pattern for username matching.

.. envvar:: id_pattern

    This is the pattern for numerical ID matching.


[filters] SECTION
^^^^^^^^^^^^^^^^^

This section contains default pattern rules for Lograptor filters
(`command option -F <lograptor.html#cmdoption-F>`_).
Each pattern rule is usually referred as a composition of basic patterns.
Variable related strings's interpolation is then used to define the effective regexp
pattern during execution.
You could add your own filter or customize patterns, but in this case you have to make
sure that the changes do not exclude valid log lines.

In default configuration 8 filters are defined. Those filters could be
commented out because are also defined with it's default in Lograptor code.

.. envvar:: user

    Filter for usernames (defaults to ``${username_pattern}``).

.. envvar:: mail

    Filter for email addresses (defaults to ``${email_pattern}``).

.. envvar:: from

    Filter for sender email addresses (defaults to ``${email_pattern}``).

.. envvar:: rcpt

    Filter for recipient email addresses (defaults to ``${email_pattern}``).

.. envvar:: client

    Filter for client IP/name (defaults to
    ``(${dnsname_pattern}|${ipv4_pattern}|${dnsname_pattern}\[${ipv4_pattern}\])``).

.. envvar:: pid

    Filter for process IDs (defaults to ``${id_pattern}``).

.. envvar:: uid

    Filter for user numerical IDs (defaults to ``${id_pattern}``).

.. envvar:: msgid

    Filter for message IDs (defaults to ``${ascii_pattern}``).


[report] SECTION
^^^^^^^^^^^^^^^^

.. envvar:: title

    What should be the title of the report. For mailed reports, this is
    the subject of the message. For the ones published on the web, this is
    the title of the page (as in <title></title>) for html reports, or the
    main header for plain text reports.

.. envvar:: html_template

    Which template should be used for the final html reports.
    The default value is ``$cfgdir/report_template.html``.

.. envvar:: text_template

    Which template should be used for the final plain text reports.
    The default value is ``$cfgdir/report_template.txt``.


[subreports] SECTION
^^^^^^^^^^^^^^^^^^^^

The *subreports* section define the report logical divisions. The subreports are
inserted in the report using the interpolation of variable string "$subreport".
The order of subreports's definition is preserved in report composition.
In default configuration there are 4 subreports defined:

.. envvar:: logins

    User's logins subreport.

.. envvar:: email

    E-mail subreport.

.. envvar:: commands

    System commands subreport.

.. envvar:: databases

    Databases lookups subreport.

You could add your own subreports: this should be needed when add new apps to configuration.
To composite the report the subreports are then referred in application's report rules.
See `lograptor-apps(5) <lograptor-apps.html>`_ for more details on app's report rules.


MAIL PUBLISHER SECTIONS
^^^^^^^^^^^^^^^^^^^^^^^

.. py:attribute:: method

    Method must be set to "mail" for this publisher to be considered a
    mail publisher.

.. py:attribute:: mailto

    The list of email addresses where to mail the report. Separate
    multiple entries by a comma. If ommitted, "root@localhost" will be
    used.

.. py:attribute:: format

    Can be one of the following: *html*, *plain*, or *csv*. If
    you use a mail client that doesn't support html mail, then you better
    use "plain" or "both", though you will miss out on visual cueing that
    lograptor uses to notify of important events.

.. py:attribute:: include_rawlogs

    Whether to include the gzipped raw logs with the message. If set to
    "yes", it will attach the file with all processed logs with the
    message. If you use a file publisher in addition to the mail
    publisher, this may be a tad too paranoid.

.. py:attribute:: rawlogs_limit

    If the size of rawlogs.gz is more than this setting (in kilobytes),
    then raw logs will not be attached. Useful if you have a 50Mb log and
    check your mail over a slow uplink.

.. py:attribute:: gpg_encrypt

    Logs routinely contain sensitive information, so you may want to
    encrypt the email report to ensure that nobody can read it other than
    designated administrators. Set to "yes" to enable gpg-encryption of the
    mail report. You will need to install mygpgme (installed by default on
    all yum-managed systems).

.. py:attribute:: gpg_keyringdir

    If you don't want to use the default keyring (usually /root/.gnupg), you
    can set up a separate keyring directory for lograptor's use. E.g.::

    > mkdir -m 0700 /etc/lograptor/gpg

.. py:attribute:: gpg_recipients

    List of PGP key id's to use when encrypting the report. The keys must be in
    the pubring specified in gpg_keyringdir. If this option is omitted, lograptor
    will encrypt to all keys found in the pubring. To add a public key to a
    keyring, you can use the following command::

    > gpg [--homedir=/etc/lograptor/gpg] --import pubkey.gpg

    You can generate the pubkey.gpg file by running "gpg --export KEYID" on your
    workstation, or you can use "gpg --search" to import the public keys from
    the keyserver.

.. py:attribute:: gpg_signers

    To use the signing option, you will first need to generate a private key::

    > gpg [--homedir=/etc/lograptor/gpg] --gen-key

    Create a *sign-only RSA key* and leave the passphrase empty. You can then
    use ``"gpg --export"`` to export the key you have generated and import it on the
    workstation where you read mail.
    If gpg_signers is not set, the report will not be signed.


FILE PUBLISHER SECTIONS
^^^^^^^^^^^^^^^^^^^^^^^

.. py:attribute:: method

    Method must be set to "file" for this config to work as a file
    publisher.

.. py:attribute:: path

    Where to place the directories with reports. A sensible location would
    be in ``/var/www/html/lograptor``. Note that the reports may contain
    sensitive information, so make sure you place a .htaccess in that
    directory and require a password, or limit by host.

.. py:attribute:: dirmask, filemask

    These are the masks to be used for the created directories and
    files. For format values look at strftime documentation here:
    `https://docs.python.org/2/library/time.html <https://docs.python.org/2/library/time.html#time.strftime>`_

.. py:attribute:: save_rawlogs

    Whether to save the raw logs in a file in the same directory as the report.
    The default is off, since you can easily look in the original log sources.

.. py:attribute:: expire_in

    A digit specifying the number of days after which the old directories
    should be removed. Default is 7.

.. py:attribute:: notify

    Optionally send notifications to these email addresses when new
    reports become available. Comment out if no notification is
    desired. This is definitely redundant if you also use the mail
    publisher.

.. py:attribute:: pubroot

    When generating a notification message, use this as publication root
    to make a link. E.g.::

        pubroot = http://www.example.com/lograptor

    will make a link: `http://www.example.com/lograptor/dirname/filename.html
    <http://www.example.com/lograptor/dirname/filename.html>`_


COMMENTS
--------

Lines starting with "#" or ';' are ignored and may be used to provide comments.


AUTHORS
-------

Davide Brunato <`brunato@sissa.it <mailto:brunato@sissa.it>`_>


SEE ALSO
--------
`lograptor(8) <lograptor.html>`_,
`lograptor-apps(5) <lograptor-apps.html>`_,
`lograptor-examples(5) <lograptor-examples.html>`_,

