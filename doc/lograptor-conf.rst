=======================
Lograptor configuration
=======================

******************
CONFIGURATION FILE
******************

**lograptor.conf**

lograptor looks at `./lograptor.conf`, `~/.config/lograptor/lograptor.conf`,
`~/.local/etc/lograptor/lograptor.conf` or `/etc/lograptor/lograptor.conf` for a
configuration file, using the first file found, but you can use an specific
configuration file  using the ``--conf`` command line option.


***********
DESCRIPTION
***********

A lograptor configuration file uses the
`Python's ConfigParser <https://docs.python.org/2/library/configparser.html>`_
format which provides a structure similar to Microsoft Windows INI files.
A configuration file consists of sections and option entries. A section start with a ''[section]'' header.
Each section can have different ``name=value`` (``name: value`` is also accepted) option entries, with
continuations in the style of `RFC 822 <https://www.ietf.org/rfc/rfc0822.txt>`_
(see section 3.1.1, “LONG HEADER FIELDS”).
Note that leading and trailing whitespaces are removed from values.

A configuration file for lograptor includes three fixed-named sections (*main*,
*patterns* and *fields*) and at least one section for the default report (*default_report*).
Other sections can be added in order to configure additional output channels or reports.


**************
[main] SECTION
**************

.. envvar:: confdir

    This is where lograptor should look for apps configuration information,
    most notably, *conf.d* directory. See `lograptor-apps(5) <lograptor-apps.html>`_
    for more info on apps configuration.

.. envvar:: logdir

    Where the system logs are located. Useful to shortening log path specification in
    application's configuration files.

.. envvar:: tmpdir

    Where to create temporary directories and put temporary files. Note that log files
    can grow VERY big and lograptor might need similar space for processing purposes.
    Make sure there is no danger of filling up that partition. A good place is /var/tmp,
    since that is usually a separate partition dedicated entirely for logs.

.. envvar::

    The file where to log application errors (/var/log/lograptor.log for default).

.. envvar:: from_address

    Use a specific sender address when sending reports or notifications.
    Defaults to address *root@<HOST_FQDN>*.

.. envvar:: smtp_server

    Use this smtp server when sending notifications. Can be either a hostname
    of an SMTP server to use, or the location of a sendmail binary.
    If the value starts with a "/" is considered a path.
    E.g. valid entries::

        smtp_server = mail.example.com

        smtp_server = /usr/sbin/sendmail -t

.. envvar:: encodings

    A comma-separated list of
    `standard encodings's codecs <https://docs.python.org/3.6/library/codecs.html#standard-encodings>`_
    to use for accessing the log resources. For default its value is 'uft-8, latin1, latin2'.

.. envvar:: mapexp

    The dimension of translation tables for
    `--anonymize <lograptor.html#cmdoption--anonymize>`_ option. The number is
    the power of 10 that represents the maximum extension of each table (default is 4).


******************
[patterns] SECTION
******************

This section includes these basic pattern rules:

.. envvar:: DNSNAME

    Regular expression pattern for DNS names matching.

.. envvar:: IPV4_ADDRESS

    Regular expression pattern for IPv4 addresses matching.

.. envvar:: IPV6_ADDRESS

    Regular expression pattern for IPv6 addresses matching.

.. envvar:: EMAIL

    Regular expression pattern for RFC824 e-mail address matching.

.. envvar:: USERNAME

    Regular expression pattern for username matching.

.. envvar:: ID

    Regular expression pattern for numerical ID matching.

.. envvar:: ASCII

    Regular expression pattern for ASCII characters matching.

These rules are essential for a correct program execution. You don't need to add basic
pattern rules to you configuration files because are embedded in program defaults.
You can redefine the basic patterns pattern rules but you have to make sure the new
patterns are conform with regexp syntax to avoid execution errors.
Basic pattern customization is useful to match non-ortodox log elements or if you want
to simplify the patterns to slightly speed-up the processing.

Declare additional pattern options if you want to define also additional fields in
your configuration.
All the pattern options maybe declared using name with uppercase letters, for clarity
and for avoiding collisions with field names.

Defined pattern can be used as template strings in the pattern rules of the applications.


****************
[fields] SECTION
****************

This section contains the fields that can be included in lograptor filters
(`command option -F <lograptor.html#cmdoption-F>`_) and in
`application's pattern rules <lograptor-apps.html>`_.

Each field declaration maybe a template regex pattern, that uses the declared patterns
as template variables. A string interpolation is then used to create the effective
regexp patterns during lograptor execution.

The default configuration includes 8 predefined fields:

.. envvar:: user

    Field for usernames (defaults to ``(|${USERNAME})``).

.. envvar:: mail

    Field for email addresses (defaults to ``${EMAIL}``).

.. envvar:: from

    Field for sender email addresses (defaults to ``${EMAIL}``).

.. envvar:: rcpt

    Field for recipient email addresses (defaults to ``$${EMAIL}``).

.. envvar:: client

    Field for client IP/name (defaults to
    ``(${DNSNAME}|${IPV4_ADDRESS}|${DNSNAME}\[${IPV4_ADDRESS}\])``).

.. envvar:: pid

    Field for process IDs (defaults to ``${ID}``).

.. envvar:: uid

    Field for user IDs (defaults to ``${ID}``).

.. envvar:: msgid

    Field for message IDs (defaults to ``${ASCII}``).

Those filters are usually skipped in the configuration files because are embedded in the
lograptor's defaults.


***********************
OUTPUT CHANNEL SECTIONS
***********************

The default output channel is *stdout* that is the standard output terminal channel
(*TermChannel*). Other types of channels can be defined, currently you can choose
either a *Mail Channel* or a *File Channel*.

Channel types have two common options and some characteristic options. Other options are ignored.
A channel section has a name of format *<channel-name>_channel*. The defined channels are
usable within the option `--output option <lograptor.html#cmdoption--output>`_.

.. py:attribute:: type

    The channel type. Type must be set to "tty" for a terminal channel (*TermChannel*),
    "mail" for *MailChannel* and "file" for a *FileChannel".

.. py:attribute:: formats

    Can be one a comma-separated list of the following: *text*, *html*, or *csv*.


Mail Channel SECTIONS
---------------------

These are the custom options used by *MailChannel* declaration sections:

.. py:attribute:: mailto

    The list of email addresses where to mail the report. Separate
    multiple entries by a comma. If omitted, "root@localhost" will be
    used.

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


File Channel SECTIONS
---------------------

These are the custom options used by *FileChannel* declaration sections:

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


***************
REPORT SECTIONS
***************

A report section has a name of format *<report-name>_report*. The defined reports are
usable within the option `--report option <lograptor.html#cmdoption--report>`_.

These are the entries that can be declared within a report section:

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


The *subreport options* define the report logical divisions. The subreports are
inserted in the report using the interpolation of variable string "${subreport}".
You can declare a subreport option using an option name thas has a "_subreport" suffix.
The order of subreports's declaration is preserved in report composition.
In the default report configuration there are 4 subreports defined:

.. envvar:: logins_subreport

    User's "logins" subreport.

.. envvar:: email_subreport

    E-mail ("email") subreport.

.. envvar:: commands_subreport

    System "commands" subreport.

.. envvar:: databases_subreport

    Databases lookups subreport.

You could add your own subreports: this can be a needs when you expand the applications
configurations provided.
To composite the report the subreports are then referred in application's "report data" sections.
See `lograptor-apps(5) <lograptor-apps.html>`_ for more details on app's report rules.


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
`lograptor-apps(5) <lograptor-apps.html>`_,
`lograptor-examples(5) <lograptor-examples.html>`_,

