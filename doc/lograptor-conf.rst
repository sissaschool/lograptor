Lograptor configuration
=======================

NAME
----
*lograptor.conf* \- lograptor configuration

SYNOPSIS
--------
*lograptor* config file is a simple plaintext file in win.ini style format.

Location
--------
Lograptor will look in /etc/lograptor/lograptor.conf by default, but you can
override that by passing \--conf switch on the command line.

Section "[main]"
----------------
**cfgdir**
    This is where lograptor should look for other configuration information,
    most notably, *conf.d* directory. See :ref:`lograptor-apps(5)` for more info.
**logdir**
    Where the system logs are located. Useful to shortening log path
    specification in application's configuration files.
**tmpdir**
    Where to create temporary directories and put temporary files. Note
    that log files can grow VERY big and lograptor might need similar
    space for processing purposes. Make sure there is no danger
    of filling up that partition. A good place on a designated loghost is
    /var/tmp, since that is usually a separate partition dedicated
    entirely for logs.
**pidfile**
    Location of pidfile (default: /var/run/lograptor.pid) that is created when
    lograptor is called with --cron parameter. This is useful to avoid multiple
    runs.
**fromaddr**
    Use a specific sender address when sending reports or notifications.
    Defaults to address *root@<FQDN of the host>*'.
**smtpserv**
    Use this smtp server when sending notifications. Can be either a
    hostname or a path to sendmail. Defaults to "/usr/sbin/sendmail -t".

Section "[pattern]"
-------------------
All the patterns are commented because is wrapped in the configuration code.
It is possible to customize uncommenting and modifying the patterns, but
at your risk that the pattern doesn't match properly yet.
This is useful to include in match non-ortodox log elements or if you want to
simplify the patterns to slightly speed-up the processing.

**rfc3164_pattern**
    This is the path for legacy BSD log header searches, compliant to
    RFC 3164 specifications.
**rfc5424_pattern**
    This is the path for IETF log header searches, compliant to
    RFC 5424 specifications.
**ipaddr_pattern**
    This is the pattern for IP addresses matching.
**dnsname_pattern**
    This is the pattern for DNS names matching.
**email_pattern**
    This is the pattern for RFC824 e-mail address matching.
**username_pattern**
    This is the pattern for username matching.

Section "[report]"
------------------
**title**
    What should be the title of the report. For mailed reports, this is
    the subject of the message. For the ones published on the web, this is
    the title of the page (as in <title></title>) for html reports, or the
    main header for plain text reports.
**html_template**
    Which template should be used for the final html reports. See the
    source of the default template for the format used.
**text_template**
    Which template should be used for the final plain text reports. See the
    source of the default template for the format used.
**include_unparsed**
    Can be either "yes" or "no". If "yes" is specified, strings that didn't
    match any of the modules will be appended to the report. Usable for
    application calibration and pattern rule debugging.
**max_unparsed**
    Maximum unparsed lines to consider (default is 1000). Reached the limit the
    unparsed logs are no more collected. This avoid an excessive growth of
    the final report.

Publishers
----------
Lists the publishers to use. The value is the name of the section
where to look for the publisher configuration. E.g.:
.br
.B publishers = nfspub
.br
will look for a section called "[nfspub]" for publisher
initialization. The name of the publisher has nothing to do with the
method it uses for publishing. The fact that the default are named
[file] and [mail] is only a matter of convenience. List multiple
values separated by a comma.

**method**
    Method must be set to "mail" for this publisher to be considered a
    mail publisher.
**smtpserv**
    Can be either a hostname of an SMTP server to use, or the location of
    a sendmail binary. If the value starts with a "/" it will be
    considered a path. E.g. valid entries:

    smtpserv = mail.example.com

    smtpserv = /usr/sbin/sendmail -t

**mailto**
    The list of email addresses where to mail the report. Separate
    multiple entries by a comma. If ommitted, "root@localhost" will be
    used.
**format**
    Can be one of the following: \fBhtml\fR, \fBplain\fR, or \fBboth\fR. If
    you use a mail client that doesn't support html mail, then you better
    use "plain" or "both", though you will miss out on visual cueing that
    lograptor uses to notify of important events.
**include_rawlogs**
    Whether to include the gzipped raw logs with the message. If set to
    "yes", it will attach the file with all processed logs with the
    message. If you use a file publisher in addition to the mail
    publisher, this may be a tad too paranoid.
**rawlogs_limit**
    If the size of rawlogs.gz is more than this setting (in kilobytes),
    then raw logs will not be attached. Useful if you have a 50Mb log and
    check your mail over a slow uplink.
**gpg_encrypt**
    Logs routinely contain sensitive information, so you may want to
    encrypt the email report to ensure that nobody can read it other than
    designated administrators. Set to "yes" to enable gpg-encryption of the
    mail report. You will need to install mygpgme (installed by default on
    all yum-managed systems).
**gpg_keyringdir**
    If you don't want to use the default keyring (usually /root/.gnupg), you
    can set up a separate keyring directory for lograptor's use. E.g.::

    > mkdir -m 0700 /etc/lograptor/gpg
**gpg_recipients**
    List of PGP key id's to use when encrypting the report. The keys must be in
    the pubring specified in gpg_keyringdir. If this option is omitted, lograptor
    will encrypt to all keys found in the pubring. To add a public key to a
    keyring, you can use the following command::

    > gpg [--homedir=/etc/lograptor/gpg] --import pubkey.gpg

    You can generate the pubkey.gpg file by running "gpg --export KEYID" on your
    workstation, or you can use "gpg --search" to import the public keys from
    the keyserver.
**gpg_signers**
    To use the signing option, you will first need to generate a private key::

    > gpg [--homedir=/etc/lograptor/gpg] --gen-key

    Create a *sign-only RSA key* and leave the passphrase empty. You can then
    use "gpg --export" to export the key you have generated and import it on the
    workstation where you read mail.
    If gpg_signers is not set, the report will not be signed.

File Publisher
^^^^^^^^^^^^^^
**method**
    Method must be set to "file" for this config to work as a file
    publisher.
**path**
    Where to place the directories with reports. A sensible location would
    be in /var/www/html/lograptor. Note that the reports may contain
    sensitive information, so make sure you place a .htaccess in that
    directory and require a password, or limit by host.
**dirmask, filemask**
    These are the masks to be used for the created directories and
    files. For format values look at strftime documentation here:
    http://www.python.org/doc/current/lib/module-time.html
**save_rawlogs**
    Whether to save the raw logs in a file in the same directory as the report.
    The default is off, since you can easily look in the original log sources.
**expire_in**
    A digit specifying the number of days after which the old directories
    should be removed. Default is 7.
**notify**
    Optionally send notifications to these email addresses when new
    reports become available. Comment out if no notification is
    desired. This is definitely redundant if you also use the mail
    publisher.
**pubroot**
    When generating a notification message, use this as publication root
    to make a link. E.g.::

    pubroot = http://www.example.com/lograptor

    will make a link: http://www.example.com/lograptor/dirname/filename.html

COMMENTS
--------
Lines starting with "#" will be considered commented out.

AUTHORS
-------
Davide Brunato <brunato@sissa.it>

SEE ALSO
--------
:ref:`lograptor(8)`, :ref:`lograptor-apps(5)`, :ref:`lograptor-examples(5)`

