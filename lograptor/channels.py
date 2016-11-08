# -*- coding: utf-8 -*-
"""
This module defines communication channels for the program.
"""
#
# Copyright (C), 2011-2016, by SISSA - International School for Advanced Studies.
#
# This file is part of Lograptor.
#
# Lograptor is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# See the file 'LICENSE' in the root directory of the present
# distribution or http://www.gnu.org/licenses/gpl-2.0.en.html.
#
# @Author Davide Brunato <brunato@sissa.it>
#
from __future__ import print_function

import os
import re
import time
import shutil
import logging
import sys
import tempfile

try:
    from io import BytesIO, StringIO
except ImportError:
    # Python 2 fallback
    from io import StringIO
    BytesIO = StringIO

from .exceptions import LograptorConfigError
from .info import __version__
from . import __name__ as package_name
from .utils import mail_sendmail, mail_smtp, do_chunked_gzip


logger = logging.getLogger(__name__)


class grep_colors:
    """
    Define a structure for grep color codes.
    """
    DEFAULT_SPEC = "ms=01;31:mc=01;31:sl=:cx=:fn=35:ln=32:bn=32:se=36"
    mt = ms = mc = sl = cx = fn = ln = bn = se = ''

    def __init__(self, color_spec=None):
        color_spec = color_spec or self.DEFAULT_SPEC
        color_dict = dict([item.strip().split('=') for item in self.DEFAULT_SPEC.split(':')])
        try:
            spec_dict = dict([item.strip().split('=') for item in color_spec.split(':')])
        except ValueError as err:
            logger.error("wrong GREP_COLORS spec: %r" % err)
        else:
            if 'mt' in spec_dict:
                spec_dict['mc'] = spec_dict['ms'] = spec_dict['mt']
            color_dict.update(spec_dict)

        self.clear = '\033[0m'
        self.rv = bool(color_dict.get('rv', ''))
        self.ne = bool(color_dict.get('ne', ''))

        for attr in ('mt', 'ms', 'mc', 'sl', 'cx', 'fn', 'ln', 'bn', 'se'):
            values = color_dict.get(attr, '') or '0'
            setattr(self, attr, ''.join(['\033[%dm' % int(v) for v in values.split(';')]))


GREP_COLORS = grep_colors(os.environ.get('GREP_COLORS'))


class BaseChannel(object):
    """
    Abstract base class for Lograptor's channels.
    """
    TEMP_DIR = None

    def __init__(self, name, args, config):
        self.name = name
        self.args = args
        self.config = config
        self.formats = list(set(re.split('\s*, \s*', config.getstr('channel.%s' % name, 'formats'))))
        self.rawfh = None
        logger.debug('Formats ={0}'.format(self.formats))

    def __str__(self):
        return u"<%s '%s'>" % (self.__class__.__name__, self.name)

    def __repr__(self):
        return u"<%s '%s' at %#x>" % (self.__class__.__name__, self.name, id(self))

    def has_format(self, ext):
        return (ext == 'txt' and 'plain' in self.formats) or ext in self.formats

    def open(self):
        pass

    def set_tempdir(self):
        if self.TEMP_DIR:
            return
        tmpdir = self.config.getstr('main', 'tmpdir')
        if tmpdir:
            tempfile.tempdir = tmpdir
        try:
            self.TEMP_DIR = tempfile.mkdtemp('.LOGRAPTOR')
        except OSError:
            raise LograptorConfigError('could not create a temp directory in %r!' % tempfile.tempdir)

    def send_message(self, message):
        raise NotImplementedError("%r: you must provide a concrete send_message() method" % self)

    def send_selected(self, **kwargs):
        raise NotImplementedError("%r: you must provide a concrete send_event() method" % self)

    def send_context(self, **kwargs):
        raise NotImplementedError("%r: you must provide a concrete send_context() method" % self)

    def send_separator(self):
        raise NotImplementedError("%r: you must provide a concrete send_separator() method" % self)

    def send_report(self, report):
        raise NotImplementedError("%r: you must provide a concrete send_report() method" % self)

    def close(self):
        if self.rawfh is not None:
            self.rawfh.close()


class TermChannel(BaseChannel):
    """
    Terminal capable Output Channel
    """
    def __init__(self, name, args, config):
        super(TermChannel, self).__init__(name, args, config)
        if name == 'stdout':
            self._channel = sys.stdout
        color = self.color = args.color == 'always' or args.color == 'auto' and self.isatty()
        invert = GREP_COLORS.rv and self.args.invert
        colon_sep = GREP_COLORS.se + ":" if color else ":"
        dash_sep = GREP_COLORS.se + "-" if color else "-"
        self.group_sep = ''.join([GREP_COLORS.se, '--\n', GREP_COLORS.clear]) if color else "--\n"
        selected_color = GREP_COLORS.cx if invert else GREP_COLORS.sl
        context_color = GREP_COLORS.sl if invert else GREP_COLORS.cx

        if invert:
            self.fmt_matching_selected = ''.join([GREP_COLORS.mc, '%s', GREP_COLORS.cx])
            self.fmt_matching_context = ''.join([GREP_COLORS.ms, '%s', GREP_COLORS.sl])
        else:
            self.fmt_matching_selected = ''.join([GREP_COLORS.ms, '%s', GREP_COLORS.sl])
            self.fmt_matching_context = ''.join([GREP_COLORS.mc, '%s', GREP_COLORS.cx])

        fmt_dict = {
            'filename': ''.join([GREP_COLORS.fn if color else '', '%(filename)s']),
            'line_number': ''.join([GREP_COLORS.ln if color else '', '%(line_number)s']),
            'counter': ''.join([selected_color, '%(counter)s\n', GREP_COLORS.clear]) if color else '%(counter)s\n',
            'selected': ''.join([selected_color, '%(rawlog)s', GREP_COLORS.clear]) if color else '%(rawlog)s',
            'context': ''.join([context_color, '%(rawlog)s', GREP_COLORS.clear]) if color else '%(rawlog)s'
        }

        fmt_parts = []
        if self.args.with_filename or len(self.args.files) > 1 and self.args.with_filename is None:
            fmt_parts.append('filename')
        if self.args.count:
            # When -c/--count option
            fmt_parts.append('counter')
            self.fmt_selected = colon_sep.join([fmt_dict[i] for i in fmt_parts])
            self.fmt_context = ''
        else:
            if self.args.line_number:
                fmt_parts.append('line_number')
            self.fmt_selected = colon_sep.join([fmt_dict[i] for i in fmt_parts + ['selected']])
            self.fmt_context = dash_sep.join(
                [fmt_dict[i] for i in fmt_parts + ['context']]
            )

    def isatty(self):
        try:
            return self._channel.isatty()
        except AttributeError:
            return False

    def send_message(self, message):
        self._channel.write(message)

    def send_selected(self, match=False, **kwargs):
        if self.color:
            if match:
                try:
                    kwargs['rawlog'] = ''.join([
                        item if not pos % 2 else self.fmt_matching_selected % item
                        for pos, item in enumerate(match.re.split(kwargs['rawlog']))
                    ])
                except AttributeError:
                    pass
        self._channel.write(self.fmt_selected % kwargs)

    def send_context(self, match=False, **kwargs):
        if self.color:
            if match:
                kwargs['rawlog'] = ''.join([
                    item if not pos % 2 else self.fmt_matching_context % item
                    for pos, item in enumerate(match.re.split(kwargs['rawlog']))
                ])
        self._channel.write(self.fmt_context % kwargs)

    def send_separator(self):
        self._channel.write(self.group_sep)

    def send_report(self, report):
        for fmt in self.formats:
            try:
                self._channel.write('\n')
                self._channel.write(report[fmt].text)
                self._channel.write('\n')
            except KeyError:
                pass


class NoTermChannel(BaseChannel):

    def __init__(self, name, args, config):
        super(NoTermChannel, self).__init__(name, args, config)
        colon_sep = ":"
        dash_sep = "-"
        self.group_sep = "--\n"
        fmt_dict = {
            'filename': '%(filename)s',
            'line_number': '%(line_number)s',
            'counter': '%(counter)s\n',
            'selected': '%(rawlog)s',
            'context': '%(rawlog)s'
        }

        fmt_parts = []
        if self.args.with_filename or len(self.args.files) > 1 and self.args.with_filename is None:
            fmt_parts.append('filename')
        if self.args.count:
            # When -c/--count option
            fmt_parts.append('counter')
            self.fmt_selected = colon_sep.join([fmt_dict[i] for i in fmt_parts])
            self.fmt_context = ''
        else:
            if self.args.line_number:
                fmt_parts.append('line_number')
            self.fmt_selected = colon_sep.join([fmt_dict[i] for i in fmt_parts + ['selected']])
            self.fmt_context = dash_sep.join(
                [fmt_dict[i] for i in fmt_parts + ['context']]
            )


class MailChannel(NoTermChannel):
    """
    Channel type to send results with SMTP.
    """
    def __init__(self, name, args, config):
        super(MailChannel, self).__init__(name, args, config)
        section = 'channel.%s' % name
        self.email_address = config.getstr('main', 'email_address')
        self.smtp_server = config.getstr('main', 'smtp_server')
        self.mailto = list(set(re.split('\s*, \s*', config.getstr('channel.%s' % name, 'mailto'))))

        # if self.args.report is not None and self.report.need_rawlogs():
        self.rawlogs = config.getbool(section, 'include_rawlogs')
        if self.rawlogs:
            self.set_tempdir()
            self.rawlogs_limit = config.getint('channel.%s' % name, 'rawlogs_limit') * 1024
        else: 
            self.rawlogs_limit = 0

        self.gpg_encrypt = config.getbool(section, 'gpg_encrypt')
        logger.debug('recipients = %r', self.mailto)
        logger.debug('rawlogs = %r', self.rawlogs)
        logger.debug('rawlogs_limit = %r', self.rawlogs_limit)
        logger.debug('gpg_encrypt = %r', self.gpg_encrypt)

        if self.gpg_encrypt:
            self.gpg_keyringdir = config.getstr(section, 'gpg_keyringdir')
            gpg_recipients = config.getstr(section, 'gpg_recipients')
            self.gpg_recipients = [keyid.strip() for keyid in gpg_recipients.split(',') if keyid.strip()]
            gpg_signers = config.getstr(section, 'gpg_signers')
            self.gpg_signers = [keyid.strip() for keyid in gpg_signers.split(',') if keyid.strip()]
            logger.debug('gpg_keyringdir = %r', self.gpg_recipients)
            logger.debug('gpg_recipients = %r', self.gpg_recipients)
            logger.debug('gpg_signers = %r', self.gpg_signers)

    def __repr__(self):
        return u"<%s '%s: (mailto=%r)' at %#x>" % (self.__class__.__name__, self.name, self.mailto, id(self))

    # Create temporary file for matches rawlog
    def open(self):
        if self.rawlogs:
            self.rawfh = tempfile.NamedTemporaryFile(mode='w+', delete=False)

    def send_message(self, message):
        pass

    def send_selected(self, **kwargs):
        if self.rawfh:
            self.rawfh.write(self.fmt_selected % kwargs)

    def send_context(self, **kwargs):
        if self.rawfh:
            self.rawfh.write(self.fmt_context % kwargs)

    def send_separator(self, **kwargs):
        if self.rawfh:
            self.rawfh.write(self.group_sep)

    def send_report(self, report_parts):
        """
        Publish by sending the report by e-mail
        """
        from email.mime.base import MIMEBase
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.utils import formatdate, make_msgid

        title = list(report_parts.values())[0].title

        logger.info('Creating an email message')
        root_part = MIMEMultipart('mixed')
        root_part.preamble = 'This is a multi-part message in MIME format.'
        has_text_plain = 'text' in report_parts

        logger.debug('Creating the text/"text_type" parts')
        for text_part in report_parts.values():
            # Skip report formats not related with this channel
            if not self.has_format(text_part.ext):
                continue

            if text_part.ext == 'txt' or (not has_text_plain and text_part.ext == 'html'):
                root_part.attach(MIMEText(text_part.text, text_part.ext, 'utf-8'))
            else:
                attach_part = MIMEText(text_part.text, text_part.ext, 'utf-8')
                attach_part.add_header(
                    'Content-Disposition', 'attachment', filename='%s.%s' % (text_part.title, text_part.ext)
                )
                root_part.attach(attach_part)

        if self.rawlogs:
            out = BytesIO()
            do_chunked_gzip(self.rawfh, out, filename=u'raw.log.gz')
            out.seek(0, os.SEEK_END)
            size = out.tell()

            if size > self.rawlogs_limit:
                logger.warning('{0} is over the defined max of "{1}"'.format(size, self.rawlogs_limit))
                logger.warning('Not attaching the raw logs')
            else:
                logger.debug('Creating the application/x-gzip part')
                attach_part = MIMEBase('application', 'x-gzip')
                attach_part.set_payload(out.getvalue())

                from email.encoders import encode_base64

                logger.debug('Encoding the gzipped raw logs with base64')
                encode_base64(attach_part)
                attach_part.add_header('Content-Disposition', 'attachment', filename='raw.log.gz')
                root_part.attach(attach_part)

        if self.gpg_encrypt:
            import gpgme
            try:
                if self.gpg_keyringdir and os.path.exists(self.gpg_keyringdir):
                    logger.debug('Setting keyring dir to %r', self.gpg_keyringdir)
                    os.environ['GNUPGHOME'] = self.gpg_keyringdir

                cleartext = BytesIO(root_part.as_string().encode())
                ciphertext = BytesIO()

                ctx = gpgme.Context()
                ctx.armor = True

                if self.gpg_recipients:
                    recipients = [ctx.get_key(recipient) for recipient in self.gpg_recipients]
                else:
                    recipients = []
                    for key in ctx.keylist():
                        for subkey in key.subkeys:
                            if subkey.can_encrypt:
                                logger.debug('Found can_encrypt key=%d', subkey.keyid)
                                recipients.append(key)
                                break

                signers = [ctx.get_key(signer) for signer in self.gpg_signers]
                if signers:
                    logger.info('Encrypting and signing the report')
                    ctx.signers = signers
                    ctx.encrypt_sign(recipients, gpgme.ENCRYPT_ALWAYS_TRUST, cleartext, ciphertext)
                else:
                    logger.info('Encrypting the report')
                    ctx.encrypt(recipients, gpgme.ENCRYPT_ALWAYS_TRUST, cleartext, ciphertext)

                logger.debug('Creating the MIME envelope for PGP')

                gpg_envelope_part = MIMEMultipart('encrypted')
                gpg_envelope_part.set_param('protocol', 'application/pgp-encrypted', header='Content-Type')
                gpg_envelope_part.preamble = 'This is an OpenPGP/MIME encrypted message (RFC 2440 and 3156)'

                gpg_mime_version_part = MIMEBase('application', 'pgp-encrypted')
                gpg_mime_version_part.add_header('Content-Disposition', 'PGP/MIME version identification')
                gpg_mime_version_part.set_payload('Version: 1')

                gpg_payload_part = MIMEBase('application', 'octet-stream', name='encrypted.asc')
                gpg_payload_part.add_header('Content-Disposition', 'OpenPGP encrypted message')
                gpg_payload_part.add_header('Content-Disposition', 'inline', filename='encrypted.asc')
                gpg_payload_part.set_payload(ciphertext.getvalue())

                gpg_envelope_part.attach(gpg_mime_version_part)
                gpg_envelope_part.attach(gpg_payload_part)

                # envelope becomes the new root part
                root_part = gpg_envelope_part

            except ImportError:
                logger.error('Need crypto libraries for gpg_encrypt.')
                logger.error('Install pygpgme for GPG encryption support.')
                logger.error('Not mailing the report out of caution.')
                return

        # Define headers
        root_part['Date'] = formatdate()
        root_part['From'] = self.email_address
        root_part['To'] = ', '.join(self.mailto)
        root_part['Subject'] = title
        root_part['Message-Id'] = make_msgid()
        root_part['X-Mailer'] = u'{0}-{1}'.format(package_name, __version__)
        
        logger.debug('Creating the message as string')
        if re.compile('^/').search(self.smtp_server):
            mail_sendmail(self.smtp_server, root_part.as_string())
        else:   
            mail_smtp(self.smtp_server, self.email_address, self.mailto, root_part.as_string())

        print('Mailed the report to: {0}'.format(','.join(self.mailto)))


class FileChannel(BaseChannel):
    """
    FileChannel save results of a run into a set of files
    and directories on the hard drive.
    """
    name = 'file'

    def __init__(self, section, args, config):
        super(FileChannel, self).__init__(section, args, config)
        self.expire = config.getint(section, 'expire_in')
        self.dirmask = config.getstr(section, 'dirmask')
        self.filemask = config.getstr(section, 'filemask')
        self.pubdir = config.getstr(section, 'pubdir')
        maskmsg = 'Invalid mask for {0}: {1}'

        try:
            self.dirname = time.strftime(self.dirmask, time.localtime())
        except: 
            raise LograptorConfigError(maskmsg.format('dirmask', self.dirmask))

        try: 
            self.filename = time.strftime(self.filemask, time.localtime())
        except TypeError:
            LograptorConfigError(maskmsg.format('filemask', self.filemask))

        self.rawlogs = config.getboolean(section, 'save_rawlogs')       
        if self.rawlogs:
            logger.info('Will save raw logs in the reports directory')

        notify = config.getstr(section, 'notify')
        self.notify = [addy.strip() for addy in notify.split(',') if addy.strip()]

        self.fromaddr = config['email_address']
        self.smtp_server = config['smtp_server']

        if self.notify:
            self.pubroot = config.getstr(section, 'pubroot')
            logger.debug('pubroot=%r', self.pubroot)
            if not self.pubroot:
                raise LograptorConfigError('File channel requires a pubroot when notify is set')
        
        logger.debug('path=%r', self.pubdir)
        logger.debug('filename=%r', self.filename)

    def __repr__(self):
        return u"<%s '%s: pubdir=%r, expire_in=%r' at %#x>" % (
            self.__class__.__name__, self.name, self.pubdir, self.expire, id(self)
        )

    def prune_old(self):
        """
        Removes the directories that are older than a certain date.
        """
        path = self.pubdir
        dirmask = self.dirmask
        expire = self.expire
        logger.info('Pruning directories older than {0} days'.format(expire))
        expire_limit = int(time.time()) - (86400 * expire)

        logger.debug('expire_limit={0}'.format(expire_limit))

        if not os.path.isdir(path):
            logger.info('Dir {0} not found -- skipping pruning'.format(path))
            return

        for entry in os.listdir(path):
            logger.debug('Found: {0}'.format(entry))
            if os.path.isdir(os.path.join(path, entry)):
                try: 
                    stamp = time.mktime(time.strptime(entry, dirmask))
                except ValueError as e:
                    logger.info('Dir %r did not match dirmask %r: %r', entry, dirmask, e)
                    logger.info('Skipping %r', entry)
                    continue

                if stamp < expire_limit:
                    shutil.rmtree(os.path.join(path, entry))
                    logger.info('File Publisher: Pruned old dir: %r', entry)
                else:
                    logger.info('%r is still active', entry)
            else:
                logger.info('%r is not a directory. Skipping.', entry)

        logger.info('Finished with pruning')
        
    def send_report(self, report_parts):
        """
        Publish the report parts to local files. Each report part is a text
        with a title and specific extension. For html and plaintext sending
        the report part is unique, for csv send also the stats and unparsed
        string are plain text and report items are csv texts.
        """
        logger.info('Checking and creating the report directories')

        title = report_parts[0].title

        workdir = os.path.join(self.pubdir, self.dirname)
        filename = None

        if not os.path.isdir(workdir):
            try: 
                os.makedirs(workdir)
            except OSError as e:
                logger.error('Error creating directory "{0}": {0}'.format(workdir, e))
                return

        rawfh = None

        fmtname = '{0}-{1}-{2}.{3}' if len(report_parts) > 1 else '{0}.{3}'

        for i in range(len(report_parts)):
            ext = report_parts[i].ext

            # Skip report formats not related with this channel
            if not self.has_format(ext):
                continue

            filename = fmtname.format(self.filename, i, report_parts[i].title, ext)
            repfile = os.path.join(workdir, filename)
            
            logger.info('Dumping the report part {1} into {0}'.format(repfile, i))
            
            fh = open(repfile, 'w')
            fh.write(report_parts[i].text)
            fh.close()
            print('Report {0}saved in: {1}'.format('part ' if ext == 'csv' else '', repfile))

        if self.notify:
            logger.info('Creating an email message')
            publoc = '{0}/{1}/{2}'.format(self.pubroot, self.dirname, filename)

            from email.mime.text import MIMEText
            eml = MIMEText('New Lograptor report is available at:\r\n{0}'.format(
                           publoc))

            eml['Subject'] = '{0} (report notification)'.format(title)
            eml['To'] = ', '.join(self.notify)
            eml['X-Mailer'] = u'{0}-{1}'.format(package_name, __version__)

            msg = eml.as_string()

            logger.info('Figuring out if we are using sendmail or smtplib')
            if self.smtp_server[0] == '/':
                mail_sendmail(self.smtp_server, msg)
            else:
                mail_smtp(self.smtp_server, self.fromaddr, self.notify, msg)

            print('Notification mailed to: {0}'.format(','.join(self.notify)))

        if self.rawlogs:
            logfilen = '{0}.log'.format(self.filename)
            logfile = os.path.join(workdir, '{0}.gz'.format(logfilen))

            logger.info('Gzipping logs and writing them to {0}'.format(logfilen))
            outfh = open(logfile, 'w+b')
            do_chunked_gzip(rawfh, outfh, logfilen)
            outfh.close()
            print('Gzipped logs saved in: {0}'.format(logfile))

        # Purge old reports
        self.prune_old()
