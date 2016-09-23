# -*- coding: utf-8 -*-
"""
This module defines communication channels for the program.
"""
#
# Copyright (C), 2011-2016, by Davide Brunato and
# SISSA (Scuola Internazionale Superiore di Studi Avanzati).
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

from .exceptions import LograptorConfigError
from .info import __version__
from .utils import mail_sendmail, mail_smtp, do_chunked_gzip


logger = logging.getLogger(__name__)


class BaseChannel(object):
    """
    Base class for Lograptor's channels.
    """

    def __init__(self, name, config):
        self.name = name
        self.formats = list(set(re.split('\s*, \s*', config.getstr('channel.%s' % name, 'formats'))))
        logger.debug('Formats ={0}'.format(self.formats))

    def __repr__(self):
        return u"<%s '%s' at %#x>" % (self.__class__.__name__, self.name, id(self))

    def has_format(self, ext):
        return (ext == 'txt' and 'plain' in self.formats) or ext in self.formats

    def has_format2(self, fmt):
        return fmt in self.formats
        #return (ext == 'txt' and 'plain' in self.formats) or ext in self.formats

    def is_raw(self):
        return True

    @staticmethod
    def get_line_printer():
        """
        Return the printer function for send macthed lines to channel.
        :return:
        """
        raise NotImplementedError(
            "%r: you must provide a concrete get_line_printer() method"
        )


class StdoutChannel(BaseChannel):
    """
    Channel for standard output.
    """
    @staticmethod
    def get_line_printer():
        return print


class MailChannel(BaseChannel):
    """
    Channel type to send results with SMTP.
    """
    def __init__(self, section, config):
        super(MailChannel, self).__init__(section, config)
        self.email_address = config['email_address']
        self.smtp_server = config['smtp_server']

        self.mailto = list(set(re.split('\s*, \s*', config.getstr(section, 'mailto'))))
        logger.debug('Recipients list ={0}'.format(self.mailto))

        self.rawlogs = config.getboolean(section, 'include_rawlogs')
        if self.rawlogs:
            self.rawlogs_limit = config.getint(section, 'rawlogs_limit') * 1024
        else: 
            self.rawlogs_limit = 0
        
        logger.debug('rawlogs={0}'.format(self.rawlogs))
        logger.debug('rawlogs_limit={0}'.format(self.rawlogs_limit))

        self.gpg_encrypt = config.getstr(section, 'gpg_encrypt')
        if self.gpg_encrypt:
            self.gpg_keyringdir = config.get['gpg_keyringdir']

            gpg_recipients = config.get['gpg_recipients']
            if gpg_recipients is not None:
                keyids = gpg_recipients.split(',')
                self.gpg_recipients = []
                for keyid in keyids:
                    keyid = keyid.strip()
                    logger.debug('adding gpg_recipient=' + keyid)
                    self.gpg_recipients.append(keyid)

            gpg_signers = config['gpg_signers']
            if self.gpg_signers is not None:
                keyids = gpg_signers.split(',')
                self.gpg_signers = []
                for keyid in keyids:
                    keyid = keyid.strip()
                    logger.debug('adding gpg_signer=' + keyid)
                    self.gpg_signers.append(keyid)
        
        logger.debug('gpg_encrypt={0}'.format(self.gpg_encrypt))        

    def __repr__(self):
        return u'{0}({1}: mailto={2})'.format(self.section, self.name, u','.join(self.mailto))

    def send(self, title, report_parts, rawfh):
        """
        Publish by sending the report by e-mail
        """
        from email.mime.base import MIMEBase
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.utils import formatdate, make_msgid

        logger.info('Creating an email message')

        logger.debug('Creating a main header')
        root_part = MIMEMultipart('mixed')
        root_part.preamble = 'This is a multi-part message in MIME format.'

        has_text_plain = any(text_part.ext == 'txt' for text_part in report_parts)

        logger.debug('Creating the text/"text_type" parts')
        for text_part in report_parts:

            # Skip report formats not related with this channel
            if not self.has_format(text_part.ext):
                continue

            if text_part.ext == 'txt' or (not has_text_plain and text_part.ext == 'html'):
                root_part.attach(MIMEText(text_part.text, text_part.ext, 'utf-8'))
            else:
                attach_part = MIMEText(text_part.text, text_part.ext, 'utf-8')
                attach_part.add_header('Content-Disposition', 'attachment',
                                       filename='{0}.{1}'.format(text_part.title, text_part.ext))
                root_part.attach(attach_part)

        if self.rawlogs:
            try:
                import cStringIO
                out = cStringIO.StringIO()
            except ImportError:
                import io
                out = io.StringIO()  
            
            do_chunked_gzip(rawfh, out, filename='raw.log.gz')
            out.seek(0, os.SEEK_END)
            size = out.tell()
            
            if size > self.rawlogs_limit:
                logger.warning('{0} is over the defined max of "{1}"'
                               .format(size, self.rawlogs))
                logger.warning('Not attaching the raw logs')
            else:
                logger.debug('Creating the application/x-gzip part')
                attach_part = MIMEBase('application', 'x-gzip')
                attach_part.set_payload(out.getvalue())

                from email.encoders import encode_base64

                logger.debug('Encoding the gzipped raw logs with base64')
                encode_base64(attach_part)
                attach_part.add_header('Content-Disposition', 'attachment',
                                       filename='raw.log.gz')
                root_part.attach(attach_part)

        if self.gpg_encrypt:
            logger.info('Encrypting the message')

            from StringIO import StringIO
            try:
                import gpgme

                if self.gpg_keyringdir and os.path.exists(self.gpg_keyringdir):
                    logger.debug('Setting keyring dir to {0}'.format(
                                 self.gpg_keyringdir))
                    os.environ['GNUPGHOME'] = self.gpg_keyringdir

                msg = root_part.as_string()
                logger.debug('----Cleartext follows----')
                logger.debug(msg)
                logger.debug('----Cleartext ends----')

                cleartext = StringIO(msg)
                ciphertext = StringIO()

                ctx = gpgme.Context()

                ctx.armor = True

                recipients = []
                signers = []

                logger.debug('gpg_recipients={0}'.format(self.gpg_recipients))
                logger.debug('gpg_signers={0}'.format(self.gpg_signers))

                if self.gpg_recipients is not None:
                    for recipient in self.gpg_recipients:
                        logger.debug('Looking for an encryption key for {0}'.format(
                                     recipient))
                        recipients.append(ctx.get_key(recipient))
                else:
                    for key in ctx.keylist():
                        for subkey in key.subkeys:
                            if subkey.can_encrypt:
                                logger.debug('Found can_encrypt key={0}'.format(
                                             subkey.keyid))
                                recipients.append(key)
                                break

                if self.gpg_signers is not None:
                    for signer in self.gpg_signers:
                        logger.debug('Looking for a signing key for {0}'.format(
                                     signer))
                        signers.append(ctx.get_key(signer))

                if len(signers) > 0:
                    logger.info('Encrypting and signing the report')
                    ctx.signers = signers
                    ctx.encrypt_sign(recipients, gpgme.ENCRYPT_ALWAYS_TRUST,
                                     cleartext, ciphertext)

                else:
                    logger.info('Encrypting the report')
                    ctx.encrypt(recipients, gpgme.ENCRYPT_ALWAYS_TRUST,
                                cleartext, ciphertext)

                logger.debug('Creating the MIME envelope for PGP')

                gpg_envelope_part = MIMEMultipart('encrypted')
                gpg_envelope_part.set_param('protocol',
                                            'application/pgp-encrypted', header='Content-Type')
                gpg_envelope_part.preamble = ('This is an OpenPGP/MIME encrypted message '
                                              '(RFC 2440 and 3156)')

                gpg_mime_version_part = MIMEBase('application', 'pgp-encrypted')
                gpg_mime_version_part.add_header('Content-Disposition',
                                                 'PGP/MIME version identification')
                gpg_mime_version_part.set_payload('Version: 1')

                gpg_payload_part = MIMEBase('application', 'octet-stream', 
                                            name='encrypted.asc')
                gpg_payload_part.add_header('Content-Disposition', 
                                            'OpenPGP encrypted message')
                gpg_payload_part.add_header('Content-Disposition', 'inline',
                                            filename='encrypted.asc')
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
        root_part['X-Mailer'] = u'{0}-{1}'.format(Lograptor.__name__, __version__)
        
        logger.debug('Creating the message as string')
        msg = root_part.as_string()

        logger.debug('----Message follows----')
        logger.debug(msg)
        logger.debug('----Message ends----')

        logger.info('Figuring out if we are using sendmail or smtplib')

        if re.compile('^/').search(self.smtp_server):
            mail_sendmail(self.smtp_server, msg)
        else:   
            mail_smtp(self.smtp_server, self.email_address, self.mailto, msg)

        print('Mailed the report to: {0}'.format(','.join(self.mailto)))


class FileChannel(BaseChannel):
    """
    FileChannel save results of a run into a set of files
    and directories on the hard drive.
    """
    name = 'file'

    def __init__(self, section, config):
        super(FileChannel, self).__init__(section, config)
        self.expire = config.getint(section, 'expire_in')
        self.dirmask = config.getstr(section, 'dirmask')
        self.filemask = config.getstr(section, 'filemask')
        maskmsg = 'Invalid mask for {0}: {1}'

        self.pubdir = config.getstr(section, 'pubdir')

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
        
        self.notify = []

        try:
            notify = config.getstr(section, 'notify')
            if notify:
                for addy in notify.split(','):
                    addy = addy.strip()
                    logger.info('Will notify: {0}'.format(addy))
                    self.notify.append(addy)
        except TypeError:
            pass

        self.fromaddr = config['email_address']
        self.smtp_server = config['smtp_server']

        if self.notify:
            try:
                self.pubroot = config.getstr(section, 'pubroot')
                logger.debug('pubroot={0}'.format(self.pubroot))
            except:
                msg = 'File channel requires a pubroot when notify is set'
                raise LograptorConfigError(msg)
        
        logger.debug('path={0}'.format(self.pubdir))
        logger.debug('filename={0}'.format(self.filename))

    def __repr__(self):
        return u'{0}({1}: pubdir={2}, expire_in={3})'.format(
            self.section, self.name, self.pubdir, self.expire)

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
                    logger.info('Dir {0} did not match dirmask {1}: {2}'.format(
                                entry, dirmask, e))
                    logger.info('Skipping {0}'.format(entry))
                    continue

                if stamp < expire_limit:
                    shutil.rmtree(os.path.join(path, entry))
                    print('File Publisher: Pruned old dir: {0}'.format(
                                entry))
                else:
                    logger.info('{0} is still active'.format(entry))
            else:
                logger.info('{0} is not a directory. Skipping.'.format(entry))

        logger.info('Finished with pruning')
        
    def send(self, title, report_parts, rawfh):
        """
        Publish the report parts to local files. Each report part is a text
        with a title and specific extension. For html and plaintext sending
        the report part is unique, for csv send also the stats and unparsed
        string are plain text and report items are csv texts.
        """
        logger.info('Checking and creating the report directories')

        workdir = os.path.join(self.pubdir, self.dirname)
        filename = None

        if not os.path.isdir(workdir):
            try: 
                os.makedirs(workdir)
            except OSError as e:
                logger.error('Error creating directory "{0}": {0}'.format(workdir, e))
                return

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
            eml['X-Mailer'] = u'{0}-{1}'.format(Lograptor.__name__, __version__)

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
