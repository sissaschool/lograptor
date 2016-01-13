#!/usr/bin/env python
"""
This module contains various utility functions for Lograptor.
"""
##
# Copyright (C) 2012-2016 by SISSA - International School for Advanced Studies
#
# This file is part of Lograptor.
#
# Lograptor is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Lograptor is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Lograptor; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# @Author Davide Brunato <brunato@sissa.it>
#
##

import sys
import os
import logging
import errno
 
import lograptor.tui

logger = logging.getLogger('lograptor')

GZIP_CHUNK_SIZE = 8192


def set_logger(loglevel):
    """
    Setup a basic logger with an handler and a formatter, using a
    classic numerical range [0..5]. If a logger is already defined
    do nothing.
    """
    if logger.handlers:
        return
    
    loglevel = max(logging.DEBUG, logging.CRITICAL - loglevel * 10)

    logger.setLevel(loglevel)
    lh = logging.StreamHandler()
    lh.setLevel(loglevel)
    
    if loglevel <= logging.DEBUG:
        formatter = logging.Formatter("[%(levelname)s:%(module)s:%(funcName)s: "
                                      "%(lineno)s] %(message)s")
    elif loglevel <= logging.INFO:
        formatter = logging.Formatter("[%(levelname)s:%(module)s] %(message)s")
    else:
        formatter = logging.Formatter("%(levelname)s: %(message)s")

    lh.setFormatter(formatter)
    logger.addHandler(lh)


def do_chunked_gzip(infh, outfh, filename):
    """
    A memory-friendly way of compressing the data.
    """
    import gzip

    gzfh = gzip.GzipFile('rawlogs', mode='wb', fileobj=outfh)

    if infh.closed:
        infh = open(infh.name, 'r')
        
    readsize = 0
    sys.stdout.write('Gzipping {0}: '.format(filename))

    infh.seek(0)
    progressbar = lograptor.tui.ProgressBar(sys.stdout, os.stat(infh.name).st_size,
                                            "bytes gzipped")
    while True:
        chunk = infh.read(GZIP_CHUNK_SIZE)
        if not chunk:
            break

        if sys.version_info[0] >= 3:
            # noinspection PyArgumentList
            gzfh.write(bytes(chunk, "utf-8"))
        else:
            gzfh.write(chunk)
            
        readsize += len(chunk)
        progressbar.redraw(readsize)
        logger.debug('Wrote {0} bytes'.format(len(chunk)))

    gzfh.close()


def mail_smtp(smtpserv, fromaddr, toaddr, msg):
    """
    Send mail using smtp.
    """
    import smtplib

    logger.info('Mailing via SMTP server {0}'.format(smtpserv))

    server = smtplib.SMTP(smtpserv)
    server.sendmail(fromaddr, toaddr, msg)
    server.quit()


def mail_sendmail(sendmail, msg):
    """
    Send mail using sendmail.
    """
    logger.info('Mailing the message via sendmail')

    p = os.popen(sendmail, 'w')
    p.write(msg)
    p.close()


def get_value_unit(value, unit, prefix):
    """
    Return a human-readable value with unit specification. Try to
    transform the unit prefix to the one passed as parameter. When
    transform to higher prefix apply nearest integer round. 
    """
    prefixes = ('', 'K', 'M', 'G', 'T')

    if len(unit):
        if unit[:1] in prefixes:
            valprefix = unit[0] 
            unit = unit[1:]
        else:
            valprefix = ''
    else:
        valprefix = ''
    
    while valprefix != prefix:
        uidx = prefixes.index(valprefix)

        if uidx > prefixes.index(prefix):
            value *= 1024
            valprefix = prefixes[uidx-1]
        else:
            if value < 10240:
                return value, '{0}{1}'.format(valprefix, unit)
            value = int(round(value/1024.0))
            valprefix = prefixes[uidx+1]
    return value, '{0}{1}'.format(valprefix, unit)


def htmlsafe(unsafe):
    """
    Escapes all x(ht)ml control characters.
    """
    unsafe = unsafe.replace('&', '&amp;')
    unsafe = unsafe.replace('<', '&lt;')
    unsafe = unsafe.replace('>', '&gt;')
    return unsafe


def get_fmt_results(resdict, limit=5, sep='::', fmt=None):
    """
    Return a list of formatttes strings representation on a result dictionary.
    The elements of the key are divided by a separator string. The result is
    appended after the key beetween parentheses. Apply a format transformation
    to odd elements of the key if a fmt parameter is passed.
    """
    reslist = []
    for key in sorted(resdict, key=lambda x: resdict[x], reverse=True):
        if len(reslist) >= limit and resdict[key] <= 1:
            break
        if fmt is not None:
            fmtkey = []
            for i in range(len(key)):
                if i % 2 == 1:
                    fmtkey.append(fmt.format(key[i]))
                else:
                    fmtkey.append(key[i])
            reslist.append(u'{0}({1})'.format(sep.join(fmtkey), resdict[key]))
        else:
            reslist.append(u'{0}({1})'.format(sep.join(key), resdict[key]))
    else:
        return reslist
    if fmt is not None:
        reslist.append(fmt.format(u'[%d more skipped]' % (len(resdict)-len(reslist))))
    else:
        reslist.append(u'[%d more skipped]' % (len(resdict)-len(reslist)))
    return reslist
