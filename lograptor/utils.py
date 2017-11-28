# -*- coding: utf-8 -*-
"""
This module contains various utility functions for lograptor.
"""
#
# Copyright (C), 2011-2017, by SISSA - International School for Advanced Studies.
#
# This file is part of lograptor.
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
# along with lograptor; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# See the file 'LICENSE' in the root directory of the present
# distribution for more details.
#
# @Author Davide Brunato <brunato@sissa.it>
#
import sys
import os
import stat
import string
from functools import wraps

from .tui import ProgressBar

GZIP_CHUNK_SIZE = 8192


def do_chunked_gzip(infh, outfh, filename):
    """
    A memory-friendly way of compressing the data.
    """
    import gzip

    gzfh = gzip.GzipFile('rawlogs', mode='wb', fileobj=outfh)

    if infh.closed:
        infh = open(infh.name, 'r')
    else:
        infh.seek(0)
        
    readsize = 0
    sys.stdout.write('Gzipping {0}: '.format(filename))

    if os.stat(infh.name).st_size:
        infh.seek(0)
        progressbar = ProgressBar(sys.stdout, os.stat(infh.name).st_size, "bytes gzipped")
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

    gzfh.close()


def mail_message(smtp_server, message, from_address, rcpt_addresses):
    """
    Send mail using smtp.
    """
    if smtp_server[0] == '/':
        # Sending the message with local sendmail
        p = os.popen(smtp_server, 'w')
        p.write(message)
        p.close()
    else:
        # Sending the message using a smtp server
        import smtplib

        server = smtplib.SMTP(smtp_server)
        server.sendmail(from_address, rcpt_addresses, message)
        server.quit()


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


def field_multisub(strings, field, values):
    result = set()
    for s in strings:
        result.update(
            [string.Template(s).safe_substitute({field: v}) for v in values]
        )
    return list(result)


def exact_sub(s, mapping):
    fields = list()
    for key, value in mapping.items():
        new_s = string.Template(s).safe_substitute({key: value})
        if new_s != s:
            fields.append(key)
            s = new_s
    return s, fields


def dummy(*args, **kwargs):
    return


def build_dispatcher(objects, func_name):
    _functions = [getattr(obj, func_name) for obj in objects]
    if not all([callable(f) for f in _functions]):
        raise TypeError('%r: not a callable for all objects %r' % (func_name, objects))

    def multi_dispatcher(*args, **kwargs):
        for _func in _functions:
            _func(*args, **kwargs)

    if not objects:
        return dummy
    elif len(objects) == 1:
        return getattr(objects[0], func_name)
    else:
        return multi_dispatcher


def results_to_string(results):
    return u', '.join([
        u'%s(%s)' % (key, results[key])
        for key in sorted(results, key=lambda x: results[x], reverse=True)
    ])


def is_pipe(fd):
    return stat.S_ISFIFO(os.fstat(fd).st_mode)


def is_redirected(fd):
    return stat.S_ISREG(os.fstat(fd).st_mode)



def protected_property(func):
    """
    Class method decorator that creates a property that returns the protected attribute
    or the value returned by the wrapped method, if the protected attribute is not defined.
    """
    if func.__name__.startswith('_'):
        raise ValueError("%r: Cannot decorate a protected method!" % func)

    @property
    @wraps(func)
    def proxy_wrapper(self):
        try:
            return getattr(self, '_%s' % func.__name__)
        except AttributeError:
            pass
        return func(self)

    return proxy_wrapper


def normalize_path(path, base_path=None):
    path = path.strip()
    if path.startswith('/') or base_path is None:
        return path
    elif path.startswith('./'):
        return os.path.join(os.path.dirname(base_path), path[2:])
    else:
        return os.path.join(os.path.dirname(base_path), path)
