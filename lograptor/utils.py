#
# Copyright (C), 2011-2020, by SISSA - International School for Advanced Studies.
#
# This file is part of lograptor.
#
# Lograptor is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# file 'LICENSE' in the root directory of the present distribution
# for more details.
#
# @Author Davide Brunato <brunato@sissa.it>
#
import sys
import os
import io
import stat
import string
from functools import wraps
from urllib.request import urlopen

from .tui import ProgressBar

GZIP_CHUNK_SIZE = 8192


def do_chunked_gzip(infh, outfh, filename):
    """
    A memory-friendly way of compressing the data.

    :param infh: input file-like object.
    :param outfh: output file-like object for gzipped data.
    :param filename: basename for gzipped output file.
    """
    import gzip

    gzfh = gzip.GzipFile('rawlogs', mode='wb', fileobj=outfh)

    if isinstance(infh, (io.StringIO, io.BytesIO)):
        input_size = len(infh.getvalue())
    else:
        input_size = os.stat(infh.name).st_size
        if infh.closed:
            infh = open(infh.name, 'r')

    readsize = 0
    sys.stdout.write('Gzipping {0}: '.format(filename))

    if input_size:
        infh.seek(0)
        progressbar = ProgressBar(sys.stdout, input_size, "bytes gzipped")
        while True:
            chunk = infh.read(GZIP_CHUNK_SIZE)
            if not chunk:
                break

            gzfh.write(bytes(chunk, "utf-8"))
            readsize += len(chunk)
            progressbar.redraw(readsize)

    gzfh.close()


def mail_message(smtp_server, message, from_address, rcpt_addresses):
    """
    Send an e-mail message using the smtp protocol.

    :param smtp_server: a full path to an external command \
    (eg. "/usr/sbin/sendmail -t") or an address of a SMTP server.
    :param message: the message to send, complete of headers.
    :param from_address: the sender e-mail address.
    :param rcpt_addresses: a list with recipient e-mail addresses.
    """
    if smtp_server[0] == '/':
        # Sending the message with local sendmail
        p = os.popen(smtp_server, 'w')
        p.write(message)
        p.close()
    else:
        # Sending the message using a smtp server (works if no login is required)
        import smtplib                                          # pragma: no cover
        server = smtplib.SMTP(smtp_server)                      # pragma: no cover
        server.sendmail(from_address, rcpt_addresses, message)  # pragma: no cover
        server.quit()                                           # pragma: no cover


MEASURE_UNITS = {'', 'B', 'Bytes', 'Byte', 'B/s', 'bps', 'bit/s', 'b/s'}

METRIC_PREFIXES = {
    '': (0, 'K'), 'k': (1, 'M'),
    'K': (1, 'M'), 'Ki': (1, 'Mi'),
    'M': (2, 'G'), 'Mi': (2, 'Gi'),
    'G': (3, 'T'), 'Gi': (3, 'Ti'),
    'T': (4, 'P'), 'Ti': (4, 'Pi'),
    'P': (5, 'E'), 'Pi': (5, 'Ei'),
    'E': (6, 'Z'), 'Ei': (6, 'Zi'),
    'Z': (7, 'Y'), 'Zi': (7, 'Yi'),
    'Y': (8, None), 'Yi': (7, None),
}


def get_value_unit(value, unit='', prefix='T'):
    """
    Return a human-readable value with unit specification. Try to
    transform the unit prefix to the one passed as parameter. When
    transform to higher prefix apply nearest integer round.

    :param value: a numerical value.
    :param unit: a string containing the measure unit and maybe a metric prefix. \
    To use a base of 1024 provide an IEC metric prefix (eg. TiB instead of TB).
    :param prefix: the target metric prefix, for default is 'T' (Tera).
    """
    if not unit:
        return value, ''

    try:
        unit_exponent = METRIC_PREFIXES[unit[:1]][0]
    except KeyError:
        unit_prefix, unit_exponent = '', 0
    else:
        if unit[1:2] == 'i' and unit[:1] != 'k':
            unit_prefix, unit = unit[:2], unit[2:]
        else:
            unit_prefix, unit = unit[:1], unit[1:]

    if unit not in MEASURE_UNITS:
        raise ValueError("unknown measure unit {!r}".format(unit))

    try:
        diff_exponent = unit_exponent - METRIC_PREFIXES[prefix][0]
    except KeyError:
        raise ValueError("unknown metric prefix {!r}".format(prefix))
    else:
        if prefix and unit_prefix:
            if unit_prefix.endswith('i'):
                if not prefix.endswith('i'):
                    prefix += 'i'
            elif prefix.endswith('i'):
                prefix = prefix[0]

    base = 1024 if prefix.endswith('i') or unit_prefix.endswith('i') else 1000

    if not diff_exponent:
        return value, '{0}{1}'.format(unit_prefix, unit)
    elif diff_exponent > 0:
        return value * base ** diff_exponent, '{0}{1}'.format(prefix, unit)

    for k in range(abs(diff_exponent)):
        if value < base * 10:
            break
        value = int(round(value / float(base)))
        if unit_prefix:
            unit_prefix = METRIC_PREFIXES[unit_prefix][1]
        elif prefix.endswith('i'):
            unit_prefix = 'Ki'
        else:
            unit_prefix = 'k'

    return value, '{0}{1}'.format(unit_prefix, unit)


def htmlsafe(unsafe):
    """Escapes html control characters."""
    return unsafe.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def get_fmt_results(results, limit=5, sep='::', fmt=None):
    """
    Return a list of formatted strings representation on a result dictionary.
    The elements of the key are divided by a separator string. The result is
    appended after the key between parentheses. Apply a format transformation
    to odd elements of the key if a fmt parameter is passed.
    """
    result_list = []
    for key in sorted(results, key=lambda x: results[x], reverse=True):
        if len(result_list) >= limit and results[key] <= 1:
            break

        if fmt is not None:
            fmt_key = []
            for i in range(len(key)):
                if i % 2 == 1:
                    fmt_key.append(fmt.format(key[i]))
                else:
                    fmt_key.append(key[i])
            result_list.append(u'{0}({1})'.format(sep.join(fmt_key), results[key]))
        else:
            result_list.append(u'{0}({1})'.format(sep.join(key), results[key]))
    else:
        return result_list

    if fmt is not None:
        result_list.append(fmt.format('[%d more skipped]' % (len(results) - len(result_list))))
    else:
        result_list.append('[%d more skipped]' % (len(results) - len(result_list)))

    return result_list


def field_multisub(strings, field, values):
    return list({
        string.Template(s).safe_substitute({field: v}) for v in values for s in strings
    })


def exact_sub(s, mapping):
    fields = list()
    for key, value in mapping.items():
        new_s = string.Template(s).safe_substitute({key: value})
        if new_s != s:
            fields.append(key)
            s = new_s
    return s, fields


def safe_expand(template, substitution_map):
    """
    Safe string template expansion. Raises an error if the provided
    substitution map has circularities.
    """
    for _ in range(len(substitution_map) + 1):
        _template = template
        template = string.Template(template).safe_substitute(substitution_map)
        if template == _template:
            return template
    else:
        raise ValueError("substitution map has a circularity!")


def results_to_string(results):
    return ', '.join([
        '%s(%s)' % (key, results[key])
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
        raise ValueError("%r: cannot decorate a protected method!" % func)

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
    if path.startswith('~/'):
        home = os.path.expanduser("~/")
        return os.path.join(os.path.dirname(home), path[2:])
    elif path.startswith('/') or base_path is None:
        return path
    elif path.startswith('./'):
        return os.path.join(base_path, path[2:])
    else:
        return os.path.abspath(os.path.join(base_path, path))


def open_resource(source):
    """
    Opens a resource in binary reading mode.

    :param source: a filepath or an URL.
    """
    try:
        return open(source, mode='rb')
    except (IOError, OSError):
        try:
            resource = urlopen(source)  # source is an URL
        except ValueError:
            pass
        else:
            resource.name = resource.url
            return resource

        raise
    except TypeError:
        if hasattr(source, 'read') and hasattr(source, 'readlines'):
            return source  # source is already a file-like object
        raise
