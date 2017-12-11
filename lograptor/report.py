# -*- coding: utf-8 -*-
"""
This module define classes for building the report produced by a program run.
"""
#
# Copyright (C), 2011-2017, by SISSA - International School for Advanced Studies.
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
import logging
import re
import os
import socket
import time
from collections import namedtuple, OrderedDict, MutableMapping
from string import Template

from .info import __version__
from .exceptions import (LogRaptorNoOptionError, LogRaptorNoSectionError, LogRaptorOptionError,
                         RuleMissingError, LogRaptorConfigError)
from . import tui
from .utils import get_fmt_results, htmlsafe, get_value_unit, normalize_path


logger = logging.getLogger(__package__)

TextPart = namedtuple('TextPart', 'fmt text ext')


class ReportData(MutableMapping):
    """
    Class to manage the report items defined for an
    application's logs parsed by lograptor.
    """
    # RE fixed object to check and extract report table parameters
    _color_regexp = re.compile(r'^([a-z]+|#[0-9a-f]{6})', re.IGNORECASE)
    _function_regexp = re.compile(
        r'^(?P<function>table|top|total)(\((\s*(?P<topnum>\d+)\s*,)?'
        r'\s*(?P<headers>(\"[^\"]*\"(\s*,\s*)?)+)\s*\)|)')
    _report_data_regexp = re.compile(
        r'^\(\s*(?P<condition>\*|(?P<field>(\w)+)(!=|==)\"[^\"]*\")\s*,'
        r'\s*(?P<fields>((\w|\"[^\"]*\")(\s*,\s*)?)+)'
        r'(\s*:\s*(?P<add2res>\+)?(?P<valfld>\w+)(\[(?P<unit>(|K|M|G|T)'
        r'(b|bits|B|Bytes))\])?)?\s*\)')
    
    def __init__(self, name, options, rules):
        self._data = OrderedDict()
        self.name = name
        self.subreport = self.title = self.color = self.function = None
        self.rules = dict()
        self.results = []
        self.text = None
        self.html = None
        self.csv = None
        n_headers = 0

        for opt, value in options:
            # Check fixed options
            if opt == 'subreport':
                self.subreport = value
            elif opt == 'title':
                self.title = value
            elif opt == 'color':
                if self._color_regexp.search(value) is None:
                    raise LogRaptorOptionError('color')
                self.color = value
            elif opt == 'function':
                match = self._function_regexp.search(value)
                if not match:
                    raise LogRaptorOptionError('function')

                self.function = match.group('function')
                self.topnum = match.group('topnum')
                self.headers = match.group('headers')
                
                if self.headers:
                    n_headers = len(re.split('\s*,\s*', self.headers))
                else:
                    n_headers = 0
                
                # Parameters value checking
                if self.function == "total" and n_headers > 0:
                    raise LogRaptorOptionError('function', 'function "total" doesn\'t have headers!')
                elif self.function == "top":
                    try:
                        if int(self.topnum) < 0:
                            raise ValueError
                    except (ValueError, TypeError):
                        msg = 'the first argument of function "top" must be a positive integer'
                        raise LogRaptorOptionError('function', msg)
            else:
                # Load and check names of report data options
                for rule in rules:
                    if rule.name == opt or (opt[-1].isdigit() and opt[:-1] == rule.name):
                        rule.used_by_report = True
                        self.rules[opt] = rule
                        break
                else:
                    msg = u"skip report data %r because use undefined or not active app rule!" % self.name
                    raise RuleMissingError(msg)
                self._data[opt] = value

        # Raise if a required option is missing
        if self.subreport is None:
            raise LogRaptorNoOptionError('subreport', name)
        elif self.title is None:
            raise LogRaptorNoOptionError('title', name)
        elif self.function is None:
            raise LogRaptorNoOptionError('function', name)

        # Check the values of report data options
        for opt in self:
            match = self._report_data_regexp.search(self._data[opt])
            if not match:
                raise LogRaptorOptionError(opt, 'a syntax error in report data')

            valfld = match.group('valfld')
            cond = match.group('condition')
            condfield = match.group('field')
            
            fields = re.split('\s*,\s*', match.group('fields'))
            if len(fields) < n_headers:
                raise LogRaptorOptionError('function', 'more headers than fields in the rule!')

            # Check report data function declaration
            if self.function == 'total':
                if cond != '*' and condfield not in self.rules[opt].regexp.groupindex:
                    raise LogRaptorOptionError('function', 'condition %r not in rule %r gids' % (condfield, opt))
                if valfld is not None and valfld not in self.rules[opt].regexp.groupindex:
                    raise LogRaptorOptionError(opt, 'field %r not in rule %r gids' % (valfld, opt))
                if len(fields) > 1:
                    raise LogRaptorOptionError(opt, 'multiple row descriptions!')
                if fields[0][0] != '"':
                    raise LogRaptorOptionError(opt, 'a description must be double-quoted!')
            elif self.function == 'top':
                if valfld is not None and valfld not in self.rules[opt].regexp.groupindex:
                    raise LogRaptorOptionError(opt, 'field %r not in rule %r gids' % (valfld, opt))
                if len(fields) != 1 or fields[0][0] == '"':
                    raise LogRaptorOptionError(opt, 'missing field specification!')
            elif self.function == 'table':
                if valfld is not None:
                    raise LogRaptorOptionError(opt, 'syntax error in report data')
                if cond != '*' and condfield not in self.rules[opt].regexp.groupindex:
                    raise LogRaptorOptionError('function', 'field %r not in rule %r gids' % (condfield, opt))

            # Checking report data fields
            logger.debug('checking fields: %s', fields)
            for field in fields:
                if field[0] == '"' and field[-1] == '"':
                    continue
                if field == "host":
                    continue
                if field not in self.rules[opt].regexp.groupindex:
                    raise LogRaptorOptionError(opt, 'field %r not in rule gids' % field)

    def __repr__(self):
        return u"<%s '%s' at %#x>" % (self.__class__.__name__, self.name, id(self))

    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self._data[key] = value

    def __delitem__(self, key):
        del self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __eq__(self, repitem):
        """
        Compare two 'table' report items. When True the report items
        results are mergeable.
        """
        if self.function != 'table' or repitem.function != 'table':
            return False
        
        if self.title != repitem.title:
            return False
        
        head1 = re.split('\s*,\s*', self.headers)
        head2 = re.split('\s*,\s*', repitem.headers)
        if len(head1) != len(head2):
            return False
        for k in range(len(head1)):
            if head1[k].strip() != head2[k].strip():
                return False
        return True

        # TODO if requested: matching also report item gids
        
    def make_text(self, width):
        """
        Make the text representation of a report data element.
        """
        def mformat(reslist):
            _text = ""
            _buffer = reslist[0]
            for j in range(1, len(reslist)):
                if (_buffer == "") or (len(_buffer) + len(reslist[j])) <= (width - len(filling)):
                    if reslist[j][0] == '[' and reslist[j][-1] == ']':
                        _buffer = '{0} {1}'.format(_buffer, reslist[j])
                    else:
                        _buffer = '{0}, {1}'.format(_buffer, reslist[j])
                else:
                    _text = '{0}{1}\n{2}'.format(_text, _buffer, filling)
                    _buffer = reslist[j]
            _text = '{0}{1}'.format(_text, _buffer)
            return _text

        text = '\n----- {0} -----\n\n'.format(self.title.strip())

        if self.function == 'total':
            width1 = max(len(res[0]) for res in self.results if res is not None)
            for res in self.results:
                padding = ' ' * (width1 - len(res[0]) + 1)
                text = '{0}{1}{2}| {3}\n'.format(text, res[0], padding, res[1])
                
        elif self.function == 'top':
            if self.results[0] is not None:
                width1 = max(len(res[0]) for res in self.results if res is not None)
                width2 = min([width-width1-4,
                              max(len(', '.join(res[1])) for res in self.results if res is not None)])

                text = '{0}{1} | {2}\n'.format(text, ' ' * width1, self.headers.strip('"'))
                text = '{0}{1}-+-{2}-\n'.format(text, '-' * width1, '-' * width2)

                for res in self.results:
                    if res is not None:
                        padding = ' ' * (width1 - len(res[0]) + 1)
                        filling = '{0}| '.format(' ' * (width1 + 1))
                        lastcol = mformat(res[1])
                        text = '{0}{1}{2}| {3}\n'.format(text, res[0], padding, lastcol)
            else:
                text = '{0} {1}\n'.format(text, 'None')
                    
        elif self.function == 'table':
            headers = re.split('\s*,\s*', self.headers)

            colwidth = []
            for i in range(len(headers)-1):
                colwidth.append(max([len(headers[i]), max(len(res[i]) for res in self.results)]))

            for i in range(len(headers)-1):
                text = '{0}{1}{2}| '\
                            .format(text, headers[i].strip('"'), ' ' * (colwidth[i]-len(headers[i])+2))

            text = '{0}{1}\n'.format(text, headers[-1].strip('"'))
            text = '{0}{1}\n'.format(text, '-' * (width-1))

            filling = ""
            for i in range(len(headers)-1):
                filling = '{0}{1}| '.format(filling, ' ' * colwidth[i])
            
            for res in sorted(self.results, key=lambda x: x[0]):
                for i in range(len(headers)-1):
                    text = '{0}{1}{2}| '.format(text, res[i], ' ' * (colwidth[i]-len(res[i])))
                lastcol = get_fmt_results(res[-1], limit=5)
                text = '{0}{1}\n'.format(text, mformat(lastcol))
        self.text = text

    def make_html(self):
        """
        Make the text representation of a report element as html.
        """
        html = None
        if self.function == 'total':
            html = u'<table border="0" width="100%" rules="cols" cellpadding="2">\n'\
                   '<tr><th colspan="2" align="left"><h3><font color="{1}">'\
                   '{0}</font></h3></th></tr>\n'\
                   .format(htmlsafe(self.title.strip()), self.color)

            for res in self.results:
                html = u'{0}<tr><td valign="top" align="right">{1}</td>'\
                       '<td valign="top" width="90%">{2}</td></tr>'\
                       .format(html, res[0], res[1])

        elif self.function == 'top':
            html = u'<table border="0" width="100%" rules="cols" cellpadding="2">\n'\
                   '<tr><th colspan="2" align="left"><h3><font color="{1}">'\
                   '{0}</font></h3></th></tr>\n'\
                   .format(htmlsafe(self.title.strip()), self.color)

            if self.results[0] is not None:
                for res in self.results:
                    if res is not None:
                        html = u'{0}<tr><td valign="top" align="right">{1}</td>'\
                               '<td valign="top" width="90%">{2}</td></tr>'\
                               .format(html, res[0], ', '.join(res[1]))
            else:
                html = u'{0}<tr><td valign="top" align="left">{1}</td>'\
                       .format(html, "None")
                
        elif self.function == 'table':
            html = u'<h3><font color="{1}">{0}</font></h3>'\
                   '<table width="100%" rules="cols" cellpadding="2">\n'\
                   '<tr bgcolor="#aaaaaa">'\
                   .format(htmlsafe(self.title.strip()), self.color)
            
            headers = re.split('\s*,\s*', self.headers)
            for i in range(len(headers)):
                html = '{0}<th align="center" colspan="1">'\
                       '<font color="black">{1}</font></th>'\
                       .format(html, headers[i].strip('"'))

            html = u'{0}</tr>\n'.format(html)
            
            oddflag = False
            lastval = ""            
            for res in sorted(self.results, key=lambda x: x[0]):
                if lastval != res[0]:
                    oddflag = not oddflag
                    if oddflag:
                        html = u'{0}<tr bgcolor="#dddddd">'.format(html)
                    else:
                        html = u'{0}<tr>'.format(html)

                    html = u'{0}<td valign="top" width="15%">{1}</td>'\
                           .format(html, res[0])
                else:
                    if oddflag:
                        html = u'{0}<tr bgcolor="#dddddd">'.format(html)
                    else:
                        html = u'{0}<tr>'.format(html)

                    html = u'{0}<td valign="top" width="15%">&nbsp;</td>'.format(html)
                lastval = res[0]
                
                for i in range(1, len(headers)-1):
                    html = u'{0}<td valign="top" width="15%">{1}</td>'.format(html, res[i])
                lastcol = get_fmt_results(res[-1], limit=10, fmt=u'<font color="darkred">{0}</font>')

                if lastcol[-1].find(u" more skipped]") > -1:
                    html = u'{0}<td valign="top" width="{1}%">{2} {3}</td></tr>\n'\
                           .format(html, 100-15*(len(headers)-1),
                                   u', '.join(lastcol[:-1]), lastcol[-1])
                else:
                    html = u'{0}<td valign="top" width="{1}%">{2}</td></tr>\n'\
                           .format(html, 100-15*(len(headers)-1), u', '.join(lastcol))

        self.html = u'{0}</table>\n<p>\n'.format(html)

    def make_csv(self):
        """
        Get the text representation of a report element as csv.
        """
        import csv
        try:
            from StringIO import StringIO  # Python 2.7
        except ImportError:
            from io import StringIO

        out = StringIO()
        writer = csv.writer(out, delimiter='|', lineterminator='\n', quoting=csv.QUOTE_MINIMAL)

        if self.function == 'total':
            writer.writerows(self.results)                

        elif self.function == 'top':
            rows = [['Value', self.headers.strip('"')]]
            if self.results[0] is not None:
                for res in self.results:
                    if res is not None:
                        rows.append(tuple([res[0], ','.join(res[1])]))
                writer.writerows(rows)
                
        elif self.function == 'table':
            rows = [[header.strip('"') for header in re.split('\s*,\s*', self.headers)]]

            for res in sorted(self.results, key=lambda x: x[0]):
                row = list(res[:-1])
                lastcol = get_fmt_results(res[-1], limit=10)
                if lastcol[-1][0] == '[' and lastcol[-1][-1] == ']':
                    row.append(u'{0} {1}'.format(u', '.join(lastcol[:-1]), lastcol[-1]))
                else:
                    row.append(u', '.join(lastcol))
                rows.append(row)
            writer.writerows(rows)

        self.csv = out.getvalue()

    def parse_report_data(self, opt):
        return self._report_data_regexp.search(self._data[opt])


class Subreport(object):
    """
    Class to manage subreports
    """

    def __init__(self, name, title):
        self.name = name
        self.title = title
        self.report_data = []
        self.reptext = ""

    def __len__(self):
        return len(self.report_data)

    def __repr__(self):
        return u"<%s '%s' at %#x>" % (self.__class__.__name__, self.name, id(self))

    def make(self, apps):
        """
        Make subreport items from results.
        """
        for (appname, app) in sorted(apps.items(), key=lambda x: (x[1].priority, x[0])):
            logger.info('Getting report results from %r', appname)

            for report_data in app.report_data:
                if report_data.subreport != self.name:
                    continue

                if report_data.function == 'total':
                    for opt in report_data:
                        match = report_data.parse_report_data(opt)
                        cond = match.group('condition')
                        valfld = match.group('valfld')
                        unit = match.group('unit')
                        itemtitle = match.group('fields').strip('"')

                        total = report_data.rules[opt].total_events(cond, valfld)
                        if total == 0:
                            continue

                        if unit is not None:
                            total, unit = get_value_unit(total, unit, 'T')
                            total = '{0} {1}'.format(total, unit)
                        else:
                            total = str(total)
                        report_data.results.append(tuple([total, itemtitle]))

                elif report_data.function == 'top':
                    k = int(report_data.topnum)
                    for opt in report_data:
                        match = report_data.parse_report_data(opt)

                        valfld = match.group('valfld')
                        field = match.group('fields')
                        usemax = match.group('add2res') is None

                        toplist = report_data.rules[opt].top_events(k, valfld, usemax, field)
                        report_data.results.extend(toplist)
                        
                elif report_data.function == 'table':
                    cols = len(re.split('\s*,\s*', report_data.headers))
                    for opt in report_data:
                        match = report_data.parse_report_data(opt)
                        cond = match.group('condition')
                        fields = re.split('\s*,\s*', match.group('fields'))
                        tablelist = report_data.rules[opt].list_events(cond, cols, fields)
                        report_data.results.extend(tablelist)

                if report_data.results:
                    self.report_data.append(report_data)

        # Sort and rewrite results as strings with units 
        for report_data in self.report_data:
            if report_data.function == 'top':
                # Sort values
                report_data.results = sorted(report_data.results, key=lambda x: x[0], reverse=True)

                # Get the unit if any and convert numeric results to strings
                unit = None
                for opt in report_data:
                    match = report_data.parse_report_data(opt)
                    unit = match.group('unit')
                    if unit is not None:
                        break

                for res in report_data.results:
                    if unit is not None:
                        v, u = get_value_unit(res[0], unit, 'T')
                        res[0] = '{0} {1}'.format(v, u)
                    else:
                        res[0] = str(res[0])

    def make_format(self, fmt, width):
        """
        Make subreport text in a specified format         
        """
        if not self.report_data:
            return
        
        for data_item in self.report_data:
            if data_item.results:
                if fmt is None or fmt == 'text':
                    data_item.make_text(width)
                elif fmt == 'html':
                    data_item.make_html()
                elif fmt == 'csv':
                    data_item.make_csv()

    def compact_tables(self):
        """
        Compact report items of type "table" with same results type. Report items of type "tables" in the
        same subreport is merged into one. The data are ordered by 1st column.
        """
        items_to_del = set()
        for i in range(len(self.report_data)):
            if i in items_to_del:
                continue
            if self.report_data[i].function[0:5] == 'table':
                for j in range(i+1, len(self.report_data)):
                    if self.report_data[j].function[0:5] == 'table':
                        if self.report_data[i] == self.report_data[j]:
                            logger.debug('Merge of 2 identical report tables: {0}'
                                         .format(self.report_data[i].title)) 
                            items_to_del.add(j)
                            self.report_data[i].results.extend(self.report_data[j].results)
        if items_to_del:
            for i in reversed(sorted(items_to_del, key=lambda x: x)):
                self.report_data.pop(i)

                
class Report(object):
    """
    This helper class holds the contents of a report before it is
    sent to selected channels.
    """
    def __init__(self, name, patterns, args, config):
        self.name = name
        self.patterns = patterns
        self.args = args
        self.config = config

        self.stats = dict()
        self.runtime = time.localtime()

        # Read the report options from the config file
        try:
            options = dict(config.items('%s_report' % name))
        except LogRaptorNoSectionError:
            raise LogRaptorConfigError("no configured report for name %r." % name)

        self.title = Template(options['title']).safe_substitute({
            'localhost': socket.gethostname(),
            'localtime': time.strftime('%c', self.runtime)
        })
        base_path = os.path.dirname(self.config.cfgfile)
        self.html_template = normalize_path(options['html_template'], base_path)
        self.text_template = normalize_path(options['text_template'], base_path)

        self.subreports = [
            Subreport(name=opt.partition('_')[0], title=value)
            for opt, value in options.items() if opt.endswith('_subreport')
        ]

    def make(self, apps):
        """
        Create the report from application results
        """
        for subreport in self.subreports:
            logger.debug('Make subreport "{0}"'.format(subreport.name))
            subreport.make(apps)

        for subreport in self.subreports:
            subreport.compact_tables()

    def cleanup(self):
        pass

    def get_report_parts(self, apps, formats):
        """
        Make report item texts in a specified format.
        """
        for fmt in formats:
            width = 100 if fmt is not None else tui.getTerminalSize()[0]
            for sr in self.subreports:
                sr.make_format(fmt, width)

        logger.debug('Build a map for arguments and run\'s statistics ...')
        value_mapping = {
            'title': self.title,
            'patterns': ', '.join([repr(pattern) for pattern in self.args.patterns]) or None,
            'pattern_files': ', '.join(self.args.pattern_files) or None,
            'hosts': ', '.join(self.args.hosts) or None,
            'apps': u', '.join([
                u'%s(%d)' % (app.name, app.matches) for app in apps.values() if app.matches > 0
            ]),
            'version': __version__
        }

        filters = []
        for flt in self.args.filters:
            filters.append(' AND '.join(['%s=%r' % (k, v.pattern) for k, v in flt.items()]))
        if filters:
            value_mapping['filters'] = ' OR '.join(['(%s)' % item for item in filters])
        else:
            value_mapping['filters'] = filters[0] if filters else None

        value_mapping.update(self.stats)

        report = []
        for fmt in formats:
            if fmt == 'text':
                logger.info('appends a text page report')
                report.append(self.make_text_page(value_mapping))
            elif fmt == 'html':
                logger.info('appends a html page report')
                report.append(self.make_html_page(value_mapping))
            elif fmt == 'csv':
                logger.info('extends with a list of csv subreports')
                report.extend(self.make_csv_tables())
        return report

    def is_empty(self):
        """
        A report is empty when it hasn't subreports or when all subreports are empty.
        """
        return not any(self.subreports)

    def set_stats(self, run_stats):
        """
        Set run statistics for the report.
        """
        self.stats = run_stats.copy()
        self.stats['files'] = ', '.join(self.stats['files'])
        self.stats['tot_files'] = len(run_stats['files'])
        self.stats['extra_tags'] = ', '.join(self.stats['extra_tags'])

    def make_html_page(self, valumap):
        """
        Builds the report as html page, using the template page from file.
        """
        logger.info('Making an html report using template %r.', self.html_template)
        fh = open(self.html_template)
        template = fh.read()
        fh.close()

        parts = []
        for sr in self.subreports:
            report_data = [item.html for item in sr.report_data if item.html]
            if report_data:
                parts.append('\n<h2>{1}</h2>\n'.format(sr.title, sr.reptext))
                parts.extend(report_data)
                parts.append('\n<hr/>')
        
        valumap['subreports'] = '\n'.join(parts) # or "\n<<NO SUBREPORT RELATED EVENTS>>\n"
        html_page = Template(template).safe_substitute(valumap)
        return TextPart(fmt='html', text=html_page, ext='html')

    def make_text_page(self, valumap):
        """
        Builds the report as text page, using the template page from file.
        """
        logger.info('Making a text report page using template %r.', self.text_template)
        fh = open(self.text_template)
        template = fh.read()
        fh.close()
        
        parts = []
        for sr in self.subreports:
            report_data = [item.text for item in sr.report_data if item.text]
            if report_data:
                parts.append('\n{1}\n***** {0} *****\n{1}'.format(sr.title, '*' * (len(sr.title)+12)))
                parts.extend(report_data)

        valumap['subreports'] = '\n'.join(parts) # "\n<<NO SUBREPORT RELATED EVENTS>>\n"
        text_page = Template(template).safe_substitute(valumap)
        return TextPart(fmt='text', text=text_page, ext='txt')

    def make_csv_tables(self):
        """
        Builds the report as a list of csv tables with titles.
        """
        logger.info('Generate csv report tables')
        report_parts = []
        for sr in self.subreports:
            for data_item in sr.report_data:
                report_parts.append(TextPart(fmt='csv', text=data_item.csv, ext='csv'))
        return report_parts
