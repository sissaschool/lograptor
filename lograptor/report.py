# -*- coding: utf-8 -*-
"""
This module define classes for building the report produced by a program run.
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
import logging
import re
import socket
import time
from collections import namedtuple, OrderedDict
from string import Template

try:
    from collections import UserDict
except ImportError:
    # Fall back for Python 2.x
    from UserDict import IterableUserDict as UserDict

try:
    import configparser
except ImportError:
    # Fall back for Python 2.x
    import ConfigParser as configparser

from lograptor.utils import get_fmt_results
from .info import __version__
import lograptor.channels
import lograptor.tui
import lograptor.utils


logger = logging.getLogger(__name__)

TextPart = namedtuple('TextPart', 'title text ext')


class ReportItem(UserDict):
    """
    Class to manage the report items defined for an
    application's logs parsed by Lograptor.
    """
    # RE fixed object to check and extract report table parameters
    _color_regexp = re.compile(r'^([a-z]+|\#[0-9a-f]{6})', re.IGNORECASE)
    _function_regexp = re.compile(r'^(?P<function>table|top|total)(\((\s*(?P<topnum>\d+)\s*,)?'
                                  r'\s*(?P<headers>(\"[^\"]*\"(\s*,\s*)?)+)\s*\)|)')
    _reprule_regexp = re.compile(r'^\(\s*(?P<condition>\*|(?P<field>(\w)+)(!=|==)\"[^\"]*\")\s*,'
                                 r'\s*(?P<fields>((\w|\"[^\"]*\")(\s*,\s*)?)+)'
                                 r'(\s*:\s*(?P<add2res>\+)?(?P<valfld>\w+)(\[(?P<unit>(|K|M|G|T)'
                                 r'(b|bits|B|Bytes))\])?)?\s*\)')
    
    def __init__(self, section, section_items, subreports, rules):
        """
        Init the report item. Redefine UserDict dictionary as OrderedDict,
        so disable the call to parent class __init__ function.
        """
        self.data = OrderedDict()
        self.name = section
        self.subreport = self.title = self.color = self.function = None
        self.rules = dict()
        self.results = []
        self.plain_text = None
        self.html_text = None
        self.csv_text = None
        n_headers = 0
        
        for opt, value in section_items:
            # Check fixed options
            if opt == 'subreport':
                if value not in subreports:
                    msg = '"{0}" is not a subreport!'.format(value)
                    raise lograptor.OptionError('subreport', msg)
                self.subreport = value
            elif opt == 'title':
                self.title = value
            elif opt == 'color':
                if self._color_regexp.search(value) is None:
                    raise lograptor.OptionError('color')
                self.color = value
            elif opt == 'function':
                match = self._function_regexp.search(value)
                if not match:
                    raise lograptor.OptionError('function')

                self.function = match.group('function')
                self.topnum = match.group('topnum')
                self.headers = match.group('headers')
                
                if self.headers:
                    n_headers = len(re.split('\s*,\s*', self.headers))
                else:
                    n_headers = 0
                
                # Parameters value checking
                if self.function == "total" and n_headers > 0:
                    msg = 'function "total" doesn\'t have headers!'
                    raise lograptor.OptionError('function', msg)
                elif self.function == "top":
                    try:
                        if int(self.topnum) < 0:
                            raise ValueError
                    except (ValueError, TypeError):
                        msg = 'First parameter of function "top" must be a positive integer'
                        raise lograptor.OptionError('function', msg)
            else:
                # Load and check names of report rule options
                for rule in rules:
                    if rule.name == opt or (opt[-1].isdigit() and opt[:-1] == rule.name):
                        rule.used_by_report = True
                        self.rules[opt] = rule
                        break
                else:
                    msg = u"skip report rule %r because use undefined or not active app rule!" % self.name
                    raise lograptor.RuleMissingError(msg)
                self.data[opt] = value

        # Check if fixed options are all defined
        if self.subreport is None:
            raise configparser.NoOptionError('subreport', section)
        elif self.title is None:
            raise configparser.NoOptionError('title', section)
        elif self.function is None:
            raise configparser.NoOptionError('function', section)

        # Check the values of report rule options
        for opt in self:
            logger.debug('Check report rule "{0}"'.format(opt))
            
            match = self._reprule_regexp.search(self.data[opt])
            
            if not match:
                msg = 'syntax error in report rule'
                raise lograptor.OptionError(opt, msg)

            valfld = match.group('valfld')
            cond = match.group('condition')
            condfield = match.group('field')
            
            fields = re.split('\s*,\s*', match.group('fields'))
            if len(fields) < n_headers:
                msg = 'too many headers with respect to the number of fields of the rules'
                raise lograptor.OptionError('function', msg)

            # Report rule check by function
            if self.function == 'total':
                if cond != "*" and condfield not in self.rules[opt].regexp.groupindex:
                    msg = 'condition field "{0}" not in rule {1} gids'.format(condfield, opt)
                    raise lograptor.OptionError('function', msg)
                if valfld is not None and valfld not in self.rules[opt].regexp.groupindex:
                    msg = 'field "{0}" not in rule {1} gids'.format(valfld, opt)
                    raise lograptor.OptionError(opt, msg)
                if len(fields) > 1:
                    msg = 'multiple row descriptions!'
                    raise lograptor.OptionError(opt, msg)
                if fields[0][0] != '"':
                    msg = 'the row description must be between double-quotes!'
                    raise lograptor.OptionError(opt, msg)

            elif self.function == 'top':
                if valfld is not None and valfld not in self.rules[opt].regexp.groupindex:
                    msg = 'field "{0}" not in rule {1} gids'.format(valfld, opt)
                    raise lograptor.OptionError(opt, msg)                    
                if len(fields) != 1 or fields[0][0] == '"':
                    msg = 'missing field specification!'
                    raise lograptor.OptionError(opt, msg)

            elif self.function == 'table':
                if valfld is not None:
                    msg = 'syntax error in report rule'
                    raise lograptor.OptionError(opt, msg)
                if cond != "*" and condfield not in self.rules[opt].regexp.groupindex:
                    msg = 'filter field "{0}" not in rule {1} gids'.format(condfield, opt)
                    raise lograptor.OptionError('function', msg)

            # Checking report rule's fields
            logger.debug('Checking fields: {0}'.format(fields)) 
            for field in fields:
                if field[0] == '"' and field[-1] == '"':
                    continue
                if field == "host":
                    continue
                if field not in self.rules[opt].regexp.groupindex:
                    msg = 'field "{0}" not in rule gids'.format(field)
                    raise lograptor.OptionError(opt, msg)

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
        
    def make_text_plain(self, width):
        """
        Make the text representation of a report element as plain text.
        """
        def mformat(reslist):
            plaintext = ""
            _buffer = reslist[0]
            for j in range(1, len(reslist)):
                if (_buffer == "") or (len(_buffer) + len(reslist[j])) <= (width - len(filling)):
                    if reslist[j][0] == '[' and reslist[j][-1] == ']':
                        _buffer = '{0} {1}'.format(_buffer, reslist[j])
                    else:
                        _buffer = '{0}, {1}'.format(_buffer, reslist[j])
                else:
                    plaintext = '{0}{1}\n{2}'.format(plaintext, _buffer, filling)
                    _buffer = reslist[j]
            plaintext = '{0}{1}'.format(plaintext, _buffer)
            return plaintext

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
        self.plain_text = text

    def make_text_html(self):
        """
        Make the text representation of a report element as html.
        """
        text = None
        if self.function == 'total':
            text = u'<table border="0" width="100%" rules="cols" cellpadding="2">\n'\
                   '<tr><th colspan="2" align="left"><h3><font color="{1}">'\
                   '{0}</font></h3></th></tr>\n'\
                   .format(lograptor.utils.htmlsafe(self.title.strip()), self.color)

            for res in self.results:
                text = u'{0}<tr><td valign="top" align="right">{1}</td>'\
                       '<td valign="top" width="90%">{2}</td></tr>'\
                       .format(text, res[0], res[1])

        elif self.function == 'top':
            text = u'<table border="0" width="100%" rules="cols" cellpadding="2">\n'\
                   '<tr><th colspan="2" align="left"><h3><font color="{1}">'\
                   '{0}</font></h3></th></tr>\n'\
                   .format(lograptor.utils.htmlsafe(self.title.strip()), self.color)

            if self.results[0] is not None:
                for res in self.results:
                    if res is not None:
                        text = u'{0}<tr><td valign="top" align="right">{1}</td>'\
                               '<td valign="top" width="90%">{2}</td></tr>'\
                               .format(text, res[0], ', '.join(res[1]))
            else:
                text = u'{0}<tr><td valign="top" align="left">{1}</td>'\
                       .format(text, "None")
                
        elif self.function == 'table':
            text = u'<h3><font color="{1}">{0}</font></h3>'\
                   '<table width="100%" rules="cols" cellpadding="2">\n'\
                   '<tr bgcolor="#aaaaaa">'\
                   .format(lograptor.utils.htmlsafe(self.title.strip()), self.color)
            
            headers = re.split('\s*,\s*', self.headers)
            for i in range(len(headers)):
                text = '{0}<th align="center" colspan="1">'\
                       '<font color="black">{1}</font></th>'\
                       .format(text, headers[i].strip('"'))

            text = u'{0}</tr>\n'.format(text)
            
            oddflag = False
            lastval = ""            
            for res in sorted(self.results, key=lambda x: x[0]):
                if lastval != res[0]:
                    oddflag = not oddflag
                    if oddflag:
                        text = u'{0}<tr bgcolor="#dddddd">'.format(text)
                    else:
                        text = u'{0}<tr>'.format(text)

                    text = u'{0}<td valign="top" width="15%">{1}</td>'\
                           .format(text, res[0])
                else:
                    if oddflag:
                        text = u'{0}<tr bgcolor="#dddddd">'.format(text)
                    else:
                        text = u'{0}<tr>'.format(text)

                    text = u'{0}<td valign="top" width="15%">&nbsp;</td>'.format(text)
                lastval = res[0]
                
                for i in range(1, len(headers)-1):
                    text = u'{0}<td valign="top" width="15%">{1}</td>'.format(text, res[i])
                lastcol = get_fmt_results(res[-1], limit=10, fmt=u'<font color="darkred">{0}</font>')

                if lastcol[-1].find(u" more skipped]") > -1:
                    text = u'{0}<td valign="top" width="{1}%">{2} {3}</td></tr>\n'\
                           .format(text, 100-15*(len(headers)-1),
                                   u', '.join(lastcol[:-1]), lastcol[-1])
                else:
                    text = u'{0}<td valign="top" width="{1}%">{2}</td></tr>\n'\
                           .format(text, 100-15*(len(headers)-1), u', '.join(lastcol))

        self.html_text = u'{0}</table>\n<p>\n'.format(text)

    def make_text_csv(self):
        """
        Get the text representation of a report element as csv.
        """
        import csv
        import io

        try:
            import cStringIO
            out = cStringIO.StringIO()
        except ImportError:
            import io
            out = io.StringIO()            
            
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

        self.csv_text = out.getvalue()

    def parse_report_rule(self, opt):
        return self._reprule_regexp.search(self.data[opt])


class Subreport(object):
    """
    Class to manage subreports
    """

    def __init__(self, name, title):
        self.name = name
        self.title = title
        self.repitems = []
        self.reptext = ""

    def __bool__(self):
        return len(self.repitems) > 0

    def __repr__(self):
        return u"<%s '%s' at %#x>" % (self.__class__.__name__, self.name, id(self))

    def make(self, apps):
        """
        Make of subreport items from results
        """
        for (appname, app) in sorted(apps.items(), key=lambda x: (x[1].priority, x[0])):
            logger.info('Getting report results from "{0}"'.format(appname))
            
            for repitem in app.repitems:
                
                if repitem.subreport != self.name:
                    continue

                if repitem.function == 'total':
                    for opt in repitem:
                        match = repitem.parse_report_rule(opt)

                        cond = match.group('condition')
                        valfld = match.group('valfld')
                        unit = match.group('unit')
                        itemtitle = match.group('fields').strip('"')

                        total = repitem.rules[opt].total_events(cond, valfld)
                        if total == 0:
                            continue

                        if unit is not None:
                            total, unit = lograptor.utils.get_value_unit(total, unit, 'T')
                            total = '{0} {1}'.format(total, unit)
                        else:
                            total = str(total)

                        repitem.results.append(tuple([total, itemtitle]))

                elif repitem.function == 'top':
                    k = int(repitem.topnum)
                    for opt in repitem:
                        match = repitem.parse_report_rule(opt)

                        valfld = match.group('valfld')
                        field = match.group('fields')
                        usemax = match.group('add2res') is None

                        toplist = repitem.rules[opt].top_events(k, valfld, usemax, field)
                        repitem.results.extend(toplist)
                        
                elif repitem.function == 'table':
                    cols = len(re.split('\s*,\s*', repitem.headers))
                    for opt in repitem:
                        match = repitem.parse_report_rule(opt)
                        cond = match.group('condition')
                        fields = re.split('\s*,\s*', match.group('fields'))
                        tablelist = repitem.rules[opt].list_events(cond, cols, fields)
                        repitem.results.extend(tablelist)

                if repitem.results:
                    self.repitems.append(repitem)

        # Sort and rewrite results as strings with units 
        for repitem in self.repitems:
            if repitem.function == 'top':
                # Sort values
                repitem.results = sorted(repitem.results, key=lambda x: x[0], reverse=True)

                # Get the unit if any and convert numeric results to strings
                unit = None
                for opt in repitem:
                    match = repitem.parse_report_rule(opt)
                    unit = match.group('unit')
                    if unit is not None:
                        break

                for res in repitem.results:
                    if unit is not None:
                        v, u = lograptor.utils.get_value_unit(res[0], unit, 'T')
                        res[0] = '{0} {1}'.format(v, u)
                    else:
                        res[0] = str(res[0])

    def make_format(self, fmt, width):
        """
        Make subreport text in a specified format         
        """
        if not self.repitems:
            return
        
        for repitem in self.repitems:
            if repitem.results:
                if fmt is None or fmt == 'plain':
                    repitem.make_text_plain(width)
                elif fmt == 'html':
                    repitem.make_text_html()
                elif fmt == 'csv':
                    repitem.make_text_csv()

    def compact_tables(self):
        """
        Compact report items of type "table" with same results type. Report items of type "tables" in the
        same subreport is merged into one. The data are ordered by 1st column.
        """
        items_to_del = set()
        for i in range(len(self.repitems)):
            if i in items_to_del:
                continue
            if self.repitems[i].function[0:5] == 'table':
                for j in range(i+1, len(self.repitems)):
                    if self.repitems[j].function[0:5] == 'table':
                        if self.repitems[i] == self.repitems[j]:
                            logger.debug('Merge of 2 identical report tables: {0}'
                                         .format(self.repitems[i].title)) 
                            items_to_del.add(j)
                            self.repitems[i].results.extend(self.repitems[j].results)
        if items_to_del:
            for i in reversed(sorted(items_to_del, key=lambda x: x)):
                self.repitems.pop(i)

                
class Report(object):
    """
    This helper class holds the contents of a report before it is
    sent to selected channels.
    """
    def __init__(self, name, patterns, apps, args, config):
        self.name = name
        self.patterns = patterns
        self.apps = apps
        self.args = args
        self.config = config

        self.stats = dict()
        self.runtime = time.localtime()

        # Read the report options from the config file
        options = dict(config.items('report.%s' % name))

        self.title = Template(options['title']).safe_substitute({
            'localhost': socket.gethostname(),
            'localtime': time.strftime('%c', self.runtime)
        })
        self.html_template = options['template.html']
        self.text_template = options['template.text']
        self.subreports = [
            Subreport(name=opt.partition('.')[2], title=value)
            for opt, value in options.items() if opt.startswith('subreport.')
        ]

    def need_rawlogs(self):
        """
        Check if rawlogs are requested by almost one report's channels.
        """
        return any([channel.rawlogs for channel in self.channels])

    def make(self):
        """
        Create the report from application results
        """
        for subreport in self.subreports:
            logger.info('Make subreport "{0}"'.format(subreport.name))
            subreport.make(self.apps)

        for subreport in self.subreports:
            subreport.compact_tables()

    def cleanup(self):
        pass

    def get_report(self, formats):
        """
        Make report item texts in a specified format.
        """
        if not self.is_empty():
            logger.info("the report is empty: skip sending to channels")
            return []

        for fmt in formats:
            width = 100 if fmt is not None else lograptor.tui.getTerminalSize()[0]
            for subrep in self.subreports:
                subrep.make_format(fmt, width)

        logger.info('Retrieve parameters and run\'s statistics')
        valumap = {
            'title': self.title,
            'localhost': socket.gethostname(),
            'patterns': ', '.join([repr(pattern) for pattern in self.args.patterns]) or None,
            'pattern_files': ', '.join(self.args.pattern_files) or None,
            'hosts': ', '.join(self.args.hostnames) or None,
            'apps': u', '.join([
                u'%s(%d)' % (app.name, app.counter) for app in self.apps.values() if app.counter > 0
            ]),
            'version': __version__
        }

        logger.debug('add filters information')
        filters = []
        for flt in self.args.filters:
            filters.append(' AND '.join(['%s=%r' % (k, v.pattern) for k, v in flt.items()]))
        if len(filters) > 1:
            valumap['filters'] = ' OR '.join(['(%s)' % item for item in filters])
        else:
            valumap['filters'] = filters[0] if filters else None

        logger.debug('Get run\'s stats')
        for key in self.stats:
            valumap[key] = self.stats[key]

        report = {}
        for fmt in formats:
            if fmt == 'text':
                logger.info('creating a plain text page report')
                report['text'] = self.make_text_page(valumap)
            elif fmt == 'html':
                logger.info('creating a standard html page report')
                report['html'] = self.make_html_page(valumap)
            elif fmt == 'csv':
                logger.info('creating a list of csv files')
                report['csv'] = self.make_csv_tables()
        return report

    def is_empty(self):
        """
        Check if the report is empty (=all subreports are empty)
        """
        return not any(self.subreports)

    def set_stats(self, stats):
        """
        Set run statistics for the report (timestamps, totals, etc.).
        """
        for key, value in stats.items():
            self.stats[key] = value
            logger.debug('{0}={1}'.format(key, value))

    def make_html_page(self, valumap):
        """
        Builds the report as html page, using the template page from file.
        """
        logger.info('Making a standard report page')

        logger.info('Reading in the template file "{0}"'.format(self.html_template))
        fh = open(self.html_template)
        template = fh.read()
        fh.close()

        logger.info('Concatenating the subreports together')

        allsubrep = ''
        for subrep in self.subreports:
            if subrep.repitems:
                logger.info('Processing report for "{0}"'.format(subrep.name))
                allsubrep = '{0}\n<h2>{1}</h2>\n'\
                            .format(allsubrep, subrep.title, subrep.reptext)
                for repitem in subrep.repitems:
                    allsubrep = '{0}{1}'.format(allsubrep, repitem.html_text)
                allsubrep = '{0}<hr />'.format(allsubrep)
        
        valumap['subreports'] = allsubrep

        logger.info('Create the final report')
        endpage = Template(template).safe_substitute(valumap)

        logger.debug('----htmlreport starts----')
        logger.debug(endpage)
        logger.debug('----htmlreport ends-----')

        return TextPart("Lograptor report", endpage, 'html')

    def make_text_page(self, valumap):
        """
        Builds the report as text page, using the template page from file.
        """
        
        logger.info('Making a standard report text page')

        logger.info('Reading in the template file "{0}"'.format(self.text_template))
        fh = open(self.text_template)
        template = fh.read()
        fh.close()
        
        logger.info('Concatenating the subreports together')

        allsubrep = ''
        for subrep in self.subreports:
            if subrep.repitems:
                logger.info('Processing report for "{0}"'.format(subrep.name))
                allsubrep = '{0}\n\n{2}\n***** {1} *****\n{2}'\
                            .format(allsubrep, subrep.title, '*' * (len(subrep.title)+12))
                for repitem in subrep.repitems:
                    allsubrep = '{0}\n{1}'.format(allsubrep, repitem.plain_text)

        valumap['subreports'] = allsubrep
        
        logger.info('Create the final report')
        endpage = Template(template).safe_substitute(valumap)

        logger.debug('----textreport starts----')
        logger.debug(endpage)
        logger.debug('----textreport ends-----')

        return TextPart("Lograptor report", endpage, 'txt')

    def make_csv_tables(self):
        """
        Builds the report as a list of csv tables with titles.
        """
        logger.info('Adding csv report tables as attachments')

        report_parts = []
        for subrep in self.subreports:
            if subrep.repitems:
                for repitem in subrep.repitems:
                    report_parts.append(TextPart(repitem.title, repitem.csv_text, 'csv'))

        return report_parts
