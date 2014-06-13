#!/usr/bin/env python
"""
This module contains additional class and functions to handle time
and date values for Lograptor package.
"""
##
# Copyright (C) 2011-2012 by SISSA
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# @Author Davide Brunato <brunato@sissa.it>
##

def parse_last(last):
    """
    Parse the --last value and return the time difference in seconds.
    """
    
    wordmap = {
        'hour'  : '1h',
        'day'   : '1d',
        'week'  : '1w',
        'month' : '1m'
    }

    # seconds
    multmap = {
        'h' : 3600,
        'd' : 86400,
        'w' : 604800,
        'm' : 2592000
    }

    if last in wordmap:
        last = wordmap[last]

    cat = last[-1:].lower()

    if cat not in multmap:
        raise TypeError

    try: 
        num = int(last[:-1])
        if num <= 0:
            raise TypeError
    except ValueError: 
        raise TypeError
    
    diff = num * multmap[cat]    
    return diff


def get_interval(timestamp, diff, offset=0):
    """
    Returns datetime interval from timestamp backward in the past,
    computed using the milliseconds difference passed as argument.
    The final datetime is corrected with an optional offset.
    """
    import datetime
    fin_datetime = datetime.datetime.fromtimestamp(timestamp + offset)
    ini_datetime = datetime.datetime.fromtimestamp(timestamp - diff)
    return (fin_datetime, ini_datetime)


def parse_date(date):
    """
    Parse the --date value and return a couple of datetime object.
    The format is [YYYY]MMDD[,[YYYY]MMDD]. If a date is in the
    future raise a ValueError exception.
    """
    import datetime
    
    now = datetime.datetime.today()
    date_len = len(date)
    
    if date_len == 4:
        date1 = str(now.year) + date
        date2 = str(now.year) + date + "235959"
    elif date_len == 8:
        date1 = date
        date2 = date + "235959"
    elif date_len == 9:
        if date[4] != ',':
            raise TypeError
        date1 = str(now.year) + date[0:4]
        date2 = str(now.year) + date[5:9] + "235959"
    elif date_len == 17:
        if date[8] != ',':
            raise TypeError
        date1 = date[0:8]
        date2 = date[9:17] + "235959"
    else:
        raise TypeError

    try:
        date1 = datetime.datetime.strptime(date1, "%Y%m%d")
    except ValueError as e:
        if date_len < 9:
            raise ValueError("Error of date value in --date parameter, use --date=[YYYY]MMDD")
        else:
            raise ValueError("Error in the first date value in --date parameter, "
                             "use --date=[YYYY]MMDD,[YYYY]MMDD")
    try:
        date2 = datetime.datetime.strptime(date2, "%Y%m%d%H%M%S")        
    except ValueError as e:
        raise ValueError("Error in the second date value in --date parameter, "
                         "use --date=[YYYY]MMDD,[YYYY]MMDD")
        
    if date1 > date2:
        if date_len == 8 or date_len == 17:
            raise ValueError("Wrong parameter --date: the first date is after the second!")
        date1 = datetime.datetime(date1.year - 1, date1.month, date1.day)
        
    if date2 > datetime.datetime(now.year, now.month, now.day, 23, 59, 59):
        if date_len == 8 or date_len == 17:
            raise ValueError("Wrong parameter --date: date of the future!")
        date1 = datetime.datetime(date1.year - 1, date1.month, date1.day)
        date2 = datetime.datetime(date2.year - 1, date2.month, date2.day,
                                  date2.hour, date2.minute, date2.second)

    return (date1, date2)


class TimeRange:
    """
    A simple class to manage time range intervals
    """
    h1 = m1 = h2 = m2 = 0

    def __init__(self,tr=""):
        """
        Constructor from timerange string.
        The time range format is HH:MM,HH:MM.
        """

        if ( len(tr) < 11 ):
            raise ValueError
        if ( tr[2] != ':' or tr[5] != ',' or tr[8] != ':' ):
            raise ValueError
            
        self.h1=int(tr[0:2])
        self.m1=int(tr[3:5])
        self.h2=int(tr[6:8])
        self.m2=int(tr[9:])

        if ( self.h1 not in range(0,23) or
             self.h2 not in range(0,23) or
             self.m1 not in range(0,59) or
             self.m2 not in range(0,59) or
             self.h1>self.h2 or
             ( self.h1==self.h2 and self.m1>self.m2 ) ):
            raise ValueError

    def between(self, mytime):
        """
        Compare if the parameter HH:MM is in the time range.
        """
        hour=int(mytime[0:2])
        minute=int(mytime[3:5])
        return ( not ( hour < self.h1 or hour > self.h2 or
                ( hour == self.h1 and minute < self.m1 ) or
                ( hour == self.h2 and minute > self.m2)))
