# -*- coding: utf-8 -*-
"""
This module contains functions and classes to manage output on text-based
user interface (TUI).
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
import os
import sys


def getTerminalSize():
    """
    getTerminalSize()
     - get width and height of console
     - works on linux,os x,windows,cygwin(windows)
    """
    import platform
   
    current_os = platform.system()
    tuple_xy = None
    if current_os == 'Windows':
        tuple_xy = _getTerminalSize_windows()
        if tuple_xy is None:
            tuple_xy = _getTerminalSize_tput()
            # needed for window's python in cygwin's xterm!
    if current_os == 'Linux' or current_os == 'Darwin' or current_os.startswith('CYGWIN'):
        tuple_xy = _getTerminalSize_linux()
    if tuple_xy is None:
        tuple_xy = (80, 25)  # default value
    return tuple_xy


def _getTerminalSize_windows():
    from ctypes import windll, create_string_buffer

    # stdin handle is -10
    # stdout handle is -11
    # stderr handle is -12
    handle = windll.kernel32.GetStdHandle(-12)

    try:
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(handle, csbi)
    except (IOError, OSError):
        return None

    if res:
        import struct
        (bufx, bufy, curx, cury, wattr,
         left, top, right, bottom, maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
        sizex = right - left + 1
        sizey = bottom - top + 1
        return sizex, sizey
    else:
        return None


def _getTerminalSize_tput():
    # get terminal width
    # src: http://stackoverflow.com/questions/263890/how-do-i-find-the-width-height-of-a-terminal-window
    import subprocess
    try:
        proc = subprocess.Popen(["tput", "cols"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        output = proc.communicate(input=None)
        cols = int(output[0])
        proc = subprocess.Popen(["tput", "lines"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        output = proc.communicate(input=None)
        rows = int(output[0])
        return cols, rows
    except (IOError, OSError):
        return None


def _getTerminalSize_linux():

    def ioctl_GWINSZ(fd):
        try:
            import fcntl
            import termios
            import struct
            return struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
        except (IOError, OSError):
            return None

    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            f = open(os.ctermid())
            cr = ioctl_GWINSZ(f.fileno())
            f.close()
        except (IOError, OSError):
            pass
    if not cr:
        try:
            cr = (os.environ['LINES'], os.environ['COLUMNS'])
        except KeyError:
            return None
    return int(cr[1]), int(cr[0])


class ProgressBar(object):
    """
    Draw a progress toolbar to stdout. The toolbar is initialized calling
    the function with the first argument set to None.
    """

    def __init__(self, output, maxval=0, suffix=""):
        """
        Create and initialize the progress bar
        """
        self.output = output
        self.suffix = suffix

        self.step_perc = max(1, min(int(100000/maxval), 5))
        self.barwidth = int(0.3 * getTerminalSize()[0])
        self.nextperc = 0

        self.maxval = int(maxval)
        if self.maxval <= 0:
            raise ValueError("Maximum value of a progress bar must be positive number.")

        self.output.write('[{0}] {1} {2}'.format(" " * self.barwidth,
                                                 format(0, '1d'), self.suffix))
        self._width = self.barwidth + 4 + len(self.suffix)
        self.output.flush()
        self.initialized = True

    def redraw(self, value, counter=0):
        """
        Redraw the progress bar with a value and a counter.
        """
        if self.initialized is False:
            return
        if value < 0:
            raise ValueError("Size of a progress bar must be a non negative value")

        perc = int(100 * value / self.maxval)
        if (perc >= self.nextperc) or perc >= 100:
            fill = min(self.barwidth, int(self.barwidth * perc / 100))
            counter = str(counter) if counter > 0 else str(value)

            sys.stdout.write("\b" * self._width)  # return to start of line, after '['
            sys.stdout.write('{0}{1}] {2} {3}'
                             .format("#" * fill, " " * (self.barwidth-fill),
                                     counter, self.suffix))
            sys.stdout.flush()
            if perc < 100:
                self._width = self.barwidth + len(self.suffix) + len(counter) + 3
                self.nextperc = perc + self.step_perc
            else:
                sys.stdout.write("\n")
                self.initialized = False
