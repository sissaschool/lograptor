# -*- coding: utf-8 -*-
"""
This module contains functions and classes to manage output on text-based
user interface (TUI).
"""
#
# Copyright (C), 2011-2018, by SISSA - International School for Advanced Studies.
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


def get_terminal_size():
    """
    Get the terminal size in width and height. Works on Linux, Mac OS X, Windows, Cygwin (Windows).

    :return: Returns a 2-tuple with width and height.
    """
    import platform
   
    current_os = platform.system()
    tuple_xy = None
    if current_os == 'Windows':
        tuple_xy = get_windows_terminal_size()
        if tuple_xy is None:
            tuple_xy = get_unix_tput_terminal_size()  # needed for window's python in cygwin's xterm!
    elif current_os == 'Linux' or current_os == 'Darwin' or current_os.startswith('CYGWIN'):
        tuple_xy = get_unix_ioctl_terminal_size()

    if tuple_xy is None:
        tuple_xy = (80, 25)  # default value
    return tuple_xy


def get_windows_terminal_size():
    """Get the terminal size of a Windows OS terminal."""
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


def get_unix_tput_terminal_size():
    """
    Get the terminal size of a UNIX terminal using the tput UNIX command.
    Ref: http://stackoverflow.com/questions/263890/how-do-i-find-the-width-height-of-a-terminal-window
    """
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


def get_unix_ioctl_terminal_size():
    """Get the terminal size of a UNIX terminal using the ioctl UNIX command."""
    def ioctl_gwinsz(fd):
        try:
            import fcntl
            import termios
            import struct
            return struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
        except (IOError, OSError):
            return None

    cr = ioctl_gwinsz(0) or ioctl_gwinsz(1) or ioctl_gwinsz(2)
    if not cr:
        try:
            f = open(os.ctermid())
            cr = ioctl_gwinsz(f.fileno())
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

    :param output: the file object where the progress bar is written.
    :param max_value: the maximum value of the progress bar.
    :param label: the label appended at the right of the progress bar.
    :param width_percentage: the screen width percentage to set for the progress bar, 25% for default.
    :ivar width: the effective width of the progress bar, in characters.
    :ivar percentage: the progress percentage.
    """
    def __init__(self, output, max_value=0, label='', width_percentage=0.25):
        self.output = output
        if max_value <= 0:
            raise ValueError("Maximum value of a progress bar must be positive number.")
        self.max_value = int(max_value)
        self.label = label

        self.width = int(width_percentage * get_terminal_size()[0])
        self.percentage = 0
        self._next_percentage = self._step_percentage = max(1, min(int(100000 / max_value), 5))
        self._draw_length = self.width + 4 + len(self.label)

        self.output.write('[{}] {} {}'.format(' ' * self.width, format(0, '1d'), self.label))
        self.output.flush()

    def redraw(self, value):
        if self.percentage == 100:
            return

        percentage = int(100 * value / self.max_value)
        if percentage >= self._next_percentage or percentage >= 100:
            fill = min(self.width, int(self.width * percentage / 100))
            counter = str(value)

            sys.stdout.write('\b' * self._draw_length)
            sys.stdout.write('{}{}] {} {}'.format('#' * fill, ' ' * (self.width - fill), counter, self.label))
            sys.stdout.flush()

            self.percentage = min(percentage, 100)
            self._next_percentage = self.percentage + self._step_percentage
            self._draw_length = self.width + len(counter) + 3 + len(self.label)

            if self.percentage == 100:
                sys.stdout.write("\n")
