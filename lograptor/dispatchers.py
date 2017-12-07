# -*- coding: utf-8 -*-
"""
This module contains class to handle events dispatching for lograptor.
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
from collections import OrderedDict, deque
from itertools import chain, repeat
import abc

try:
    import pwd
except ImportError:
    pwd = None


# noinspection PyUnusedLocal
def dummy(*args, **kwargs):
    return


def create_dispatcher(functions):

    def dispatch(*args, **kwargs):
        for _func in functions:
            _func(*args, **kwargs)

    if not functions:
        return dummy
    elif len(functions) == 1:
        return functions[0]
    else:
        return dispatch


class AbstractDispatcher(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, channels):
        self.channels = tuple(channels)

    def __setattr__(self, name, value):
        if name == 'channels':
            if not isinstance(value, tuple):
                value = tuple(value)
            self.open = create_dispatcher([channel.open for channel in value])
            self.close = create_dispatcher([channel.close for channel in value])
            self.send_message = create_dispatcher([channel.send_message for channel in value])
            self.send_selected = create_dispatcher([channel.send_selected for channel in value])
            self.send_context = create_dispatcher([channel.send_context for channel in value])
            send_separator = create_dispatcher([channel.send_separator for channel in value])
            self.send_separator = chain([lambda *args: None], repeat(send_separator))
            self.send_report = create_dispatcher([channel.send_report for channel in value])
        super(AbstractDispatcher, self).__setattr__(name, value)

    def dispatch(self, method, *args, **kwargs):
        for channel in self.channels:
            getattr(channel, method)(*args, **kwargs)

    @abc.abstractmethod
    def dispatch_selected(self, *args, **kwargs):
        return

    @abc.abstractmethod
    def dispatch_context(self, *args, **kwargs):
        return

    @abc.abstractmethod
    def reset(self, *args, **kwargs):
        return


class UnbufferedDispatcher(AbstractDispatcher):

    def __init__(self, channels):
        super(UnbufferedDispatcher, self).__init__(channels)

    def __setattr__(self, name, value):
        super(UnbufferedDispatcher, self).__setattr__(name, value)
        if name == "channels":
            self.dispatch_selected = self.send_selected

    def dispatch_selected(self, *args, **kwargs):
        raise NotImplementedError

    def dispatch_context(self, *args, **kwargs):
        return

    def reset(self, *args, **kwargs):
        return


class LineBufferDispatcher(deque, AbstractDispatcher):

    def __init__(self, channels, before_context, after_context):
        super(LineBufferDispatcher, self).__init__(maxlen=before_context)
        AbstractDispatcher.__init__(self, channels)
        self.before_context = before_context
        self.after_context = after_context
        self.last_line = 0
        self.context_until = 0

    def dispatch_selected(self, filename, line_number, match=None, **kwargs):
        next_line = line_number - len(self)
        if self.last_line == 0 or (next_line - self.last_line) > 1:
            next(self.send_separator)()
        for n_line in range(line_number - len(self), line_number):
            self.send_context(
                filename=filename,
                line_number=n_line,
                rawlog=self.popleft(),
                match=match
            )
        self.last_line = line_number
        self.context_until = line_number + self.after_context
        self.send_selected(filename=filename, line_number=line_number, match=match, **kwargs)

    def dispatch_context(self, line_number, rawlog, **kwargs):
        if self.after_context and self.context_until >= line_number:
            self.send_context(line_number=line_number, rawlog=rawlog, **kwargs)
            self.last_line = line_number
        elif self.before_context:
            self.append(rawlog)

    def reset(self):
        self.last_line = 0
        self.context_until = 0
        self.clear()


class ThreadedDispatcher(OrderedDict, AbstractDispatcher):
    """
    A cache for multiple threads.
    """
    def __init__(self, channels, before_context, after_context, max_threads=1000):
        super(ThreadedDispatcher, self).__init__()
        AbstractDispatcher.__init__(self, channels)
        if before_context <= 0:
            raise ValueError("before_context must be a positive integer")
        if after_context <= 0:
            raise ValueError("after_context must be a positive integer")
        self.before_context = before_context
        self.after_context = after_context
        self.context = before_context + after_context + 1
        self.max_threads = max_threads

    def flush(self, key):
        line_cache, matched, after_context = self[key]
        if not matched:
            del self[key]
            return

        next(self.send_separator)()
        for entry in line_cache:
            if entry['match']:
                self.send_selected(**entry)
            else:
                self.send_context(**entry)
        del self[key]

    def dispatch_selected(self, key, **kwargs):
        try:
            line_cache, matched, after_context = self[key]
        except KeyError:
            line_cache = deque()
            line_cache.append(kwargs)
            self[key] = (line_cache, True, 0)
        else:
            if line_cache.maxlen is not None:
                line_cache = deque()
            del self[key]
            line_cache.append(kwargs)
            self[key] = (line_cache, True, 0)

    def dispatch_context(self, key, **kwargs):
        try:
            line_cache, matched, after_context = self[key]
        except KeyError:
            line_cache = deque(maxlen=self.before_context)
            line_cache.append(kwargs)
            self[key] = (line_cache, False, 0)
        else:
            if after_context >= self.after_context:
                self.flush(key)
            else:
                del self[key]
                line_cache.append(kwargs)
                self[key] = (line_cache, matched, 0 if not matched else after_context + 1)

    def reset(self):
        self.clear()
