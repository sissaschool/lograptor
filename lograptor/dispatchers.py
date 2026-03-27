"""
This module defines classes to handle events dispatching for lograptor.
"""
#
# Copyright (C), 2011-2026, by SISSA - International School for Advanced Studies.
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
import abc
from collections import deque
from collections.abc import Sequence, Callable
from functools import partial
from itertools import chain, repeat
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lograptor.channels import AbstractChannel


# noinspection PyUnusedLocal
def no_dispatch(*args, **kwargs):
    """Do nothing, used to set dispatchers with no channels."""


def dispatch(*args, functions: Sequence[Callable[[...], Any]], **kwargs):
    """Dispatch arguments to a sequence of functions."""
    for func in functions:
        func(*args, **kwargs)


_DISPATCHERS = (
    'open',
    'close',
    'send_message',
    'send_selected',
    'send_context',
    'send_separator',
    'send_report'
)


class AbstractDispatcher(metaclass=abc.ABCMeta):
    """Abstract base class to handle events dispatching."""

    channels: tuple['AbstractChannel', ...]

    def __setattr__(self, name, value):
        if name == 'channels':
            if not isinstance(value, tuple):
                value = tuple(value)

            if not value:
                for attr in _DISPATCHERS:
                    setattr(self, attr, no_dispatch)
            elif len(value) == 1:
                for attr in _DISPATCHERS:
                    setattr(self, attr, getattr(value[0], attr))
            else:
                self.open = partial(dispatch, functions=[ch.open for ch in value])
                self.close = partial(dispatch, functions=[ch.close for ch in value])
                self.send_message = partial(dispatch, functions=[ch.send_message for ch in value])
                self.send_selected = partial(dispatch, functions=[ch.send_selected for ch in value])
                self.send_context = partial(dispatch, functions=[ch.send_context for ch in value])
                send_separator = partial(dispatch, functions=[ch.send_separator for ch in value])
                self.send_separator = chain([lambda *args: None], repeat(send_separator))
                self.send_report = partial(dispatch, functions=[ch.send_report for ch in value])

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

    __slots__ = _DISPATCHERS + ('channels',)

    def __init__(self, channels: Sequence['AbstractChannel']):
        self.channels = tuple(channels)

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

    __slots__ = _DISPATCHERS + (
        'channels',
        'before_context',
        'after_context',
        'last_line',
        'context_until',
    )

    def __init__(self,
                 channels: Sequence['AbstractChannel'],
                 before_context: int = 0,
                 after_context: int = 0):

        super(LineBufferDispatcher, self).__init__(maxlen=before_context)
        self.channels = tuple(channels)
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


class ThreadedDispatcher(dict, AbstractDispatcher):
    """
    A cache for multiple threads.
    """
    __slots__ = _DISPATCHERS + (
        'channels',
        'before_context',
        'after_context',
        'context',
        'max_threads',
    )

    def __init__(self,
                 channels: Sequence['AbstractChannel'],
                 before_context: int = 0,
                 after_context: int = 0,
                 max_threads: int = 1000):

        super(ThreadedDispatcher, self).__init__()
        self.channels = tuple(channels)

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
