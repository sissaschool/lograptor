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

from lograptor.tui import ProgressBar


class TestTextualUserInterface(object):
    def setup_method(self, method):
        print("\n%s:%s" % (type(self).__name__, method.__name__))

    def test_progress_bar(self, capsys):
        progress_bar = ProgressBar(sys.stdout, 9999, 'messages.log')
        out, _ = capsys.readouterr()
        assert '#' not in out, "Found a # character at 0 percentage."

        progress_bar.redraw(1000)
        out, _ = capsys.readouterr()
        assert out.rsplit('\b', 1)[1][0] == '#', "No progress marker # written."

        progress_bar.redraw(10000)
        out, _ = capsys.readouterr()
        out = out.rsplit('\b', 1)[1]
        assert '#]' in out, "No progress end marker '#]' written."
        assert out.endswith("10000 messages.log\n"), "Unfinished progress bar."
        assert progress_bar.percentage == 100, "Wrong percentage."
