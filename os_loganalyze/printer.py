# Copyright (c) 2013 Red Hat, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re


class LogPrinter(object):
    """Format Text For a Given Output Type

    NOTE: super should *always* be called in __init__ to access the
          shortcut format functions
    """

    # NOTE: these colors are in order!
    COLORS = ['black', 'red', 'green', 'yellow', 'blue',
              'magenta', 'cyan', 'white']
    SETTINGS = ['bold', 'italic', 'underline', 'reverse', 'concealed']

    def __init__(self):
        for color in self.COLORS:
            setattr(type(self), color, self.with_fg_color(color))
            setattr(type(self), 'bright_' + color,
                    self.with_fg_color(color, True))
            setattr(type(self), 'on_' + color, self.with_bg_color(color))
            setattr(type(self), 'on_bright_' + color,
                    self.with_bg_color(color, True))

        for setting in self.SETTINGS:
            setattr(type(self), setting, self.with_setting(setting))

    # these are helper methods, and should be overridden only
    # by classes that define a new output type

    def plain(self, txt):
        """Output Plain Text

        Returns text with no special formatting applied
        """
        return txt

    def with_fg_color(self, color, bright=False):
        """Get an Outputter for Foreground Coloring

        Returns a method which takes (self, txt) and
        returns colored text
        """
        return self.plain

    def with_bg_color(self, color, bright=False):
        """Get an Outputter for Background Coloring

        Returns a method which takes (self, txt) and
        returns text with a background color
        """
        return self.plain

    def with_setting(self, setting):
        """Get an Outputter for Settings

        Returns a method which takes (self, txt)
        and returns text with the given setting
        applied.
        """
        return self.plain


class ANSIPrinter(LogPrinter):
    ESC = "\x1b["

    SETTINGS_LOOKUP = {'bold': 1,
                       'underline': 4,
                       'italic': 3,
                       'reverse': 7,
                       'concealed': 8}

    @classmethod
    def ansi_code(cls, code):
        return cls.ESC + str(code) + 'm'

    def with_fg_color(self, color, bright=False):
        if bright:
            return lambda self, txt: (
                self.ansi_code(90 + self.COLORS.index(color))
                + txt + self.ansi_code(0))
        else:
            return lambda self, txt: (
                self.ansi_code(30 + self.COLORS.index(color))
                + txt + self.ansi_code(0))

    def with_bg_color(self, color, bright=False):
        if bright:
            return lambda self, txt: (
                self.ansi_code(100 + self.COLORS.index(color))
                + txt + self.ansi_code(0))
        else:
            return lambda self, txt: (
                self.ansi_code(40 + self.COLORS.index(color))
                + txt + self.ansi_code(0))

    def with_setting(self, setting):
        return lambda self, txt: (
            self.ansi_code(self.SETTINGS_LOOKUP[setting])
            + txt + self.ansi_code(0))


class DirectStyler(object):
    def __init__(self, style_map, printer=ANSIPrinter):
        self.style_map = style_map
        self.printer = printer()
        for name, style in self.style_map.items():
            styles = style.split()

            def fmt_func(self, txt, styles=styles):
                res = txt
                for s in styles:
                    res = getattr(self.printer, s)(res)
                return res

            setattr(type(self), name, fmt_func)


class HTMLStyler(object):
    REGEXP = re.compile(r'[^0-9\-_]')

    def date(self, txt):
        date_as_id = self.REGEXP.sub('_', txt)
        return '<a href="#{2}" id="{2}" class="{0}">{1}</a>'.format('date',
                                                                    txt,
                                                                    date_as_id)

    def wrap(self, txt, cl):
        return '<div class="' + cl + '">' + txt + '</div>'

    def __getattr__(self, name):
        def fmt_func(self, txt, name=name):
            return '<span class="{0}">{1}</span>'.format(name, txt)
        setattr(type(self), name, fmt_func)
        return getattr(self, name)
