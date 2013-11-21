#!/usr/bin/python
#
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

from __future__ import print_function

import argparse
import fileinput
import os.path

from os_loganalyze import common
from os_loganalyze import printer

if __name__ == '__main__':

    class ActionNoYes(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            if option_string.starts_with('--no-'):
                setattr(namespace, self.dest, False)
            else:
                setattr(namespace, self.dest, True)

    parser = argparse.ArgumentParser(description=('Filter and colorize '
                                                  'OpenStack Logs'))

    parser.add_argument('--no-hide-raw', '--hide-raw',
                        dest='hide_raw',
                        nargs=0,
                        default=True,
                        help=('[don\'t] hide messages from the '
                              '*.messaging.ops.raw source (default: do)'),
                        action=ActionNoYes)
    parser.add_argument('--no-strip-u', '--strip-u',
                        nargs=0,
                        dest='strip_u',
                        default=True,
                        help=('[don\'t] strip the \'u\' designator on unicode'
                              ' strings (default: do)'),
                        action=ActionNoYes)
    parser.add_argument('--no-highlight-content', '--highlight-content',
                        dest='highlight_content',
                        nargs=0,
                        default=True,
                        help=('[don\'t] highlight the \'content=\' key in '
                              'message bodies (default: do)'),
                        action=ActionNoYes)
    parser.add_argument('--skip-source',
                        dest='skip_sources',
                        metavar='REGEX',
                        default=[],
                        help=('skip any message with a source matching the '
                              'given regular expression (may be specified '
                              'more than once'),
                        action='append')
    parser.add_argument('--skip-message-type',
                        dest='skip_message_types',
                        metavar='REGEX',
                        default=[],
                        help=('skip any messages with a message type matching'
                              ' the given regular expression (may be '
                              'specified more than once'),
                        action='append')
    parser.add_argument('--output-format', '-o',
                        dest='output_format',
                        default='color',
                        help='The output format of the result',
                        choices=['color', 'plain', 'html'])
    parser.add_argument('--min-sev', '--level', '-l',
                        dest='min_sev',
                        metavar='SEV',
                        default=None,
                        help=('the minimum severity of message to show'
                              ' NOTE: specifying this will override'
                              ' the log severity support autodetection)'),
                        choices=common.SEVS.keys())
    parser.add_argument('--log-type', '-t',
                        dest='log_type',
                        metavar='TYPE',
                        default=None,
                        help=('override the filename-based autodetection'
                              ' of log type'))
    parser.add_argument('--no-filter-sev', '--filter-sev',
                        dest='filter_sev',
                        nargs=0,
                        default=None,
                        help='Override the severity filtering autodetection',
                        action=ActionNoYes)
    parser.add_argument('file',
                        nargs='?',
                        default='-',
                        help=('the file to parse (specifiy \'-\' or nothing '
                              'to read from stdin)'))

    args = parser.parse_args()

    styler = None
    style_map = {'date': 'yellow', 'source': 'blue', 'req_id': 'bold',
                 'msg_op': 'magenta', 'msg_num': 'bold',
                 'msg_content': 'bold', 'msg_type': 'yellow',
                 'lvl_DEBUG': 'cyan', 'lvl_INFO': 'green',
                 'LVL_ERROR': 'red', 'LVL_warning': 'magenta',
                 'LVL_other': 'white'}
    if args.output_format == 'color':
        styler = printer.DirectStyler(style_map, printer=printer.ANSIPrinter)
    elif args.output_format == 'html':
        style = printer.HTMLStyler()
    else:  # args.output_format == 'plain'
        styler = printer.DirectStyler(style_map, printer=printer.LogPrinter)

    fname = os.path.basename(args.file),
    matcher, formatter = common.build_matcher_function(
        fname,
        args.min_sev,
        styler,
        common.file_supports_sev(fname, args.filter_sev, args.min_sev),
        common.detect_log_type(fname, args.log_type),
        invert_order=False,
        skip_raw=args.hide_raw,
        skip_sources_in=args.skip_sources,
        skip_message_types=args.skip_message_types,
        highlight_content=args.highlight_content)

    try:
        if args.output_format == 'html':
            print(common.css_preamble())

        for line in fileinput.input(args.file):
            res = matcher.run(line, {})
            if res is None:
                continue

            if res[0] is not None:
                print(formatter.output(res[0]))

    except KeyboardInterrupt:
        pass
    finally:
        if args.output_format == 'html':
            print(common.html_end())
