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

from os_loganalyze import filters as parsers
from os_loganalyze import outputter

import os.path
import re

# which logs support severity
SUPPORTS_SEV_REGEXP = r'(screen-(n-|c-|q-|g-|h-|ceil|key)|tempest\.txt)'

# regular expressions to match against for various log types
LOG_TYPE_REGEXPS = {
    'console': 'console',
    'devstack': 'stack',
    'keystone': 'key'
    # oslo is the default
}

# the log severity levels
SEVS = {
    'NONE': 0,
    'DEBUG': 1,
    'INFO': 2,
    'AUDIT': 3,
    'TRACE': 4,
    'WARNING': 5,
    'ERROR': 6
    }


def not_html(fname):
    return re.search('(\.html(\.gz)?)$', fname) is None


def file_supports_sev(fname, filter_sev=None, level=None):
    if filter_sev is not None:
        return filter_sev
    elif level is not None:
        return True
    else:
        m = re.search(SUPPORTS_SEV_REGEXP, fname)
        return m is not None


def detect_log_type(fname, log_type=None):
    "Detect the type of the current log file"
    # if the user has manually specified a log type, use that
    if log_type is not None:
        return log_type

    local_fname = os.path.basename(fname)
    for ltype, regexp in LOG_TYPE_REGEXPS.items():
        if re.search(regexp, local_fname) is not None:
            return ltype

    # oslo is the default
    return 'oslo'


def build_matcher_formatter(fname, minsev, styler,
                            log_style, supports_sev,
                            invert_order=False,
                            skip_raw=True, skip_sources_in=[],
                            skip_message_types=[],
                            highlight_content=False):
    # build base matcher and formatter
    matcher = None
    formatter = None

    log_style = log_style

    if log_style == 'devstack':
        formatter = outputter.StackLogOutputter(styler=styler)
        matcher = parsers.DevstackMetadataMatcher()
    elif log_style == 'console':
        formatter = outputter.ConsoleLogOutputter(styler=styler)
        matcher = parsers.ConsoleMetadataMatcher()
    elif log_style == 'keystone':
        formatter = outputter.KeystoneLogOutputter(styler=styler,
                                                   invert_order=invert_order)
        matcher = parsers.KeystoneMetadataMatcher()
    else:  # oslo-style
        formatter = outputter.LogOutputter(styler=styler,
                                           highlight_content=highlight_content)
        matcher = parsers.MetadataMatcher()

    # initialize options
    skip_sources = []
    if skip_raw:
        skip_sources.append(r'\w+\.messaging\.io\.raw')

    skip_sources.extend(skip_sources_in)

    # add on optional parts
    if supports_sev:
        levels_to_skip = [name for name, num in SEVS.items()
                          if num < SEVS[minsev]]
        if 'NONE' in levels_to_skip:
            levels_to_skip.append(None)
        matcher = matcher.chain(parsers.LevelSkipper(levels_to_skip))

    if log_style in ['olso', 'keystone'] and len(skip_sources) > 0:
        matcher = matcher.chain(parsers.SourceSkipper(skip_sources))

    if log_style == 'oslo':
        matcher = (matcher.chain(parsers.MessageMatcher())
                   .chain(parsers.MessageOpMatcher()))
    elif log_style == 'keystone':
        matcher = matcher.chain(parsers.KeystoneMessageOpMatcher())

    if not not_html(fname):
        matcher = matcher.chain(parsers.PreTagSkipper())

    if log_style in ['oslo', 'keystone'] and len(skip_message_types) > 0:
        matcher = matcher.chain(
            parsers.MessageTypeSkipper(skip_message_types))

    # add on the body matcher
    matcher = matcher.chain(parsers.MessageBodyMatcher())

    # return the results
    return (matcher, formatter)


def html_close():
    return ("</pre></body></html>\n")


def css_preamble(head_extra='', body_extra='', css_extra=''):
    """Write a valid html start with css that we need."""
    header = """<!DOCTYPE html>
<html>
<head>
<style>
a {color: #000; text-decoration: none}
a:hover {text-decoration: underline}
.DEBUG {color: #888}
.ERROR {color: #c00; font-weight: bold}
.TRACE {color: #c60}
.WARNING {color: #D89100;  font-weight: bold}
.INFO {color: #006; font-weight: bold}
.selector, .selector a {color: #888}
.selector a:hover {color: #c00}

.lvl_NONE {color: rgb(136,136,136);}
.lvl_AUDIT {color: rgb(136,136,136);}
.lvl_TRACE {color: rgb(136,136,136);}
.lvl_DEBUG {color: rgb(0,205,205);}
.lvl_INFO {color: rgb(0,255,0);}
.lvl_ERROR {color: rgb(204,0,0);}
.lvl_WARNING {color: rgb(205,0,205);}

.date {color: rgb(216,125,0);}
.src {color: rgb(0,0,102);}
.req_id {font-style: italic;}
.msg_op {color: rgb(205,0,205);}
.msg_num {font-style: italic;}
.msg_content {font-weight:bold;}
.msg_type {color: rgb(204,102,0);}
"""
    header += css_extra
    header += "\n</style>\n"

    header += head_extra
    header += """</head>
<body>"""

    header += body_extra
    header += "<pre id='main_container'>\n"
    return header
