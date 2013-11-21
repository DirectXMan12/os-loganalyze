#!/usr/bin/python
#
# Copyright (c) 2013 IBM Corp.
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


import cgi
from copy import deepcopy
import fileinput
import os.path
import re
import sys
import wsgiref.util

from os_loganalyze import filters as parsers
from os_loganalyze import outputter
from os_loganalyze import printer

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


def _html_close():
    return ("</pre></body></html>\n")


def _css_preamble(supports_sev, curr_sev, parameters):
    """Write a valid html start with css that we need."""
    header = """<html>
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
</style>
</head>
<body>"""
    if supports_sev:
        partial_params = deepcopy(parameters)
        pstr = ""
        if partial_params.get('level') is not None:
            del partial_params['level']
        if len(partial_params) > 0:
            params_pairs = []
            for k, arr in partial_params.items():
                params_pairs.extend([(k, v) for v in arr])
            pstr = '&' + '&'.join(k + '=' + v for k, v in params_pairs)

        header += """
<span class='selector dynamic'>
Display level: [
"""
        sev_pairs = sorted(SEVS.items(), key=lambda x: x[1])
        for sev, num in sev_pairs:
            header += ('<a href="?level=' + sev + pstr + '">'
                       + sev + "</a> | ")

        header += "]</span>\n"

    header += "<pre id='main_container'>\n"
    return header


def file_supports_sev(fname, parameters):
    sev_param = parameters.get('filter_sev', [None])[0]
    if sev_param is not None:
        if sev_param.lower() == 'false':
            return False
        elif sev_param.lower() == 'true':
            return True
    elif parameters.get('level') is not None:
        return True
    else:
        m = re.search(SUPPORTS_SEV_REGEXP, fname)
        return m is not None


def detect_log_type(fname, parameters):
    "Detect the type of the current log file"
    # if the user has manually specified a log type, use that
    if parameters.get('log_type', [None])[0] is not None:
        return parameters['log_type']

    local_fname = os.path.basename(fname)
    for ltype, regexp in LOG_TYPE_REGEXPS.items():
        if re.search(regexp, local_fname) is not None:
            return ltype

    # oslo is the default
    return 'oslo'


def not_html(fname):
    return re.search('(\.html(\.gz)?)$', fname) is None


def escape_html(line):
    """Escape the html in a line.

    We need to do this because we dump xml into the logs, and if we don't
    escape the xml we end up with invisible parts of the logs in turning it
    into html.
    """
    return cgi.escape(line)


def passthrough_filter(fname, minsev, environ):
    parameters = cgi.parse_qs(environ.get('QUERY_STRING', ''))

    matcher, _ = build_matcher_formatter(fname, parameters, minsev, None)

    for line in fileinput.FileInput(fname, openhook=fileinput.hook_compressed):
        if parameters.get('no_match', ['false'])[0].lower() == 'false':
            if matcher.run(line, {}) is None:
                continue

        yield line


def does_file_exist(fname):
    """Figure out if we'll be able to read this file.

    Because we are handling the file streams as generators, we actually raise
    an exception too late for us to be able to handle it before apache has
    completely control. This attempts to do the same open outside of the
    generator to trigger the IOError early enough for us to catch it, without
    completely changing the logic flow, as we really want the generator
    pipeline for performance reasons.

    This does open us up to a small chance for a race where the file comes
    or goes between this call and the next, however that is a vanishingly
    small possibility.
    """
    f = open(fname)
    f.close()


def build_matcher_formatter(fname, parameters, minsev, styler):
    # build base matcher and formatter
    matcher = None
    formatter = None

    log_style = detect_log_type(fname, parameters)

    if log_style == 'devstack':
        formatter = outputter.StackLogOutputter(styler=styler)
        matcher = parsers.DevstackMetadataMatcher()
    elif log_style == 'console':
        formatter = outputter.ConsoleLogOutputter(styler=styler)
        matcher = parsers.ConsoleMetadataMatcher()
    elif log_style == 'keystone':
        invert_order = (parameters.get('invert_order', ['False'])[0].lower()
                        == 'true')
        formatter = outputter.KeystoneLogOutputter(styler=styler,
                                                   invert_order=invert_order)
        matcher = parsers.KeystoneMetadataMatcher()
    else:  # oslo-style
        formatter = outputter.LogOutputter(styler=styler)
        matcher = parsers.MetadataMatcher()

    # initialize options
    supports_sev = file_supports_sev(fname, parameters)

    should_skip_raw = True
    if 'skip_raw' in parameters:
        if cgi.escape(parameters['skip_raw'][0]).lower() == 'false':
            should_skip_raw = False

    skip_sources = []
    if should_skip_raw:
        skip_sources.append(r'\w+\.messaging\.io\.raw')

    if 'skip_source' in parameters:
        skip_sources.extend([cgi.escape(src).replace(' ', '+')
                             for src in parameters['skip_source']])

    # add on optional parts
    if supports_sev:
        levels_to_skip = [name for name, num in SEVS.items()
                          if num < SEVS[minsev]]
        if 'NONE' in levels_to_skip:
            levels_to_skip.append(None)
        matcher = matcher.chain(parsers.LevelSkipper(levels_to_skip))

    if log_style in ['olso', 'keystone']:
        matcher = matcher.chain(parsers.SourceSkipper(skip_sources))

    if log_style == 'oslo':
        matcher = (matcher.chain(parsers.MessageMatcher())
                   .chain(parsers.MessageOpMatcher()))
    elif log_style == 'keystone':
        matcher = matcher.chain(parsers.KeystoneMessageOpMatcher())

    if not not_html(fname):
        matcher = matcher.chain(parsers.PreTagSkipper())

#    if log_style in ['oslo', 'keystone']:
#        matcher = matcher.chain(parsers.MessageTypeSkipper())

    # add on the body matcher
    matcher = matcher.chain(parsers.MessageBodyMatcher())

    # return the results
    return (matcher, formatter)


def html_filter(fname, minsev, environ):
    """Generator to read logs and output html in a stream.

    This produces a stream of the htmlified logs which lets us return
    data quickly to the user, and use minimal memory in the process.
    """
    should_escape = not_html(fname)

    parameters = cgi.parse_qs(environ.get('QUERY_STRING', ''))

    supports_sev = file_supports_sev(fname, parameters)

    matcher, formatter = build_matcher_formatter(fname,
                                                 parameters,
                                                 minsev,
                                                 printer.HTMLStyler())

    yield _css_preamble(supports_sev,
                        parameters.get('level', ['NONE'])[0],
                        parameters)

    for line in fileinput.FileInput(fname, openhook=fileinput.hook_compressed):
        if should_escape:
            newline = escape_html(line)
        else:
            newline = line

        res = matcher.run(newline, {})

        if res is None:
            continue

        yield formatter.output(res[0])
    yield _html_close()


def htmlify_stdin():
    out = sys.stdout
    out.write(_css_preamble(True, 'NONE', {}))

    skip_sources = [r'\w+\.messaging\.io\.raw']

    formatter = outputter.LogOutputter(styler=printer.HTMLStyler())
    matcher = (parsers.MetadataMatcher()
               .chain(parsers.SourceSkipper(skip_sources))
               .chain(parsers.MessageMatcher())
               .chain(parsers.MessageOpMatcher())
               #.chain(parsers.MessageTypeSkipper())
               .chain(parsers.MessageBodyMatcher()))

    for line in fileinput.FileInput():
        newline = escape_html(line)

        res = matcher.run(newline, {})
        if res is None:
            continue

        out.write(formatter.output(res[0]))

    out.write(_html_close())


def safe_path(root, environ):
    """Pull out a safe path from a url.

    Basically we need to ensure that the final computed path
    remains under the root path. If not, we return None to indicate
    that we are very sad.
    """
    path = wsgiref.util.request_uri(environ, include_query=0)
    match = re.search('htmlify/(.*)', path)
    if match:
        raw = match.groups(1)[0]
        newpath = os.path.abspath(os.path.join(root, raw))
        if newpath.find(root) == 0:
            return newpath

    return None


def should_be_html(environ):
    """Simple content negotiation.

    If the client supports content negotiation, and asks for text/html,
    we give it to them, unless they also specifically want to override
    by passing ?content-type=text/plain in the query.

    This should be able to handle the case of dumb clients defaulting to
    html, but also let devs override the text format when 35 MB html
    log files kill their browser (as per a nova-api log).
    """
    text_override = False
    accepts_html = ('HTTP_ACCEPT' in environ and
                    'text/html' in environ['HTTP_ACCEPT'])
    parameters = cgi.parse_qs(environ.get('QUERY_STRING', ''))
    if 'content-type' in parameters:
        ct = cgi.escape(parameters['content-type'][0])
        if ct == 'text/plain':
            text_override = True

    return accepts_html and not text_override


def get_min_sev(environ):
    print(environ.get('QUERY_STRING'))
    parameters = cgi.parse_qs(environ.get('QUERY_STRING', ''))
    if 'level' in parameters:
        return cgi.escape(parameters['level'][0])
    else:
        return "NONE"


def application(environ, start_response, root_path=None):
    if root_path is None:
        root_path = os.environ.get('OS_LOGANALYZE_ROOT_PATH',
                                   '/srv/static/logs')

    # make root path absolute in case we have a path with local components
    # specified
    root_path = os.path.abspath(root_path)

    status = '200 OK'

    logpath = safe_path(root_path, environ)
    if not logpath:
        status = '400 Bad Request'
        response_headers = [('Content-type', 'text/plain')]
        start_response(status, response_headers)
        return ['Invalid file url']

    try:
        minsev = get_min_sev(environ)
        if should_be_html(environ):
            response_headers = [('Content-type', 'text/html')]
            does_file_exist(logpath)
            generator = html_filter(logpath, minsev, environ)
            start_response(status, response_headers)
            return generator
        else:
            response_headers = [('Content-type', 'text/plain')]
            does_file_exist(logpath)
            generator = passthrough_filter(logpath, minsev, environ)
            start_response(status, response_headers)
            return generator
    except IOError:
        status = "404 Not Found"
        response_headers = [('Content-type', 'text/plain')]
        start_response(status, response_headers)
        return ['File Not Found']


# for development purposes, makes it easy to test the filter output
if __name__ == "__main__":
    htmlify_stdin()
