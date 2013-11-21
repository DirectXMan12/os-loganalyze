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
import wsgiref.util

from os_loganalyze import common
from os_loganalyze import printer


def _html_close():
    return ("</pre></body></html>\n")


def css_preamble(supports_sev, parameters):
    js_header = ''
    sev_header = ''
    css_header = ''
    if supports_sev:
        curr_sev = parameters.get('level', ['NONE'])[0]

        # generate CSS for hiding sevs dynamically
        for sev, lvl in common.SEVS.items():
            lower_sevs = [name for name, num
                          in common.SEVS.items() if num < lvl]
            for lower_sev in lower_sevs:
                css_header += ('.select_' + sev + ' div.'
                               + lower_sev + " { display: none; }\n")

        # generate the JS assist code
        js_header = """
<script type="text/javascript">
    document.addEventListener('DOMContentLoaded', function(event) {
        var selector = document.querySelector('span.selector.dynamic');
        if (selector != null) {
            var pre = document.getElementById('main_container');
            var LEVELS = ["""
        js_header += ', '.join(["'" + sev + "'" for sev in common.SEVS.keys()])
        js_header += """];
            var curr_href = window.location.href.split('?');
            var query_str = [];
            if (curr_href.length > 1) {
                query_str = curr_href[1].split('&');
            }
            if (query_str.length > 0) {
                var lvl = "NONE";
                for (var i = 0; i < query_str.length; i++) {
                    if (query_str[i].substr(0,5) == 'level') {
                        lvl = query_str[i].split('=')[1];
                        break;
                    }
                }
                pre.classList.add('select_'+lvl);
            }
            var partial_query_str = query_str.join('&');

            selector.addEventListener('click', function(event) {
                if (event.target.tagName.toLowerCase() != 'a' ||
                    event.target.getAttribute('data-dynamic') != 'true') {
                    return;
                }

                var href = event.target.getAttribute('href').substr(1);
                var lvl = "";
                if (href.length == 0) lvl = "NONE";
                else {
                    var query_items = href.split('&');
                    for (var i = 0; i < query_items.length; i++) {
                        var query_item = query_items[i].split('=');
                        if(query_item[0] == 'level') {
                            lvl = query_item[1];
                            break;
                        }
                    }
                }
                LEVELS.forEach(function(old_level) {
                    pre.classList.remove('select_'+old_level);
                });

                pre.classList.add('select_'+lvl);
                event.stopPropagation();
                event.preventDefault();
                var loc = event.target.getAttribute('href');
                window.history.pushState({}, '', loc);
            });
        }
    });
</script>
"""

        # generate the level selector code
        partial_params = deepcopy(parameters)
        pstr = ""
        if partial_params.get('level') is not None:
            del partial_params['level']
        if len(partial_params) > 0:
            params_pairs = []
            for k, arr in partial_params.items():
                params_pairs.extend([(k, v) for v in arr])
            pstr = '&' + '&'.join(k + '=' + v for k, v in params_pairs)

        sev_header += """
<span class='selector dynamic'>
Display level: [
"""
        if common.SEVS[curr_sev] > 0:
            sev_header += "<a href='?level=NONE" + pstr + "'>ALL</a> |\n"
        else:
            sev_header += ("<a href='?level=NONE" + pstr + "'" +
                           " data-dynamic='true'>ALL</a> |\n")

        sev_pairs = sorted(common.SEVS.items(), key=lambda x: x[1])
        lower_sevs = [name for name, num in sev_pairs
                      if num < common.SEVS[curr_sev] and num > 0]
        higher_sevs = [name for name, num in sev_pairs
                       if num >= common.SEVS[curr_sev]
                       and num < common.SEVS['ERROR']
                       and num > 0]

        for sev in lower_sevs:
            sev_header += ('<a href="?level=' + sev + pstr + '">'
                           + sev + "</a> | ")
        for sev in higher_sevs:
            sev_header += ('<a href="?level=' + sev + pstr + '"' +
                           ' data-dynamic="true">' + sev + "</a> | ")

        sev_header += ('<a href="?level=ERROR' + pstr +
                       '" data-dynamic="true">ERROR</a>')

        sev_header += "]</span>\n"

    return common.css_preamble(head_extra=js_header,
                               body_extra=sev_header,
                               css_extra=css_header)


def file_supports_sev(fname, parameters):
    sev_param = parameters.get('filter_sev', [None])[0]
    if sev_param is not None:
        sev_param = sev_param.lower() == 'true'
    level = parameters.get('level', [None])[0]
    return common.file_supports_sev(fname, sev_param, level)


def detect_log_type(fname, parameters):
    "Detect the type of the current log file"
    log_type = parameters.get('log_type', [None])[0]
    return common.detect_log_type(fname, log_type)


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
    log_type = detect_log_type(fname, parameters)
    invert_order = (parameters.get('invert_order', ['False'])[0]
                    .lower() == 'true')
    supports_sev = file_supports_sev(fname, parameters)
    skip_raw = (parameters.get('skip_raw', ['true'])[0].lower() == 'true')
    skip_source = [cgi.escape(src).replace(' ', '+')
                   for src in parameters.get('skip_source', [])]

    return common.build_matcher_formatter(fname, minsev, styler,
                                          log_type, invert_order=invert_order,
                                          supports_sev=supports_sev,
                                          skip_raw=skip_raw,
                                          skip_sources_in=skip_source)


def html_filter(fname, minsev, environ):
    """Generator to read logs and output html in a stream.

    This produces a stream of the htmlified logs which lets us return
    data quickly to the user, and use minimal memory in the process.
    """
    should_escape = common.not_html(fname)

    parameters = cgi.parse_qs(environ.get('QUERY_STRING', ''))

    supports_sev = file_supports_sev(fname, parameters)

    matcher, formatter = build_matcher_formatter(fname,
                                                 parameters,
                                                 minsev,
                                                 printer.HTMLStyler())

    yield css_preamble(supports_sev, parameters)

    for line in fileinput.FileInput(fname, openhook=fileinput.hook_compressed):
        if should_escape:
            newline = escape_html(line)
        else:
            newline = line

        res = matcher.run(newline, {})

        if res is None:
            continue

        yield formatter.output(res[0])
    yield common.html_close()


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
