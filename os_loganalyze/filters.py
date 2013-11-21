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


def merge_dict_tree(a, b, path=None):
    """Merge Two Dictionaries of Dictionaries

    Merges dict b into dict a recursively
    """
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dict_tree(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass
            else:
                raise Exception(('Conflict while merging dictionaries '
                                'at {0}').format('.'.join(path + [str(key)])))
        else:
            a[key] = b[key]
    return a


class LogMatcher(object):
    """Extracts data and/or filters log lines
    """

    def __init__(self):
        self.next_matcher = None

    def chain(self, next_matcher):
        """Chain two matchers together

        Forward output from this matcher
        to another matcher, such that when
        this matcher is run, the results of
        the next matcher will be returned.
        """
        if self.next_matcher is None:
            self.next_matcher = next_matcher
        else:
            self.next_matcher.chain(next_matcher)

        return self

    def _run(self, line, data_so_far):
        (data, rest) = self.extract_data(line)
        merged_data = merge_dict_tree(dict(data_so_far), data)
        if self.should_skip(line, merged_data, rest):
            return None
        else:
            return (merged_data, rest)

    def run(self, line, data_so_far):
        """Process a single line

        This method processes a single log line and returns
        either None, if the line should be skipped in the final
        output, or a tuple containing the processed portion of
        the line as a dict, and the rest of the line.
        """
        res = self._run(line, data_so_far)
        if self.next_matcher is not None:
            if res is not None:
                return self.next_matcher.run(res[1], res[0])
            else:
                return None
        else:
            return res

    def should_skip(self, full_line, data, rest):
        """Decide whether to skip a line

        This method should return True if a line should
        be skipped, and False otherwise.  The default
        implementation always returns False; you should
        override it if you want your subclass to filter.

        Args:
            full_line (str): the line as passed to this matcher
            data (dict): the data so far, include any data
                         returned by this matcher
            rest (dict): the portion of this line not processed
                         by this matcher
        """
        return False

    def extract_data(self, line):
        """Extract data from a line

        This method extracts relevant data from a line to
        highlight later, returning the data from the
        matched portion of the line as a dict,
        and the rest of the line as a str (in a tuple).
        The default implementation returns an empty dict
        and the whole line; you should override this to
        actually get results.
        """
        return ({}, line)


class DevstackMetadataMatcher(LogMatcher):
    """Match Generic Metadata from Devstack Logs

    Matches the generic metadata present in devstack
    run logs, which are different than Oslo-style logs.
    Should be run first
    """

    # date time
    # indents
    REGEXP = re.compile(r'^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) '
                        r'(?:(\++) )?')

    def extract_data(self, line):
        match = self.REGEXP.match(line)
        if match is None:
            return ({}, line)
        else:
            res = {'date': match.group(1),
                   'time': match.group(2),
                   'level': len(match.group(3) or [])}

            return (res, line[match.end():])


class ConsoleMetadataMatcher(LogMatcher):
    """Match Generic Metadata from 'console'-style Logs

    Matches generic metadata from 'console'-style
    logs.  Should be run first.  May contain embedded
    Devstack Logs
    """

    # date time
    REGEXP = re.compile(r'^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}\.\d{1,3}) '
                        r'\|')
    DEVSTACK_REGEXP = DevstackMetadataMatcher.REGEXP

    def extract_data(self, line):
        match = self.REGEXP.match(line)
        if match is None:
            return ({}, line)
        else:
            res = {'date': match.group(1),
                   'time': match.group(2)}

            rest = line[match.end():]
            devstack_match = self.DEVSTACK_REGEXP.match(rest.lstrip())
            if devstack_match is None:
                return (res, rest.lstrip())
            else:
                res['is_devstack'] = True
                res['devstack_level'] = len(devstack_match.group(3) or '')
                return (res, rest[devstack_match.end():].lstrip())


class KeystoneMetadataMatcher(LogMatcher):
    """Match Generic Metadata from a Keystone Log

    Matches the generic metadata present in keystone
    logs, which are similar to, but distinct from,
    Oslo logs.  Should be run first
    """

    VALID_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'TRACE', 'AUDIT']

    # source
    # date time
    # level
    # subject
    REGEXP = re.compile(r'^\(([a-zA-Z\-_.0-9]+)\): '
                        r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2},\d{3}) '
                        r'(' + ('|'.join(VALID_LEVELS)) + r') '
                        r'([a-zA-Z0-9_]+) ')

    def extract_data(self, line):
        match = self.REGEXP.match(line)
        if match is None:
            return ({}, line)
        else:
            res = {'source': match.group(1),
                   'date': match.group(2),
                   'time': match.group(3),
                   'level': match.group(4),
                   'subject': match.group(5)}

            return (res, line[match.end():])


class KeystoneMessageOpMatcher(LogMatcher):
    """Match Keystone Log Message Type Information

    Matches the message type of keystone logs,
    which appears just after the subject.
    Should be run after the main keystone
    metadata matcher.
    """

    REGEXP = re.compile(r'^([a-zA-Z0-9_]+) ')

    def extract_data(self, line):
        match = self.REGEXP.match(line)
        if match is None:
            return ({}, line)
        else:
            res = {'message': {'type': match.group(1)}}
            return (res, line[match.end():])


class MetadataMatcher(LogMatcher):
    """Match Generic Metadata

    Matches generic metadata present for all
    OpenStack log lines.  Should be run first
    """

    VALID_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'TRACE', 'AUDIT']

    # date time
    # pid? level
    # source
    # request_id
    REGEXP = re.compile(r'^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}\.\d{1,3}) '
                        r'(?:(\d+) )?(' + ('|'.join(VALID_LEVELS)) + r') '
                        r'([a-zA-Z0-9_.]+) '
                        r'(?:\[(-|(?:(instance: )?[a-zA-Z0-9\-]+ .+ .+))\] )?')

    def extract_data(self, line):
        #line = line.rstrip()
        match = self.REGEXP.match(line)
        if match is None:
            return ({}, line)
        else:
            res = {'date': match.group(1),
                   'time': match.group(2),
                   'id': match.group(3),
                   'level': match.group(4),
                   'source': match.group(5),
                   'req_id': match.group(6)}

            return (res, line[match.end():])


class MessageMatcher(LogMatcher):
    """Match Structured Message Data

    Should run after the MetadataMatcher.
    Matches message contents.
    """

    VALID_OPS = ['OPEN', 'SENT', 'RECV', 'RCVD',
                 'REST', 'READ', 'RETR', 'RACK']
    REGEXP = re.compile((r'^({0})'
                         r'\[([a-f0-9]+)\]\: ').format('|'.join(VALID_OPS)))

    def extract_data(self, line):
        line = line.rstrip()
        match = self.REGEXP.match(line)
        if match is None:
            return ({}, line)
        else:
            res = {'message': {'operation': match.group(1),
                               'num': match.group(2)}}

            return (res, line[match.end():])


class MessageOpMatcher(LogMatcher):
    """Match Message Operation

    Should run after MessageMatcher.
    Matches message body contents, extracting message
    types (e.g. Message, etc)
    """

    REGEXP = re.compile(r'(\w+)(?=\()')

    def extract_data(self, line):
        line = line.rstrip()
        match = self.REGEXP.match(line)
        if match is None:
            return ({}, line)
        else:
            res = {'message': {'type': match.group(1)}}
            return (res, line[match.end():])


class MessageBodyMatcher(LogMatcher):
    """Match Message Body

    Consumes the rest of the input,
    so should be run last.
    """

    def extract_data(self, line):
        return ({'message': {'body': line.rstrip()}}, '')


class LevelSkipper(LogMatcher):
    """Skip Lines by Level

    Skips lines whose log level matches
    one of the given levels.
    """

    def __init__(self, levels):
        super(LevelSkipper, self).__init__()
        self.levels = levels

    def should_skip(self, full_line, data, rest):
        if data.get('level') in self.levels:
            return True
        else:
            return False


class SourceSkipper(LogMatcher):
    """Skip Lines by Source

    Skips lines whose source matches one of the
    given regular expressions (which is wrapped in
    '^YOUR_REGEXP_HERE$')
    """

    def __init__(self, sources):
        super(SourceSkipper, self).__init__()
        self.sources = [re.compile('^' + src + '$') for src in sources]

    def should_skip(self, full_line, data, rest):
        if data.get('source') is None:
            return False

        for src in self.sources:
            if src.match(data['source']):
                return True

        return False


class MessageTypeSkipper(LogMatcher):
    """Skip Lines by Message Type
    Skips lines who have message types and
    whose message type matches one of the given
    regular expressions (which is wrapped in
    '^YOUR_REGEXP_HERE$').
    """

    def __init__(self, msg_types):
        super(MessageTypeSkipper, self).__init__()
        self.msg_types = [re.compile('^' + src + '$') for src in msg_types]

    def should_skip(self, full_line, data, rest):
        if data.get('message') is None or data['message'].get('type') is None:
            return False

        for msg_type in self.msg_types:
            if msg_type.match(data['message']['type']):
                return True

        return False


class PreTagSkipper(LogMatcher):
    """Skips 'pre' tags
    Skips lines that are just <pre> or </pre>
    tags
    """

    REGEXP = re.compile(r'^\s*\</?pre\>\s*$')

    def should_skip(self, full_line, data, rest):
        return self.REGEXP.match(full_line) is not None
