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


class LogOutputter(object):
    def __init__(self, styler, highlight_content=True, strip_u=True):
        self.highlight_content = highlight_content
        self.strip_u = strip_u
        self.styler = styler

    def output(self, line):
        # print the header
        res = ""

        if line.get('level') is None:
            res = line['message']['body']
        else:
            lvl = getattr(self.styler,
                          'lvl_' + line['level'], 'lvl_other')(line['level'])
            header_fmt = ""
            if line['req_id'] is not None:
                header_fmt = "{dt} {sid} {lvl} {src} [{req_id}] "
            else:
                header_fmt = "{dt} {sid} {lvl} {src} "

            header = header_fmt.format(
                dt=self.styler.date(line['date'] + ' ' + line['time']),
                sid=line['id'],
                lvl=lvl,
                src=self.styler.source(line['source']),
                req_id=self.styler.req_id(line['req_id'])
            )
            res += header

            body = line['message']['body']
            if (line['message'].get('operation') is not None):
                res += '{op} [{num}]: '.format(
                    op=self.styler.msg_op(line['message']['operation']),
                    num=self.styler.msg_num(line['message']['num'])
                )

                if self.highlight_content:
                    body = body.replace('content=',
                                        self.styler.msg_content('content='))

            if (line['message'].get('type') is not None):
                # TODO(sross): strip u
                res += self.styler.msg_type(line['message']['type'])

            res += body

        return self.styler.wrap(res, line.get('level', 'NONE'))


class KeystoneLogOutputter(object):
    def __init__(self, styler, invert_order=False):
        self.styler = styler
        self.invert_order = invert_order

    def output(self, line):
        res = ""
        if line.get('level') is None:
            res = line['message']['body']
        else:
            fmt_line = ""
            if self.invert_order:
                fmt_line = '{dt}: ({src}) {lvl} {subj} '
            else:
                fmt_line = '({src}): {dt} {lvl} {subj} '

            res += (fmt_line.format(
                src=self.styler.source(line['source']),
                dt=self.styler.date(line['date'] + ' ' + line['time']),
                lvl=self.styler.level(line['level']),
                subj=self.styler.subject(line['subject'])))

            res += self.styler.msg_type(line['message']['type'])
            res += ' '
            res += line['message']['body']

        return self.styler.wrap(res, line.get('level', 'NONE'))


class StackLogOutputter(object):
    def __init__(self, styler):
        self.styler = styler

    def output(self, line):
        res = ""

        res += self.styler.date(line['date'] + ' ' + line['time'])
        res += ' '
        for i in range(line['level']):
            res += '+'
        if line['level'] > 0:
            res += ' '
        res += line['message']['body']

        lvl = 'DEBUG'
        if line['level'] == 0:
            lvl = 'INFO'
        return self.styler.wrap(res, lvl)


class ConsoleLogOutputter(object):
    def __init__(self, styler):
        self.styler = styler

    def output(self, line):
        if line.get('date') is None:
            raise Exception(line)

        res = ""

        res += self.styler.date(line['date'] + ' ' + line['time'])
        res += ' | '

        if line.get('is_devstack'):
            res += '(devstack) '
            for i in range(line['devstack_level']):
                res += '+'
            if line['devstack_level'] > 0:
                res += ' '

        res += line['message']['body']

        lvl = 'AUDIT'
        if line.get('is_devstack'):
            if line['devstack_level'] > 0:
                lvl = 'DEBUG'
            else:
                lvl = 'INFO'

        return self.styler.wrap(res, lvl)
