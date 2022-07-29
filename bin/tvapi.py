#!/usr/bin/env python3

#
# Copyright (c) 2022 Palo Alto Networks, Inc.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import aiohttp
import asyncio
import copy
import getopt
import json
import logging
import os
import pprint
import sys
import time
import traceback
try:
    import jmespath
    have_jmespath = True
except ImportError:
    have_jmespath = False

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]


from pantv import (ThreatVaultApi, ApiError, ArgsError,
                   DEBUG1, DEBUG2, DEBUG3,
                   title, DEFAULT_API_VERSION, __version__,
                   DEFAULT_URL)

INDENT = 4


def main():
    options = parse_opts()

    if options['debug']:
        logger = logging.getLogger()
        if options['debug'] == 3:
            logger.setLevel(DEBUG3)
        elif options['debug'] == 2:
            logger.setLevel(DEBUG2)
        elif options['debug'] == 1:
            logger.setLevel(DEBUG1)

        log_format = '%(message)s'
        if options['dtime']:
            log_format = '%(asctime)s ' + log_format
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    kwargs = {}
    for x in ['api-version', 'url', 'api-key',
              'verify', 'timeout']:
        if options[x] is not None:
            k = x.replace('-', '_')
            kwargs[k] = options[x]

    try:
        if options['aio']:
            asyncio.run(aioapi_request(kwargs, options))
        else:
            api_request(kwargs, options)
    except KeyboardInterrupt:
        sys.exit(0)


def print_exception(exc, debug):
    limit = 0
    if debug == 1:
        limit = -1
    elif debug > 1:
        limit = None
    x = traceback.format_exception(None, exc, exc.__traceback__, limit=limit)
    print(''.join(x), end='', file=sys.stderr)
    sys.exit(1)


def api_request(kwargs, options):
    try:
        with ThreatVaultApi(**kwargs) as api:
            request(api, options)

    except Exception as e:
        print_exception(e, options['debug'])


async def aioapi_request(kwargs, options):
    try:
        async with ThreatVaultApi(**kwargs) as api:
            await aiorequest(api, options)

    except Exception as e:
        print_exception(e, options['debug'])


class GeneratorList(list):
    def __init__(self, generator, **kwargs):
        self.name = generator.__name__
        self.generator = generator(**kwargs)

    def __iter__(self):
        for ok, x in self.generator:
            if ok:
                yield x
            else:
                raise ApiError('%s: %s %s: %s' % (self.name,
                                                  x.status_code,
                                                  x.reason,
                                                  x.text))

    def __len__(self):
        # ensure list is true
        return 1


def request(api, options):
    if options['threats']:
        id_ = options['id'][0] if options['id'] is not None else None
        name = options['name'][0] if options['name'] is not None else None
        sha256 = options['sha256'][0] \
            if options['sha256'] is not None else None
        md5 = options['md5'][0] \
            if options['md5'] is not None else None
        kwargs = {
            'type': options['type'],
            'id': id_,
            'name': name,
            'sha256': sha256,
            'md5': md5,
            'offset': options['offset'],
            'limit': options['limit'],
            'query_string': options['query_string_obj'],
        }

        if options['all'] and options['opt_json']:
            # only allowed with noaio
            kwargs['retry'] = True
            threats = GeneratorList(generator=api.threats_all, **kwargs)
            for x in json.JSONEncoder().iterencode(threats):
                if options['print_json']:
                    # XXX warn if not print_json?
                    print(x, end='')

        elif options['all']:
            obj = {'data': []}
            for ok, x in api.threats_all(retry=True, **kwargs):
                if ok:
                    obj['data'].append(x)
                else:
                    print_status('threats_all', x)
                    print_response(options, x)
                    x.raise_for_status()
            print_json_response(options, obj)

        else:
            resp = api.threats(**kwargs)
            print_status('threats', resp)
            print_response(options, resp)
            resp.raise_for_status()

    elif options['threats2']:
        resp = api.threats2(
            type=options['type'],
            id=options['id'],
            name=options['name'],
            sha256=options['sha256'],
            md5=options['md5'],
            data=options['data'],
            query_string=options['query_string_obj'])
        print_status('threats2', resp)
        print_response(options, resp)
        resp.raise_for_status()

    elif options['threats_history']:
        id_ = options['id'][0] if options['id'] is not None else None
        resp = api.threats_history(
            type=options['type'],
            id=id_,
            offset=options['offset'],
            limit=options['limit'],
            query_string=options['query_string_obj'])
        print_status('threats-history', resp)
        print_response(options, resp)
        resp.raise_for_status()

    elif options['release-notes']:
        resp = api.release_notes(
            type=options['type'],
            version=options['note-version'],
            query_string=options['query_string_obj'])
        print_status('release-notes', resp)
        print_response(options, resp)
        resp.raise_for_status()

    elif options['atp-reports']:
        resp = api.atp_reports(
            id=options['id'],
            data=options['data'],
            query_string=options['query_string_obj'])
        print_status('atp-reports', resp)
        print_response(options, resp)
        resp.raise_for_status()

    elif options['atp-pcaps']:
        resp = api.atp_reports_pcaps(
            id=options['id'],
            query_string=options['query_string_obj'])
        print_status('atp-pcaps', resp)
        print_response(options, resp)
        resp.raise_for_status()


async def aiorequest(api, options):
    if options['threats']:
        id_ = options['id'][0] if options['id'] is not None else None
        name = options['name'][0] if options['name'] is not None else None
        sha256 = options['sha256'][0] \
            if options['sha256'] is not None else None
        md5 = options['md5'][0] \
            if options['md5'] is not None else None
        kwargs = {
            'type': options['type'],
            'id': id_,
            'name': name,
            'sha256': sha256,
            'md5': md5,
            'offset': options['offset'],
            'limit': options['limit'],
            'query_string': options['query_string_obj'],
        }

        if options['all']:
            obj = {'data': []}
            async for ok, x in api.threats_all(retry=True, **kwargs):
                if ok:
                    obj['data'].append(x)
                else:
                    print_status('threats_all', x)
                    await aioprint_response(options, x)
                    x.raise_for_status()
            print_json_response(options, obj)

        else:
            resp = await api.threats(**kwargs)
            print_status('threats', resp)
            await aioprint_response(options, resp)
            resp.raise_for_status()

    elif options['threats2']:
        resp = await api.threats2(
            type=options['type'],
            id=options['id'],
            name=options['name'],
            sha256=options['sha256'],
            md5=options['md5'],
            data=options['data'],
            query_string=options['query_string_obj'])
        print_status('threats2', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()

    elif options['threats_history']:
        id_ = options['id'][0] if options['id'] is not None else None
        resp = await api.threats_history(
            type=options['type'],
            id=id_,
            offset=options['offset'],
            limit=options['limit'],
            query_string=options['query_string_obj'])
        print_status('threats-history', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()

    elif options['release-notes']:
        resp = await api.release_notes(
            type=options['type'],
            version=options['note-version'],
            query_string=options['query_string_obj'])
        print_status('release-notes', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()

    elif options['atp-reports']:
        resp = await api.atp_reports(
            id=options['id'],
            data=options['data'],
            query_string=options['query_string_obj'])
        print_status('atp-reports', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()

    elif options['atp-pcaps']:
        resp = await api.atp_reports_pcaps(
            id=options['id'],
            query_string=options['query_string_obj'])
        print_status('atp-pcaps', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()


def print_status(name, resp):
    print('%s:' % name, end='', file=sys.stderr)
    if hasattr(resp, 'status'):
        if resp.status is not None:
            print(' %d' % resp.status, end='', file=sys.stderr)
    elif hasattr(resp, 'status_code'):
        if resp.status_code is not None:
            print(' %d' % resp.status_code, end='', file=sys.stderr)
    if resp.reason is not None:
        print(' %s' % resp.reason, end='', file=sys.stderr)
    if resp.headers is not None:
        print(' %s' % resp.headers.get('content-length'),
              end='', file=sys.stderr)
    print(file=sys.stderr)


def print_rate_limits(headers):
    limits = [
        'X-Minute-RateLimit-Limit',
        'X-Minute-RateLimit-Remaining',
        'X-Minute-RateLimit-Reset',
        'X-Day-RateLimit-Limit',
        'X-Day-RateLimit-Remaining',
        'X-Day-RateLimit-Reset',
    ]

    if headers is not None:
        for limit in limits:
            value = headers.get(limit)
            if value is None:
                continue
            friendly = limit[2:]
            if friendly.endswith('-Reset'):
                try:
                    x = time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(int(value)))
                    value = '%s (%s)' % (value, x)
                except ValueError:
                    pass

            print('%s: %s' % (friendly, value))


def print_response(options, resp):
    if options['print_rate_limits']:
        print_rate_limits(resp.headers)
    content_type = resp.headers.get('content-type', '').lower()
    if content_type.startswith('application/json'):
        x = resp.json()
        print_json_response(options, x)
    elif content_type.startswith('application/octet-stream'):
        x = resp.content
        name = options['id'][0] if options['id'] is not None else 'unknown'
        save_pcap(x, name, options['dst'])
    else:
        print(resp.text)


async def aioprint_response(options, resp):
    if options['print_rate_limits']:
        print_rate_limits(resp.headers)
    content_type = resp.headers.get('content-type', '').lower()
    if content_type.startswith('application/json'):
        x = await resp.json()
        print_json_response(options, x)
    elif content_type.startswith('application/octet-stream'):
        x = await resp.read()
        name = options['id'][0] if options['id'] is not None else 'unknown'
        save_pcap(x, name, options['dst'])
    else:
        print(await resp.text())


def print_json_response(options, x):
    if options['jmespath'] is not None:
        try:
            x = jmespath.search(options['jmespath'], x)
        except jmespath.exceptions.JMESPathError as e:
            print('JMESPath %s: %s' % (e.__class__.__name__, e),
                  file=sys.stderr)
            sys.exit(1)

    if options['print_python']:
        print(pprint.pformat(x))

    if options['print_json']:
        print(json.dumps(x, sort_keys=True, indent=INDENT))


def save_pcap(body, name, dst):
    filename = name + '.pcap'
    if dst is not None:
        path = dst
        if os.path.isdir(path):
            path = os.path.join(path, filename)
    else:
        path = filename

    try:
        with open(path, 'wb') as f:
            f.write(body)
    except OSError as e:
        print('save_pcap: %s' % e, file=sys.stderr)
        sys.exit(1)

    print('pcap saved to %s' % path, file=sys.stderr)


def process_arg(arg):
    stdin_char = '-'

    if arg == stdin_char:
        lines = sys.stdin.readlines()
    else:
        try:
            f = open(arg)
            lines = f.readlines()
            f.close()
        except IOError:
            lines = [arg]

    lines = ''.join(lines)
    return lines


def parse_opts():
    def opt_verify(x):
        if x == 'yes':
            return True
        elif x == 'no':
            return False
        elif os.path.exists(x):
            return x
        else:
            print('Invalid --verify option:', x, file=sys.stderr)
            sys.exit(1)

    options = {
        'config': {},
        'api-version': None,
        'url': None,
        'api-key': None,
        'threats': False,
        'threats2': False,
        'threats_history': False,
        'release-notes': False,
        'atp-reports': False,
        'atp-pcaps': False,
        'all': False,
        'id': None,
        'name': None,
        'sha256': None,
        'md5': None,
        'type': None,
        'note-version': None,
        'data': None,
        'offset': None,
        'limit': None,
        'query_strings': [],
        'query_string_obj': None,
        'verify': None,
        'aio': True,
        'print_json': False,
        'print_python': False,
        'print_rate_limits': False,
        'dst': None,
        'jmespath': None,
        'opt_json': False,
        'timeout': None,
        'debug': 0,
        'dtime': False,
        }

    short_options = 'F:J:jOpQ:'
    long_options = [
        'help', 'version', 'debug=', 'dtime',
        'api-version=', 'url=', 'api-key=',
        'threats', 'threats2', 'threats-history', 'release-notes',
        'atp-reports', 'atp-pcaps',
        'all', 'id=', 'name=', 'sha256=', 'md5=',
        'type=', 'note-version=', 'data=',
        'offset=', 'limit=',
        'rate-limits', 'dst=', 'verify=', 'aio', 'noaio',
        'timeout=',
    ]

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   short_options,
                                   long_options)
    except getopt.GetoptError as error:
        print(error, file=sys.stderr)
        sys.exit(1)

    for opt, arg in opts:
        if False:
            pass
        elif opt == '-F':
            try:
                with open(arg, 'r') as f:
                    x = json.load(f)
                    options['config'].update(x)
            except (IOError, ValueError) as e:
                print('%s: %s' % (arg, e), file=sys.stderr)
                sys.exit(1)
        elif opt == '--api-version':
            options['api-version'] = arg
        elif opt == '--url':
            options['url'] = arg
        elif opt == '--api-key':
            options['api-key'] = arg
        elif opt == '--threats':
            options['threats'] = True
        elif opt == '--threats2':
            options['threats2'] = True
        elif opt == '--threats-history':
            options['threats_history'] = True
        elif opt == '--release-notes':
            options['release-notes'] = True
        elif opt == '--atp-reports':
            options['atp-reports'] = True
        elif opt == '--atp-pcaps':
            options['atp-pcaps'] = True
        elif opt == '--all':
            options['all'] = True
        elif opt == '--id':
            if options['id'] is None:
                options['id'] = []
            options['id'].append(arg)
        elif opt == '--name':
            if options['name'] is None:
                options['name'] = []
            options['name'].append(arg)
        elif opt == '--sha256':
            if options['sha256'] is None:
                options['sha256'] = []
            options['sha256'].append(arg)
        elif opt == '--md5':
            if options['md5'] is None:
                options['md5'] = []
            options['md5'].append(arg)
        elif opt == '--type':
            options['type'] = arg
        elif opt == '--note-version':
            options['note-version'] = arg
        elif opt == '--data':
            options['data'] = process_arg(arg)
        elif opt == '--offset':
            options['offset'] = arg
        elif opt == '--limit':
            options['limit'] = arg
        elif opt == '-Q':
            options['query_strings'].append(process_arg(arg))
        elif opt == '--verify':
            options['verify'] = opt_verify(arg)
        elif opt == '--timeout':
            try:
                options['timeout'] = tuple(float(x) for x in arg.split(','))
            except ValueError as e:
                print('Invalid timeout %s: %s' % (arg, e), file=sys.stderr)
                sys.exit(1)
            if len(options['timeout']) == 1:
                options['timeout'] = options['timeout'][0]
        elif opt == '--aio':
            options['aio'] = True
        elif opt == '--noaio':
            options['aio'] = False
        elif opt == '-j':
            options['print_json'] = True
        elif opt == '-p':
            options['print_python'] = True
        elif opt == '--rate-limits':
            options['print_rate_limits'] = True
        elif opt == '--dst':
            options['dst'] = arg
        elif opt == '-J':
            if not have_jmespath:
                print('Install JMESPath for -J support: http://jmespath.org/',
                      file=sys.stderr)
                sys.exit(1)
            options['jmespath'] = arg
        elif opt == '-O':
            options['opt_json'] = True
        elif opt == '--debug':
            try:
                options['debug'] = int(arg)
                if options['debug'] < 0:
                    raise ValueError
            except ValueError:
                print('Invalid debug:', arg, file=sys.stderr)
                sys.exit(1)
            if options['debug'] > 3:
                print('Maximum debug level is 3', file=sys.stderr)
                sys.exit(1)
        elif opt == '--dtime':
            options['dtime'] = True
        elif opt == '--version':
            print(title, __version__)
            sys.exit(0)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    if options['all'] and options['opt_json'] and options['aio']:
        print('Must use --noaio with --all -O', file=sys.stderr)
        sys.exit(0)

    for x in ['api-version', 'url', 'api-key']:
        if x in options['config'] and options[x] is None:
            options[x] = options['config'][x]
    if 'verify' in options['config'] and options['verify'] is None:
        options['verify'] = opt_verify(options['config']['verify'])
    if options['verify'] is None:
        options['verify'] = True

    if options['query_strings']:
        obj = {}
        for r in options['query_strings']:
            try:
                x = json.loads(r)
            except ValueError as e:
                print('%s: %s' % (e, r), file=sys.stderr)
                sys.exit(1)
            obj.update(x)
        try:
            _ = json.dumps(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

        options['query_string_obj'] = obj

    if options['debug'] > 2:
        x = copy.deepcopy(options)
        if x['api-key'] is not None:
            x['api-key'] = '*' * 6
        if ('api-key' in x['config'] and
           x['config']['api-key'] is not None):
            x['config']['api-key'] = '*' * 6
        print(pprint.pformat(x), file=sys.stderr)

    return options


def usage():
    usage = '''%s [options]
    --api-key key            API key
    --threats                threats API request
    --threats2               multiple threats bulk API request
    --threats-history        threats release history API request
    --release-notes          release-notes API request
    --atp-reports            ATP reports API request
    --atp-pcaps              ATP reports pcaps API request
    --all                    get all threats
    --id id                  signature/report ID (multiple --id's allowed)
    --name name              signature name (multiple --names's allowed)
    --sha256 hash            SHA-256 hash (multiple --sha256's allowed)
    --md5 hash               MD5 hash (multiple --md5's allowed)
    --type type              signature/release-note type
    --note-version version   release-note version
    --offset num             items offset
    --limit num              number of items to return
    -Q json                  URL query string (multiple -Q's allowed)
    --data json              threats2, atp-reports POST data
    --url url                API URL
                             default %s
    --verify opt             SSL server verify option: yes|no|path
    --aio                    Use asyncio (default)
    --noaio                  Don't use asyncio
    --api-version version    API version (default %s)
    -j                       print JSON
    -p                       print Python
    --rate-limits            print response header rate limits
    --dst dst                save pcap to directory or path
    -J expression            JMESPath expression for JSON response data
    -O                       optimized get all with JSON only output
    --timeout timeout        connect, read timeout
    -F path                  JSON options (multiple -F's allowed)
    --debug level            debug level (0-3)
    --dtime                  add time string to debug output
    --version                display version
    --help                   display usage
'''
    print(usage % (os.path.basename(sys.argv[0]),
                   DEFAULT_URL, DEFAULT_API_VERSION), end='')


if __name__ == '__main__':
    main()
