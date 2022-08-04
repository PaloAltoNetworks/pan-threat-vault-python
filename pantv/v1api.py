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

import logging
import requests
import ssl
import sys
import time

from . import (mixin, ApiError, ArgsError,
               DEBUG1, DEBUG2, DEBUG3,
               title, __version__,
               DEFAULT_URL)


BASE_PATH = '/service/v1'


class ThreatVaultApi(mixin.Mixin):
    def __init__(self, *,
                 api_version=None,
                 url=None,
                 api_key=None,
                 verify=None,
                 timeout=None):
        self._log = logging.getLogger(__name__).log
        self._log(DEBUG2, '%s: %s, ThreatVaultApi: %s',
                  title, __version__, api_version)
        self._log(DEBUG2, 'Python version: %s', sys.version)
        self._log(DEBUG2, 'ssl: %s', ssl.OPENSSL_VERSION)
        self._log(DEBUG2, 'requests: %s', requests.__version__)

        self.api_version = api_version
        if url is None:
            self.url = DEFAULT_URL
        else:
            self.url = url
        auth = self._auth(api_key)
        self.session = self._session(auth=auth,
                                     verify=verify,
                                     timeout=timeout)

    def _request_retry(self, *,
                       retry=False,
                       retry_timeout=False,
                       func=None,
                       **kwargs):
        if retry_timeout:
            timeout_delay = 5
            timeout_retries = 3
        while True:
            try:
                resp = func(**kwargs)
            except requests.Timeout:
                if not (retry_timeout and timeout_retries):
                    raise
                self._log(DEBUG2, 'timeout, sleep %.2fs', timeout_delay)
                time.sleep(timeout_delay)
                timeout_delay *= 2
                timeout_retries -= 1
            else:
                if retry and resp.status_code == 429:
                    now = time.time()
                    day_remaining = \
                        resp.headers.get('x-day-ratelimit-remaining')
                    if day_remaining is None or day_remaining == '0':
                        break

                    minute_reset = \
                        resp.headers.get('x-minute-ratelimit-reset')
                    if minute_reset is None:
                        break
                    try:
                        minute_reset = int(minute_reset)
                    except ValueError as e:
                        self._log(DEBUG1, '%s', e)
                        break

                    if minute_reset > now:
                        rate_limit_delay = minute_reset - now
                        self._log(DEBUG2, 'status code 429, sleep %.2fs',
                                  rate_limit_delay)
                        time.sleep(rate_limit_delay)
                else:
                    break

        return resp

    def threats(self, *,
                type=None,
                id=None,
                name=None,
                cve=None,
                fromReleaseDate=None,
                toReleaseDate=None,
                fromReleaseVersion=None,
                toReleaseVersion=None,
                releaseDate=None,
                releaseVersion=None,
                sha256=None,
                md5=None,
                offset=None,
                limit=None,
                query_string=None,
                retry=False):
        args = locals()
        path = BASE_PATH + '/threats'
        url = self.url + path

        params = {}
        for x in args:
            if (x not in ('self', 'query_string', 'retry') and
               args[x] is not None):
                params[x] = args[x]

        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }

        resp = self._request_retry(retry=retry,
                                   func=self.session.get,
                                   **kwargs)

        return resp

    def threats_all(self,
                    **kwargs):
        if 'offset' not in kwargs or kwargs['offset'] is None:
            kwargs['offset'] = 0
        else:
            try:
                kwargs['offset'] = int(kwargs['offset'])
            except ValueError as e:
                raise ArgsError('offset not int')

        if 'limit' not in kwargs or kwargs['limit'] is None:
            limit = 1000
            kwargs['limit'] = limit
        else:
            try:
                limit = int(kwargs['limit'])
            except ValueError as e:
                raise ArgsError('limit not int')

        total = 0
        while True:
            resp = self.threats(**kwargs)
            if resp.status_code == 200:
                obj = resp.json()
                try:
                    threats = [obj['data'][k] for k in obj['data']]
                    count = obj['count']
                except KeyError as e:
                    raise ApiError('Malformed response, missing key %s' % e)
                current = 0
                for threat in threats:
                    current += len(threat)
                total += current
                self._log(DEBUG1, 'count %d current %d total %d',
                          count, current, total)
                for threat in threats:
                    for x in threat:
                        yield True, x

                if total >= count:
                    break

                kwargs['offset'] += limit
            else:
                yield False, resp

    def threats2(self, *,
                 type=None,
                 id=None,
                 name=None,
                 sha256=None,
                 md5=None,
                 data=None,
                 query_string=None,
                 retry=False):
        args = locals()
        path = BASE_PATH + '/threats'
        url = self.url + path

        params = {}
        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }
        if data is not None:
            if isinstance(data, (bytes, str, bytearray)):
                kwargs['data'] = data
                kwargs['headers'] = {'content-type': 'application/json'}
            else:
                kwargs['json'] = data
        else:
            for x in args:
                if (x not in ('self', 'query_string', 'retry') and
                   args[x] is not None):
                    if 'json' in kwargs:
                        kwargs['json'].update({x: args[x]})
                    else:
                        kwargs['json'] = {x: args[x]}

        resp = self._request_retry(retry=retry,
                                   func=self.session.post,
                                   **kwargs)

        return resp

    def threats_history(self, *,
                        type=None,
                        id=None,
                        order=None,
                        offset=None,
                        limit=None,
                        query_string=None,
                        retry=False):
        args = locals()
        path = BASE_PATH + '/threats/history'
        url = self.url + path

        params = {}
        for x in args:
            if (x not in ('self', 'query_string', 'retry') and
               args[x] is not None):
                params[x] = args[x]

        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }

        resp = self._request_retry(retry=retry,
                                   func=self.session.get,
                                   **kwargs)

        return resp

    def release_notes(self, *,
                      type=None,
                      version=None,
                      query_string=None,
                      retry=False):
        args = locals()
        path = BASE_PATH + '/release-notes'
        url = self.url + path

        params = {}
        for x in args:
            if (x not in ('self', 'query_string', 'retry') and
               args[x] is not None):
                params[x] = args[x]

        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }

        resp = self._request_retry(retry=retry,
                                   func=self.session.get,
                                   **kwargs)

        return resp

    def atp_reports(self, *,
                    id=None,
                    data=None,
                    query_string=None,
                    retry=False):
        path = BASE_PATH + '/atp/reports'
        url = self.url + path

        params = {}
        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }
        if data is not None:
            if isinstance(data, (bytes, str, bytearray)):
                kwargs['data'] = data
                kwargs['headers'] = {'content-type': 'application/json'}
            else:
                kwargs['json'] = data
        else:
            if id is not None:
                kwargs['json'] = {'id': id}

        resp = self._request_retry(retry=retry,
                                   func=self.session.post,
                                   **kwargs)

        return resp

    def atp_reports_pcaps(self, *,
                          id=None,
                          query_string=None,
                          retry=False):
        path = BASE_PATH + '/atp/reports/pcaps'
        url = self.url + path

        params = {}
        if id is not None:
            params['id'] = id

        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }

        resp = self._request_retry(retry=retry,
                                   func=self.session.get,
                                   **kwargs)

        return resp
