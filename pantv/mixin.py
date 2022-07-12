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
import json
import logging
import requests
import requests.adapters
import ssl

from . import ArgsError, DEBUG1, DEBUG2, DEBUG3

API_KEY_HEADER = 'x-api-key'


class _MixinShared:
    def _auth(self, api_key):
        if api_key is None:
            raise ArgsError('api_key required')

        return {API_KEY_HEADER: api_key}


class AioMixin(_MixinShared):
    async def __aenter__(self):
        self._log(DEBUG2, '%s', '__aenter__')
        return self

    async def __aexit__(self, *args):
        self._log(DEBUG2, '%s', '__aexit__')
        if not self.session.closed:
            self._log(DEBUG1, 'closing aiohttp session')
            await self.session.close()

    def _timeout(self, timeout):
        if timeout is None:
            return

        if isinstance(timeout, tuple):
            if len(timeout) != 2:
                raise ArgsError('timeout tuple length must be 2')
            x = aiohttp.ClientTimeout(sock_connect=timeout[0],
                                      sock_read=timeout[1])
        else:
            x = aiohttp.ClientTimeout(total=timeout)

        return x

    def _ssl_context(self, verify):
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

        if isinstance(verify, bool):
            if not verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        elif verify is not None:
            try:
                context.load_verify_locations(cafile=verify)
            except (FileNotFoundError, ssl.SSLError) as e:
                raise ValueError('%s: %s' % (verify, e))

        return context

    def _session(self, auth=None, timeout=None):
        async def on_request_start(session, trace_config_ctx, params):
            log = logging.getLogger(__name__).log
            log(DEBUG2, '%s %s', params.method, params.url)
            for k, v in params.headers.items():
                x = '*' * 6 if k == API_KEY_HEADER else v
                log(DEBUG3, '%s: %s', k, x)

        async def on_request_chunk_sent(session, trace_config_ctx, params):
            log = logging.getLogger(__name__).log
            if params.chunk:
                log(DEBUG3, '%s', params.chunk)

        async def on_request_end(session, trace_config_ctx, params):
            log = logging.getLogger(__name__).log
            log(DEBUG1, '%s %s %s %s %s',
                params.method,
                params.url,
                params.response.status,
                params.response.reason,
                params.response.headers.get('content-length'))
            for k, v in params.response.headers.items():
                log(DEBUG3, '%s: %s', k, v)

        kwargs = {}
        if auth is not None:
            kwargs['headers'] = auth
        if timeout is not None:
            kwargs['timeout'] = timeout

        if (logging.getLogger(__name__).getEffectiveLevel() in
           [DEBUG1, DEBUG2, DEBUG3]):
            trace_config = aiohttp.TraceConfig()
            trace_config.on_request_start.append(on_request_start)
            trace_config.on_request_chunk_sent.append(on_request_chunk_sent)
            trace_config.on_request_end.append(on_request_end)
            kwargs['trace_configs'] = [trace_config]

        return aiohttp.ClientSession(**kwargs)


class _TimeoutHTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = None
        if 'timeout' in kwargs:
            self.timeout = kwargs['timeout']
            del kwargs['timeout']
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get('timeout')
        if timeout is None:
            kwargs['timeout'] = self.timeout
        return super().send(request, **kwargs)


class Mixin(_MixinShared):
    def __enter__(self):
        self._log(DEBUG2, '%s', '__enter__')
        return self

    def __exit__(self, *args):
        self._log(DEBUG2, '%s', '__exit__')
        self._log(DEBUG1, 'closing requests session')
        self.session.close()

    def _session(self,
                 auth=None,
                 verify=None,
                 timeout=None):
        session = requests.Session()

        if auth is not None:
            session.headers.update(auth)
        if verify is not None:
            session.verify = verify
        if timeout is not None:
            adapter = _TimeoutHTTPAdapter(timeout=timeout)
            session.mount("https://", adapter)

        return session
