import asyncio
import json
import logging
import os
import sys

import pantv


class _MixinShared:
    def tvapi(self):
        def opt_verify(x):
            if x == 'yes':
                return True
            elif x == 'no':
                return False
            elif os.path.exists(x):
                return x
            else:
                print('Invalid verify option:', x, file=sys.stderr)
                sys.exit(1)

        path = os.getenv('PANTV_KEYS')
        if path is None:
            raise RuntimeError('no PANTV_KEYS in environment')
        with open(path, 'r') as f:
            x = json.load(f)
        kwargs = {
            'api_key': x['api-key'],
        }
        if 'verify' in x:
            kwargs['verify'] = opt_verify(x['verify'])
        if 'url' in x:
            kwargs['url'] = x['url']

        x = os.getenv('PANTV_DEBUG')
        if x is not None:
            debug = int(x)
            logger = logging.getLogger()
            if debug == 3:
                logger.setLevel(pantv.DEBUG3)
            elif debug == 2:
                logger.setLevel(pantv.DEBUG2)
            elif debug == 1:
                logger.setLevel(pantv.DEBUG1)
            elif debug == 0:
                pass
            else:
                raise RuntimeError('PANTV_DEBUG level must be 0-3')
            log_format = '%(message)s'
            handler = logging.StreamHandler()
            formatter = logging.Formatter(log_format)
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        if x is None or debug == 0:
            # XXX suppress for LibreSSL systems
            import warnings
            warnings.filterwarnings(
                'ignore',
                message=r'^urllib3 v2 only supports OpenSSL 1\.1\.1\+',
                category=Warning,
                module='urllib3'
            )

        return pantv.ThreatVaultApi(**kwargs)


class Mixin(_MixinShared):
    def setUp(self):
        self.api = self.tvapi()

    def tearDown(self):
        self.api.session.close()


class AioMixin(_MixinShared):
    async def asyncSetUp(self):
        self.api = self.tvapi()

    async def asyncTearDown(self):
        await self.api.session.close()
        # XXX try to avoid "ResourceWarning: unclosed ..."
        await asyncio.sleep(0.1)
