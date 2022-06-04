import asyncio
import json
import logging
import os

import pantv


class _MixinShared:
    def tvapi(self):
        path = os.getenv('PANTV_KEYS')
        if path is None:
            raise RuntimeError('no PANTV_KEYS in environment')
        with open(path, 'r') as f:
            x = json.load(f)
        kwargs = {
            'api_key': x['api-key'],
            'verify': x['verify'],
        }

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
