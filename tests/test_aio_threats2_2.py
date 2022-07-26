import hashlib
import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.threats2()
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_02(self):
        arg = 'x-invalid'
        resp = await self.api.threats2(type=arg)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_03(self):
        resp = await self.api.threats2(id=[])
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_04(self):
        arg = 'x-invalid'
        resp = await self.api.threats2(sha256=[arg])
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_05(self):
        arg = 'x-invalid'
        resp = await self.api.threats2(md5=[arg])
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_06(self):
        arg = ' '
        resp = await self.api.threats2(name=[arg])
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_07(self):
        arg = '100'
        resp = await self.api.threats2(id=[arg])
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_08(self):
        m = hashlib.sha256(b'threat vault')
        arg = m.hexdigest()
        resp = await self.api.threats2(sha256=[arg])
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_09(self):
        # max query size 100
        n = 1
        args = []
        while True:
            m = hashlib.sha256(b'threat vault' * n)
            args.append(m.hexdigest())
            if n > 100:
                break
            n += 1

        resp = await self.api.threats2(sha256=args)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertFalse(x['success'])
