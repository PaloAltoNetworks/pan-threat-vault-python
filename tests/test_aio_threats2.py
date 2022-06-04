import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.threats()
        self.assertEqual(resp.status, 400)

    async def test_02(self):
        resp = await self.api.threats(id=0)
        self.assertEqual(resp.status, 404)

    async def test_03(self):
        resp = await self.api.threats(id=0.5)
#        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.status, 500)

    async def test_04(self):
        resp = await self.api.threats(id=-1)
#        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.status, 404)

    async def test_05(self):
        resp = await self.api.threats(signatureType='x')
#        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.status, 404)

    async def test_06(self):
        # length min 3
        resp = await self.api.threats(name='aa')
        self.assertEqual(resp.status, 400)

    async def test_07(self):
        # length max 255
        resp = await self.api.threats(name='x' * 256)
        self.assertEqual(resp.status, 400)

    async def test_08(self):
        # length max 255
        resp = await self.api.threats(name='x' * 255)
        self.assertEqual(resp.status, 404)

    async def test_09(self):
        # length min 3?
        resp = await self.api.threats(cve='CVE-XXXX')
        self.assertEqual(resp.status, 400)
