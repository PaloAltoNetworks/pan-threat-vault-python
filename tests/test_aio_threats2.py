import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.threats()
        self.assertEqual(resp.status, 400)

    async def test_02(self):
        resp = await self.api.threats(id=0)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'id: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_03(self):
        resp = await self.api.threats(id=0.5)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'id: A valid integer is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_04(self):
        resp = await self.api.threats(id=-1)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'id: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_05(self):
        resp = await self.api.threats(signatureType='x')
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'type: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_06(self):
        # length min 3
        resp = await self.api.threats(name='aa')
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'name: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_07(self):
        # length max 255
        resp = await self.api.threats(name='x' * 256)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'name: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_08(self):
        # length max 255
        resp = await self.api.threats(name='x' * 255)
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_09(self):
        resp = await self.api.threats(cve='CVE-XXXX')
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'cve: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])
