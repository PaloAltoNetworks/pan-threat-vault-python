import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.atp_reports()
        self.assertEqual(resp.status, 400)

    async def test_02(self):
        x = ['#']
        resp = await self.api.atp_reports(id=x)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'id: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_03(self):
        x = ['abcd0123']
        resp = await self.api.atp_reports(id=x)
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_04(self):
        x = 'x-not-list'
        resp = await self.api.atp_reports(id=x)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'id: Expected a list of items but got type "str".'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_05(self):
        x = '{"id": ["abcd0123"]}'
        resp = await self.api.atp_reports(data=x)
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertFalse(x['success'])
