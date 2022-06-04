import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.atp_reports()
#        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.status, 500)

    async def test_02(self):
        x = 'x-invalid'
        resp = await self.api.atp_reports(report_id=x)
#        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.status, 500)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_03(self):
        x = ['#']
        resp = await self.api.atp_reports(report_id=x)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertEqual(x['message'],
                         "'report_id' is not alphanumeric")
        self.assertFalse(x['success'])

    async def test_04(self):
        x = ['abcd0123']
        resp = await self.api.atp_reports(report_id=x)
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertFalse(x['success'])

    async def test_05(self):
        x = '{"id": ["abcd0123"]}'
        resp = await self.api.atp_reports(report_id=x)
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertFalse(x['success'])
