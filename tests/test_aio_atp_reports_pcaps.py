import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.atp_reports_pcaps()
#        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.status, 500)

    async def test_02(self):
        x = '#'
        resp = await self.api.atp_reports_pcaps(report_id=x)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'id: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_03(self):
        x = 'abcd0123'
        resp = await self.api.atp_reports_pcaps(report_id=x)
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertFalse(x['success'])
