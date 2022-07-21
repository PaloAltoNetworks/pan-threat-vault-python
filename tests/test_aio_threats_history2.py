import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.threats_history()
#        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.status, 500)
        x = await resp.json()
        msg = 'id: This field is required. type: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_02(self):
        resp = await self.api.threats_history(type='wildfire')
#        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.status, 500)
        x = await resp.json()
        msg = 'id: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_03(self):
        resp = await self.api.threats_history(id='100')
#        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.status, 500)
        x = await resp.json()
        msg = 'type: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_04(self):
        resp = await self.api.threats_history(type='x-invalid')
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'type: Value is invalid.'  # XXX id required
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_05(self):
        resp = await self.api.threats_history(id='x-invalid')
#        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.status, 500)
        x = await resp.json()
        msg = 'id: A valid integer is required. type: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_06(self):
        qs = {'order': 'x-invalid'}
        resp = await self.api.threats_history(type='antivirus',
                                              id=100,
                                              query_string=qs)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'order: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_07(self):
        resp = await self.api.threats_history(type='antivirus',
                                              id=100)
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertEqual(x['message'], 'Not Found')
        self.assertFalse(x['success'])
