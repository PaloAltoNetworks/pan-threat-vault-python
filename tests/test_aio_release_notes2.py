import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.release_notes()
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertEqual(x['message'],
                         'Please provide a valid parameter to query')
        self.assertFalse(x['success'])

    async def test_02(self):
        resp = await self.api.release_notes(noteType='x')
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertEqual(x['message'],
                         "'type' is invalid")
        self.assertFalse(x['success'])

    async def test_03(self):
        resp = await self.api.release_notes(version='x')
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertEqual(x['message'],
                         "'version' is invalid")
        self.assertFalse(x['success'])

    async def test_04(self):
        resp = await self.api.release_notes(noteType='content')
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        self.assertRegex(x['message'],
                         "^'type' and 'version' should be provided together "
                         "without other parameters")
        self.assertFalse(x['success'])

    async def test_05(self):
        resp = await self.api.release_notes(noteType='content',
                                            version='0001')
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertRegex(x['message'], 'Not found')
        self.assertFalse(x['success'])
