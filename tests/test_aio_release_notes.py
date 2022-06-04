import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        version = '8549-7323'
        resp = await self.api.release_notes(noteType='content',
                                            version=version)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])
        self.assertEqual(x['count'], 1)
        self.assertEqual(x['count'], len(x['data']))
        item = x['data'][0]
        self.assertEqual(item['content_version'], version)
