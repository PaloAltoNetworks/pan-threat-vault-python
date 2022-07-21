import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    args = [
        ('antivirus', '347277975', None),
        ('wildfire', '518813087', 'asc'),
        ('antivirus', '518813087', 'desc'),
    ]

    async def test_01(self):
        for type_, id_, order in ThreatVaultApiTest.args:
            kwargs = {
                'type': type_,
                'id': id_,
            }
            if order:
                kwargs['order'] = order

            resp = await self.api.threats_history(**kwargs)
            self.assertEqual(resp.status, 200)
            x = await resp.json()
            self.assertEqual(x['message'], 'Successful')
            self.assertTrue(x['success'])
            self.assertGreater(x['count'], 1)
            if x['count'] <= 10000:
                self.assertEqual(x['count'], len(x['data']))
            item = x['data'][0]
            for k in ['build_time', 'release_time', 'version']:
                self.assertIn(k, item)

            order_key = 'version'
            last = x['data'][0]
            for item in x['data'][1:]:
                if order is None or order == 'asc':
                    self.assertGreaterEqual(item[order_key],
                                            last[order_key])
                elif order == 'desc':
                    self.assertLessEqual(item[order_key],
                                         last[order_key])
                last = item

    async def test_02(self):
        for type_, id_, _ in ThreatVaultApiTest.args:
            kwargs = {
                'type': type_,
                'id': id_,
                'offset': 0,
                'limit': 1,
            }

            resp = await self.api.threats_history(**kwargs)
            self.assertEqual(resp.status, 200)
            x = await resp.json()
            self.assertEqual(x['message'], 'Successful')
            self.assertTrue(x['success'])
            self.assertEqual(len(x['data']), 1)
