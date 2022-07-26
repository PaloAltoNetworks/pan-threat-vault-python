import hashlib
import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.threats2(id=[30000])
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])
        self.assertEqual(x['count'], 1)
        self.assertEqual(x['count'], len(x['data']['vulnerability']))
        item = x['data']['vulnerability'][0]
        self.assertEqual(item['id'], 30000)
        self.assertEqual(item['cve'][0], 'CVE-2018-15984')

    async def test_02(self):
        resp = await self.api.threats2(id=['30000', '19999'])
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])
        self.assertEqual(x['count'], 2)
        item = x['data']['vulnerability'][0]
        self.assertEqual(item['id'], 30000)
        self.assertEqual(item['cve'][0], 'CVE-2018-15984')
        item = x['data']['spyware'][0]
        self.assertEqual(item['id'], 19999)
        self.assertEqual(item['name'], 'Bot: Backdoor_Win32_Agobot_pnd_pnj')

    async def test_03(self):
        resp = await self.api.threats2(type='vulnerability',
                                       id=[30000, 19999])
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])
        self.assertEqual(x['count'], 1)
        item = x['data']['vulnerability'][0]
        self.assertEqual(item['id'], 30000)
        self.assertEqual(item['cve'][0], 'CVE-2018-15984')

    async def test_04(self):
        data1 = '''{
  "type": "vulnerability",
  "id": [30000, 19999]
}'''
        data2 = {
            'type': 'vulnerability',
            'id': [30000, 19999],
        }

        for data in data1, data2:
            resp = await self.api.threats2(data=data)
            self.assertEqual(resp.status, 200)
            x = await resp.json()
            self.assertEqual(x['message'], 'Successful')
            self.assertTrue(x['success'])
            self.assertEqual(x['count'], 1)
            item = x['data']['vulnerability'][0]
            self.assertEqual(item['id'], 30000)
            self.assertEqual(item['cve'][0], 'CVE-2018-15984')

    async def test_05(self):
        id_ = '280392504'
        resp = await self.api.threats2(id=[id_])
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])
        self.assertEqual(x['count'], 1)
        item = x['data']['antivirus'][0]
        self.assertEqual(item['id'], id_)
        self.assertIn('related_sha256_hashes', item)
        resp = await self.api.threats2(sha256=item['related_sha256_hashes'])
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])
        self.assertEqual(x['count'], len(item['related_sha256_hashes']))

    async def test_06(self):
        # max query size 100
        n = 1
        args = []
        while True:
            m = hashlib.sha256(b'threat vault' * n)
            args.append(m.hexdigest())
            if n > 99:
                break
            n += 1

        resp = await self.api.threats2(sha256=args)
        self.assertEqual(resp.status, 404)
        x = await resp.json()
        self.assertFalse(x['success'])
