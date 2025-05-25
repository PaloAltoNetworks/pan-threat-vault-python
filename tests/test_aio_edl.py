import random
import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        ips = [
            '0.0.0.0',
            '2001:db8:0:0:0:0:0:1',
        ]
        for ip in ips:
            resp = await self.api.edl(ipaddr=ip)
            self.assertEqual(resp.status, 404)
            x = await resp.json()
            self.assertEqual(x['message'], 'Not Found')
            self.assertFalse(x['success'])

    async def test_02(self):
        edls = [
            'panw-known-ip-list',
            'panw-highrisk-ip-list',
            'panw-torexit-ip-list',
            #  'panw-bulletproof-ip-list',
        ]
        for edl in edls:
            resp = await self.api.edl(name=edl,
                                      version='latest',
                                      limit=10)
            self.assertEqual(resp.status, 200)
            x = await resp.json()
            self.assertEqual(x['message'], 'Successful')
            self.assertTrue(x['success'])
            self.assertEqual(len(x['data']), 10, msg=edl)

            resp = await self.api.edl(name=edl,
                                      version='latest',
                                      listformat='array',
                                      limit=10)
            self.assertEqual(resp.status, 200)
            x = await resp.json()
            self.assertEqual(x['message'], 'Successful')
            self.assertTrue(x['success'])
            self.assertEqual(len(x['data']['ipaddr']), 10, msg=edl)

    async def test_03(self):
        edl = 'panw-highrisk-ip-list'
        resp = await self.api.edl(name=edl,
                                  version='latest',
                                  limit=1)
        self.assertEqual(resp.status, 200)
        x = await resp.json()

        version = x['data'][0]['version']
        ipaddr = x['data'][0]['ipaddr']

        resp = await self.api.edl(ipaddr=ipaddr)
        self.assertEqual(resp.status, 200)
        x = await resp.json()

        if x['count'] < 1000:
            self.assertEqual(x['count'], len(x['data']))

        for data in x['data']:
            self.assertIn('ipaddr', data)
            self.assertIn('name', data)
            self.assertIn('version', data)
            self.assertEqual(data['ipaddr'], ipaddr)

        resp = await self.api.edl(ipaddr=ipaddr,
                                  version=version)
        self.assertEqual(resp.status, 200)

    async def test_04(self):
        edl = 'panw-known-ip-list'
        resp = await self.api.edl(name=edl,
                                  version='latest',
                                  limit=1)
        self.assertEqual(resp.status, 200)
        x = await resp.json()

        count = x['count']
        version = x['data'][0]['version']

        total = 0
        async for result, x in self.api.edl_all(name=edl,
                                                version=version):
            if not result:
                self.assertTrue(result, '%s %s' % (x.status, x.reason))
            self.assertTrue(isinstance(x, dict))
            total += 1
        self.assertEqual(count, total)

        total = 0
        limit = random.randrange(501, 999)

        async for result, x in self.api.edl_all(name=edl,
                                                version=version,
                                                limit=limit,
                                                listformat='array'):
            if not result:
                self.assertTrue(result, '%s %s' % (x.status, x.reason))
            self.assertTrue(isinstance(x, str))
            total += 1
        self.assertEqual(count, total)
