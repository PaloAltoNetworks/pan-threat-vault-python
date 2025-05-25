import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        args = [
            (None, "'name' or 'ipaddr' should be provided"),
            ('', "'name' or 'ipaddr' should be provided "
             "together with 'version'"),
            (' ', 'name: This field may not be blank.'),
            (' ' * 1000, 'name: This field may not be blank.'),
            ('\t' * 1000, 'name: This field may not be blank.'),
            ('\n' * 1000, 'name: This field may not be blank.'),
            ('\0' * 1000, 'name: This field may not be blank.'),
            (';' * 1000,),
            ('&' * 1000,),
            (100,),
            (100.5,),
            ('xxx-invalid',),
            ('xxx invalid',),
        ]
        for arg in args:
            resp = await self.api.edl(name=arg[0])
            self.assertEqual(resp.status, 400)
            x = await resp.json()
            msg = arg[1] if len(arg) > 1 else 'name: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_02(self):
        arg = 'x-invalid'
        resp = await self.api.edl(ipaddr=arg)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'ipaddr: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_03(self):
        arg = 'x-invalid'
        resp = await self.api.edl(version=arg)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'version: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_04(self):
        arg = 'x-invalid'
        resp = await self.api.edl(listformat=arg)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = 'listformat: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_05(self):
        arg = 'latest'
        resp = await self.api.edl(version=arg)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = "'name' or 'ipaddr' should be provided together with 'version'"
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_06(self):
        arg = 'array'
        resp = await self.api.edl(listformat=arg)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = "'name' or 'ipaddr' should be provided"
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    async def test_07(self):
        arg = 'array'
        resp = await self.api.edl(ipaddr='1.1.1.1',
                                  listformat=arg)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = "'listformat' can be used only with 'name' and 'version'"
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])
