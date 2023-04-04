import datetime
import random
import unittest

from . import mixin


class ThreatVaultApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    args = []

    async def test_00(self):
        def check_retention(type_, release):
            # retention: https://pan.dev/threat-vault/api/threatshistory/
            wildfire_retention = datetime.timedelta(days=30)
            antivirus_retention = datetime.timedelta(days=365)

            t = release['last_release_time'][0:10]
            lrt = datetime.date.fromisoformat(t)
            now = datetime.date.today()

            if type_ == 'wildfire' and now - wildfire_retention < lrt:
                return True
            if type_ == 'antivirus' and now - antivirus_retention < lrt:
                return True

            return False

        orders = [None, 'asc', 'desc']

        now = datetime.date.today()
        jan1 = datetime.date(year=now.year, month=1, day=1)
        min_days = datetime.timedelta(days=90)
        if jan1 + min_days < now:
            cve = 'CVE-%d' % now.year
        else:
            cve = 'CVE-%d' % (now.year - 1)

        resp = await self.api.threats(type='antivirus',
                                      cve=cve)
        self.assertEqual(resp.status, 200)
        data = await resp.json()

        total_tests = 0
        max_tests = 20

        for x in data['data']['antivirus']:
            if x['status'] != 'active':
                continue
            for type_ in ['antivirus', 'wildfire']:
                if (type_ in x['release'] and
                   check_retention(type_, x['release'][type_])):
                    order = orders[random.randrange(0, len(orders))]
                    ThreatVaultApiTest.args.append((type_, x['id'], order))

                    total_tests += 1
                    if total_tests >= max_tests:
                        return

    async def test_01(self):
        if not ThreatVaultApiTest.args:
            self.skipTest('no tests')

        for type_, id_, order in ThreatVaultApiTest.args:
            kwargs = {
                'type': type_,
                'id': id_,
            }
            if order:
                kwargs['order'] = order

            resp = await self.api.threats_history(**kwargs)
            self.assertEqual(resp.status, 200,
                             kwargs)
            x = await resp.json()
            self.assertEqual(x['message'], 'Successful')
            self.assertTrue(x['success'])
            self.assertGreater(x['count'], 1)
            if x['count'] <= 1000:
                self.assertEqual(x['count'], len(x['data']), kwargs)
            item = x['data'][0]
            for k in ['build_time', 'release_time', 'version']:
                self.assertIn(k, item)

            order_key = 'version'
            last = x['data'][0]
            for item in x['data'][1:]:
                if order is None or order == 'asc':
                    self.assertGreaterEqual(item[order_key],
                                            last[order_key],
                                            kwargs)
                elif order == 'desc':
                    self.assertLessEqual(item[order_key],
                                         last[order_key],
                                         kwargs)
                last = item

    async def test_02(self):
        if not ThreatVaultApiTest.args:
            self.skipTest('no tests')

        for type_, id_, _ in ThreatVaultApiTest.args:
            kwargs = {
                'type': type_,
                'id': id_,
                'offset': 0,
                'limit': 1,
            }

            resp = await self.api.threats_history(**kwargs)
            self.assertEqual(resp.status, 200,
                             kwargs)
            x = await resp.json()
            self.assertEqual(x['message'], 'Successful')
            self.assertTrue(x['success'])
            self.assertEqual(len(x['data']), 1)
