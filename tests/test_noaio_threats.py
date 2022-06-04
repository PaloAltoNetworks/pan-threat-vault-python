import unittest

from . import mixin


class ThreatVaultApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.threats(id=30000)
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])
        self.assertEqual(x['count'], 1)
        self.assertEqual(x['count'], len(x['data']['vulnerability']))
        item = x['data']['vulnerability'][0]
        self.assertEqual(item['id'], 30000)
        self.assertEqual(item['cve'][0], 'CVE-2018-15984')

    def test_02(self):
        x = {'cve': 'CVE-2018-15984'}
        resp = self.api.threats(query_string=x)
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])
        self.assertEqual(x['count'], 1)
        item = x['data']['vulnerability'][0]
        self.assertEqual(item['id'], 30000)

    def test_03(self):
        x = 'Adobe Reader Memory Corruption Vulnerability'
        resp = self.api.threats(name=x)
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])
        self.assertGreater(x['count'], 0)

    def test_04(self):
        x = {
            'fromReleaseDate': '2022-01-01',
            'toReleaseDate': '2022-01-31',
        }
        resp = self.api.threats(query_string=x)
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])
        self.assertGreater(x['count'], 0)

    def test_05(self):
        resp = self.api.threats(signatureType='ips')
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])

        threats = [x['data'][k] for k in x['data']]
        total = 0
        for threat in threats:
            total += len(threat)
        self.assertEqual(total, 10000)

    def test_06(self):
        resp = self.api.threats(signatureType='ips',
                                limit=100)
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertEqual(x['message'], 'Successful')
        self.assertTrue(x['success'])

        threats = [x['data'][k] for k in x['data']]
        total = 0
        for threat in threats:
            total += len(threat)
        self.assertEqual(total, 100)

    def test_07(self):
        resp = self.api.threats(signatureType='ips',
                                limit=1)
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        count = x['count']

        total = 0
        for result, x in self.api.threats_all(signatureType='ips'):
            if not result:
                self.assertTrue(result, '%s %s' % (x.status_code, x.reason))
            total += 1
            self.assertGreater(x['id'], 0)
        self.assertEqual(count, total)
