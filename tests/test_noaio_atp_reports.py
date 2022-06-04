import unittest

from . import mixin


class ThreatVaultApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.atp_reports()
#        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.status_code, 500)

    def test_02(self):
        x = 'x-invalid'
        resp = self.api.atp_reports(report_id=x)
#        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.status_code, 500)
        x = resp.json()
        self.assertFalse(x['success'])

    def test_03(self):
        x = ['#']
        resp = self.api.atp_reports(report_id=x)
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        self.assertEqual(x['message'],
                         "'report_id' is not alphanumeric")
        self.assertFalse(x['success'])

    def test_04(self):
        x = ['abcd0123']
        resp = self.api.atp_reports(report_id=x)
        self.assertEqual(resp.status_code, 404)
        x = resp.json()
        self.assertFalse(x['success'])

    def test_05(self):
        x = '{"id": ["abcd0123"]}'
        resp = self.api.atp_reports(report_id=x)
        self.assertEqual(resp.status_code, 404)
        x = resp.json()
        self.assertFalse(x['success'])
