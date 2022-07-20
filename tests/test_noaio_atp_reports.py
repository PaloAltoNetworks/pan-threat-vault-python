import unittest

from . import mixin


class ThreatVaultApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.atp_reports()
        self.assertEqual(resp.status_code, 400)

    def test_02(self):
        x = ['#']
        resp = self.api.atp_reports(id=x)
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'id: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_03(self):
        x = ['abcd0123']
        resp = self.api.atp_reports(id=x)
        self.assertEqual(resp.status_code, 404)
        x = resp.json()
        self.assertFalse(x['success'])

    def test_04(self):
        x = 'x-invalid-json'
        resp = self.api.atp_reports(id=x)
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'Valid JSON object is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_05(self):
        x = '{"id": ["abcd0123"]}'
        resp = self.api.atp_reports(id=x)
        self.assertEqual(resp.status_code, 404)
        x = resp.json()
        self.assertFalse(x['success'])
