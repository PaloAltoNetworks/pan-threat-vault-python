import unittest

from . import mixin


class ThreatVaultApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.atp_reports_pcaps()
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'id: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_02(self):
        x = '#'
        resp = self.api.atp_reports_pcaps(id=x)
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'id: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_03(self):
        x = 'abcd0123'
        resp = self.api.atp_reports_pcaps(id=x)
        self.assertEqual(resp.status_code, 404)
        x = resp.json()
        self.assertFalse(x['success'])
