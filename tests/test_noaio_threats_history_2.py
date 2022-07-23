import unittest

from . import mixin


class ThreatVaultApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.threats_history()
#        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.status_code, 500)
        x = resp.json()
        msg = 'id: This field is required. type: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_02(self):
        resp = self.api.threats_history(type='wildfire')
#        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.status_code, 500)
        x = resp.json()
        msg = 'id: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_03(self):
        resp = self.api.threats_history(id='100')
#        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.status_code, 500)
        x = resp.json()
        msg = 'type: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_04(self):
        resp = self.api.threats_history(type='x-invalid')
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'type: Value is invalid.'  # XXX id required
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_05(self):
        resp = self.api.threats_history(id='x-invalid')
#        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.status_code, 500)
        x = resp.json()
        msg = 'id: A valid integer is required. type: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_06(self):
        qs = {'order': 'x-invalid'}
        resp = self.api.threats_history(type='antivirus',
                                        id=100,
                                        query_string=qs)
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'order: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_07(self):
        resp = self.api.threats_history(type='antivirus',
                                        id=100)
        self.assertEqual(resp.status_code, 404)
        x = resp.json()
        self.assertEqual(x['message'], 'Not Found')
        self.assertFalse(x['success'])
