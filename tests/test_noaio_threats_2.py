import unittest

from . import mixin


class ThreatVaultApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.threats()
        self.assertEqual(resp.status_code, 400)

    def test_02(self):
        resp = self.api.threats(id=0)
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'id: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_03(self):
        resp = self.api.threats(id=0.5)
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'id: A valid integer is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_04(self):
        resp = self.api.threats(id=-1)
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'id: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_05(self):
        resp = self.api.threats(type='x')
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'type: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_06(self):
        # length min 3
        resp = self.api.threats(name='aa')
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'name: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_07(self):
        # length max 255
        resp = self.api.threats(name='x' * 256)
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'name: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_08(self):
        # length max 255
        resp = self.api.threats(name='x' * 255)
        self.assertEqual(resp.status_code, 404)
        x = resp.json()
        self.assertFalse(x['success'])

    def test_09(self):
        resp = self.api.threats(cve='CVE-XXXX')
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'cve: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])
