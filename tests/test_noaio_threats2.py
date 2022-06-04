import unittest

from . import mixin


class ThreatVaultApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.threats()
        self.assertEqual(resp.status_code, 400)

    def test_02(self):
        resp = self.api.threats(id=0)
        self.assertEqual(resp.status_code, 404)

    def test_03(self):
        resp = self.api.threats(id=0.5)
#        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.status_code, 500)

    def test_04(self):
        resp = self.api.threats(id=-1)
#        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.status_code, 404)

    def test_05(self):
        resp = self.api.threats(signatureType='x')
#        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.status_code, 404)

    def test_06(self):
        # length min 3
        resp = self.api.threats(name='aa')
        self.assertEqual(resp.status_code, 400)

    def test_07(self):
        # length max 255
        resp = self.api.threats(name='x' * 256)
        self.assertEqual(resp.status_code, 400)

    def test_08(self):
        # length max 255
        resp = self.api.threats(name='x' * 255)
        self.assertEqual(resp.status_code, 404)

    def test_09(self):
        # length min 3?
        resp = self.api.threats(cve='CVE-XXXX')
        self.assertEqual(resp.status_code, 400)
