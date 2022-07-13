import unittest

from . import mixin


class ThreatVaultApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.release_notes()
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'type: This field is required. version: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_02(self):
        resp = self.api.release_notes(noteType='x')
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'type: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_03(self):
        resp = self.api.release_notes(version='x')
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'version: Value is invalid.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_04(self):
        resp = self.api.release_notes(noteType='content')
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = 'version: This field is required.'
        self.assertEqual(x['message'], msg)
        self.assertFalse(x['success'])

    def test_05(self):
        resp = self.api.release_notes(noteType='content',
                                      version='0001')
        self.assertEqual(resp.status_code, 404)
        x = resp.json()
        self.assertRegex(x['message'], 'Not found')
        self.assertFalse(x['success'])
