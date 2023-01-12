import unittest

from . import mixin


class ThreatVaultApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        versions = [
            'latest',
            '8549-7323',
        ]

        for version in versions:
            resp = self.api.release_notes(type='content',
                                          version=version)
            self.assertEqual(resp.status_code, 200)
            x = resp.json()
            self.assertEqual(x['message'], 'Successful')
            self.assertTrue(x['success'])
            self.assertEqual(x['count'], 1)
            self.assertEqual(x['count'], len(x['data']))
            item = x['data'][0]
            if version != 'latest':
                self.assertEqual(item['content_version'], version)
