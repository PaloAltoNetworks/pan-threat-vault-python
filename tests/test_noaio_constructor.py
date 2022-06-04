import asyncio
import unittest

import pantv


class ThreatVaultApiTest(unittest.TestCase):
    def tearDown(self):
        if hasattr(self, 'api') and hasattr(self.api, 'session'):
            self.api.session.close()

    def test_00(self):
        self.assertRaises(RuntimeError, asyncio.get_running_loop)

    def test_01(self):
        kwargs = {}
        with self.assertRaises(pantv.ArgsError) as e:
            self.api = pantv.ThreatVaultApi(**kwargs)
        self.assertEqual(str(e.exception), 'api_key required')

    def test_02(self):
        kwargs = {
            'api_key': 'x',
            'api_version': 'x',
        }
        with self.assertRaises(pantv.ArgsError) as e:
            self.api = pantv.ThreatVaultApi(**kwargs)
        self.assertRegex(str(e.exception),
                         '^Invalid api_version')
