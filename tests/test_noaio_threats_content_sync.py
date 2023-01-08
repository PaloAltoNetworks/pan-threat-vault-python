import csv
import difflib
import os
import unittest

from . import mixin


class ThreatVaultApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        def version2int(version):
            if not version:
                return 0xffffff
            x = version.split('.')
            # XXX just allow major.feature[.maintenance] e.g, no hotfix etc.
            if len(x) not in [2, 3]:
                self.fail('Invalid PAN-OS version: %s' % version)
            version = int(x[2]) if len(x) > 2 else 0
            version = int(x[0]) << 16 | int(x[1]) << 8 | version
            return version

        # CSV export from PAN-OS WebUI:
        #   OBJECTS->Security Profiles->Vulnerability Protection->
        #   Vulnerability Protection Profile->Exceptions->
        #   Show all signatures->PDF/CSV->Export
        path = os.getenv('PANTV_VULN_EXPORT')
        if path is None:
            self.skipTest('PANTV_VULN_EXPORT unset')

        try:
            csvfile = open(path, 'r', newline='')
            csvreader = csv.reader(csvfile)
            panos_content = [x[0] for x in csvreader if x[0] != 'ID']
        except IOError as e:
            self.fail('open: %s: %s' % (path, e))
        else:
            csvfile.close()

        panos_content = sorted(panos_content)

        panos_version_str = os.getenv('PANTV_PANOS_VERSION')
        panos_version = version2int(panos_version_str)

        tv_vulns = []
        for result, x in self.api.threats_all(type='vulnerability'):
            if not result:
                self.assertTrue(result, '%s %s' % (x.status, x.reason))
            if x['status'] == 'disabled':
                continue
            # Unsupported PAN-OS versions
            if x['max_version'] in ['8.1.0', '9.0.0', '10.0']:
                continue
            if panos_version_str:
                min_version = version2int(x['min_version'])
                if panos_version < min_version:
                    continue
                max_version = version2int(x['max_version'])
                if panos_version > max_version:
                    continue

            tv_vulns.append(x['id'])

        tv_vulns = sorted(tv_vulns)

        if panos_version_str:
            panos = 'PAN-OS %s content' % panos_version_str
        else:
            panos = 'PAN-OS content'
        tv = 'Threat Vault API'

        diff = difflib.unified_diff(tv_vulns, panos_content,
                                    lineterm='',
                                    fromfile=tv,
                                    tofile=panos)
        delta = list(diff)
        if delta:
            msg = 'Unified diff of threat IDs:\n' + '\n'.join(delta)
            self.assertEqual(len(delta), 0, msg)
