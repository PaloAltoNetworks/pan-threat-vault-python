pan-threat-vault-python Tests
=============================

``pan-threat-vault-python`` tests use the Python
`unit testing framework
<https://docs.python.org/3/library/unittest.html>`_.

An API key is required to run the tests.

Test Prerequisites
------------------

Place the API key in a JSON file with the following object format:
::

  $ cat ~/.keys/keys-tv.json
  {
      "api-key": "******"
  }

.. note:: Ensure the key file has strict file permissions (read/write
          for the owner and not accessible by group or other).

Then export the ``PANTV_KEYS`` environment variable with the path to the
key file:
::

  $ export PANTV_KEYS=~/.keys/keys-tv.json

Run Tests
---------

To run all tests from the top-level directory:
::

  $ python3 -m unittest discover -v -s tests -t .

To run a specific test from the top-level directory:
::

  $ python3 -m unittest discover -v -s tests -t . -p test_noaio_constructor.py

To run all tests from the ``tests/`` directory:
::

  $ python3 -m unittest discover -v -s . -t ..

To run a specific test from the ``tests/`` directory:
::

  $ python3 -m unittest discover -v -s . -t .. -p test_noaio_constructor.py

asyncio and Normal Methods
--------------------------

Tests for the asyncio methods use the ``test_aio_`` prefix and for the
normal methods use the ``test_noaio_`` prefix.  asyncio method test
cases use the ``IsolatedAsyncioTestCase`` base class and the normal
methods use the ``TestCase`` base class.

Optional Tests
--------------

Tests can exist that are optionally executed based on environment
variables being set and other pre-conditions.  These will appear as
*skipped* when not executed.

``test_noaio_threats_content_sync.py``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``test_noaio_threats_content_sync.py`` is a test that will compare all
threat IDs of type **vulnerability** from the ``threats_all()`` API
method to the threat IDs from the exported threat content on a PAN-OS
firewall.

The test requires a CSV export of vulnerability protection threats
from the PAN-OS WebUI:

 OBJECTS->Security Profiles->Vulnerability Protection->
 Vulnerability Protection Profile->Exceptions->
 Show all signatures->PDF/CSV->Export

The path to the exported file is specified in the ``PANTV_VULN_EXPORT``
environment variable.

The PAN-OS version of the source firewall can be specified in the
``PANTV_PANOS_VERSION`` environment variable; this is used to ignore
threats from the API which do not apply to the firewall using the
**min_version** and **max_version** of the threat.

::

  $ PANTV_VULN_EXPORT=~/Downloads/export_objects_security_profiles_vulnerability-protection_01062023_174738pst.csv python3 -m unittest discover -v -s . -t .. -p test_noaio_threats_content_sync.py
  test_01 (tests.test_noaio_threats_content_sync.ThreatVaultApiTest) ... FAIL

  ======================================================================
  FAIL: test_01 (tests.test_noaio_threats_content_sync.ThreatVaultApiTest)
  ----------------------------------------------------------------------
  Traceback (most recent call last):
    File "/home/ksteves/git/pan-threat-vault-python/tests/test_noaio_threats_content_sync.py", line 78, in test_01
      self.assertEqual(len(delta), 0, msg)
  AssertionError: 16 != 0 : Unified diff of threat IDs:
  --- Threat Vault API
  +++ PAN-OS content
  @@ -12407,7 +12407,6 @@
   56269
   56270
   56271
  -56272
   56273
   56274
   56275
  @@ -18508,5 +18507,3 @@
   93319
   93320
   93321
  -99950
  -99951

  ----------------------------------------------------------------------
  Ran 1 test in 11.195s

  FAILED (failures=1)

The example content is from a 10.2 firewall and from the unified diff
we can see it does not contain 3 threat IDs contained in the API set
of threat IDs.  The first threat has a maximum version of 9.1, and the
last two threats have a minimum version of 11.0.  The PAN-OS version
of the content source firewall can be specified to skip these and as a
result the test passes:

::

  $ PANTV_PANOS_VERSION=10.2 PANTV_VULN_EXPORT=~/Downloads/export_objects_security_profiles_vulnerability-protection_01062023_174738pst.csv python3 -m unittest discover -v -s . -t .. -p test_noaio_threats_content_sync.py
  test_01 (tests.test_noaio_threats_content_sync.ThreatVaultApiTest) ... ok

  ----------------------------------------------------------------------
  Ran 1 test in 11.724s

  OK
