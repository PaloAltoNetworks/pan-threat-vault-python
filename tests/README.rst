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
