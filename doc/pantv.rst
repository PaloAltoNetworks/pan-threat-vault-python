..
 Copyright (c) 2022 Palo Alto Networks, Inc.

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.

 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

=====
pantv
=====

-----------------------------------------------------------
Python interface to the Palo Alto Networks Threat Vault API
-----------------------------------------------------------

NAME
====

 pantv - Python interface to the Palo Alto Networks Threat Vault
 API

SYNOPSIS
========
::

 import asyncio
 import json
 import sys
 
 import pantv


 async def tvapi():
     path = '/etc/tv/keys/keys-acmecorp.json'
     try:
         with open(path, 'r') as f:
             args = json.load(f)
     except (IOError, ValueError) as e:
         print('%s: %s' % (path, e), file=sys.stderr)
         sys.exit(1)

     kwargs = {}
     for x in args:
         kwargs[x.replace('-', '_')] = args[x]

     try:
         async with pantv.ThreatVaultApi(**kwargs) as api:
             async for ok, x in api.threats_all(type='spyware'):
                 if ok:
                     print(x)
                 else:
                     raise pantv.ApiError('%s: %s' % (
                         x.status, x.reason))
     except (pantv.ApiError, pantv.ArgsError) as e:
         print('pantv.ThreatVaultApi:', e, file=sys.stderr)
         sys.exit(1)

 asyncio.run(tvapi())

DESCRIPTION
===========

 The pantv module defines the ThreatVaultApi class, which provides an
 interface to the Palo Alto Networks ThreatVault API.

 ThreatVaultApi provides an interface to the following Threat Vault
 API requests:

 +-----------------------------------+-----------------------+-------------------------------+-------------+
 | Request                           | ThreatVaultApi Method | API Resource Path             | HTTP Method |
 +===================================+=======================+===============================+=============+
 | | Get threat prevention metadata  | threats()             | /service/v1/threats           | GET         |
 | | information                     |                       |                               |             |
 +-----------------------------------+-----------------------+-------------------------------+-------------+
 | | Get multiple threats            | threats2()            | /service/v1/threats           | POST        |
 | | information (bulk query)        |                       |                               |             |
 +-----------------------------------+-----------------------+-------------------------------+-------------+
 | | Get threat content release and  | threats_history()     | /service/v1/threats/history   | GET         |
 | | version history                 |                       |                               |             |
 +-----------------------------------+-----------------------+-------------------------------+-------------+
 | | Get application and threat      | release_notes()       | /service/v1/release-notes     | GET         |
 | | release note information        |                       |                               |             |
 +-----------------------------------+-----------------------+-------------------------------+-------------+
 | | Get Advanced Threat Prevention  | atp_reports()         | /service/v1/atp/reports       | POST        |
 | | threat report                   |                       |                               |             |
 +-----------------------------------+-----------------------+-------------------------------+-------------+
 | | Get Advanced Threat Prevention  | atp_reports_pcaps()   | /service/v1/atp/reports/pcaps | GET         |
 | | threat pcap                     |                       |                               |             |
 +-----------------------------------+-----------------------+-------------------------------+-------------+

 Convenience methods implemented as generator functions are provided,
 which can be used to process all items when response paging can
 occur, and which can automatically retry requests when rate limiting
 occurs:

 =========================   ===================
 ThreatVaultApi Method       API Resource Path
 =========================   ===================
 threats_all()               /service/v1/threats
 =========================   ===================

 ThreatVaultApi methods are implemented as both functions, and
 coroutines for use with the
 `asyncio library <https://docs.python.org/3/library/asyncio.html>`_.
 The class constructor will determine if there is a running
 event loop, and return a class implemented with or without coroutine
 methods.  The
 `aiohttp module <https://docs.aiohttp.org/>`_
 is used for asyncio HTTP requests, and the
 `requests module <https://docs.python-requests.org>`_
 is used for synchronous HTTP requests.

pantv Constants
---------------

 **__version__**
  pantv package version string.

 **DEBUG1**, **DEBUG2**, **DEBUG3**
  Python ``logging`` module debug levels (see **Debugging and
  Logging** below).

 **DEFAULT_API_VERSION**
  Default API version.


pantv Constructor
-----------------

class pantv.ThreatVaultApi(\*, api_version=None, url=None, api_key=None, verify=None, timeout=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 **api_version**
  API version is a string in the form v\ **version** or
  **version** (e.g., *v2*).  The API version is used to determine
  the ThreatVaultApi class implementation to use.

  The default API version is **DEFAULT_API_VERSION**.

  **api_version** is verified and the class attribute is set to an
  instance of the ApiVersion class (defined below).

 **url**
  URL used in API requests.

  The default is "\https://api.threatvault.paloaltonetworks.com".

 **api_key**
  The ``x-api-key`` request header value used to authenticate API
  requests.  This is the *Threat Vault API* key available on the
  customer support portal under *Assets->API Key Management*.

 **verify**
  Specify if SSL server certificate verification is performed.

  **verify** can be:

   a boolean

   a path to a file containing CA certificates to be used for SSL
   server certificate verification

  The default is to verify the server certificate.

 **timeout**
  Set client HTTP timeout values in seconds.

  **timeout** can be:

   a single value to set the total timeout (aiohttp) or the
   **connect** and **read** timeouts to the same value (requests)

   a tuple of length 2 to set the **connect** and **read** timeouts to
   different values (aiohttp and requests)

  The
  `aiohttp library timeout <https://docs.aiohttp.org/en/stable/client_quickstart.html#timeouts>`_
  defaults to a total timeout of 300 seconds, meaning the operation
  must complete within 5 minutes.

  The
  `requests library timeout <https://docs.python-requests.org/en/latest/user/advanced/#timeouts>`_
  defaults to no timeout, meaning the timeouts are determined by the
  operating system TCP implementation.

pantv Exceptions
----------------

exception pantv.ApiError
~~~~~~~~~~~~~~~~~~~~~~~~

 Exception raised by the ThreatVaultApi class when an API error
 occurs.  This can include for example an unexpected response document
 (JSON) format.

 All other exceptions are a subclass of ApiError, which can be
 used to catch any exception raised by the ThreatVaultApi class.

exception pantv.ArgsError
~~~~~~~~~~~~~~~~~~~~~~~~~

 Exception raised by the ThreatVaultApi class when an argument error
 occurs.  This can include for example missing required arguments and
 invalid arguments.

 ArgsError is a subclass of ApiError.

 The string representation of an instance of raised exceptions will
 contain a user-friendly error message.

pantv.ThreatVaultApi Method Return Value
----------------------------------------

 ThreatVaultApi class methods return the response object returned by
 the HTTP client library used for the request, or for generator
 functions, a generator object.

 For normal functions:

  The coroutine class methods use the
  `aiohttp library <https://docs.aiohttp.org/>`_
  and return a
  `ClientResponse object <https://docs.aiohttp.org/en/stable/client_reference.html#aiohttp.ClientResponse>`_.

  The normal class methods use the
  `requests library <https://docs.python-requests.org/>`_
  and return a
  `Response object <https://docs.python-requests.org/en/latest/api/#requests.Response>`_.

pantv.ThreatVaultApi Methods
----------------------------

threats(\*, type=None, id=None, name=None, cve=None, fromReleaseDate=None, toReleaseDate=None, fromReleaseVersion=None, toReleaseVersion=None, releaseDate=None, releaseVersion=None,  sha256=None, md5=None, offset=None, limit=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``threats()`` method performs the ``/threats`` API request to get
 threat prevention metadata information.  ``threats()`` uses the HTTP
 GET method.

 **type**
  Signature type.

  Signature types are grouped into *IPS* types (Intrusion Prevention
  System) and *Virus* types:

  - *IPS*

   **ips** - all IPS signature metadata

   **fileformat** - file-format signature metadata

   **spyware** - anti-spyware signature metadata

   **vulnerability** - vulnerability protection signature metadata

  - *Virus*

   **antivirus** - anti-virus signature metadata

   **dns** - DNS signature metadata

   **rtdns** - real-time DNS detection entries metadata

   **spywarec2** - spyware C2 signature metadata
 
 **id**
  Threat signature ID number.

 **name**
  Threat signature name.

  For *IPS* signature types only, words in *name* are used to
  perform a fuzzy match on the signature name; *name* must be at least
  3 characters and only alphanumeric characters are allowed, other
  characters are ignored.

 **cve**
  CVE (Common Vulnerabilities and Exposures) ID.

  An exact or partial CVE ID can be specified:

  - partial CVE ID format: *CVE-YYYY*
  - exact CVE ID format: *CVE-YYYY-NNNN* (NNNN can be 4 or more digits)

  Examples:

  - CVE-2022
  - CVE-2022-21907

 **vendor** (*IPS* signature types only)
  Vendor ID.

  This is a vulnerability identifier which can be issued by a vendor
  to reference a security advisory or bulletin.

 **fromReleaseDate** (*IPS* signature types only)
  Start date for content release range.  Date format is *YYYY-MM-DD*.

 **toReleaseDate** (*IPS* signature types only)
  End date for content release range.  Date format is *YYYY-MM-DD*.

 **fromReleaseVersion** (*IPS* signature types only)
  Start version for content release range.

 **toReleaseVersion** (*IPS* signature types only)
  End version for content release range.

 **releaseDate** (*IPS* signature types only)
  Content release date.  Date format is *YYYY-MM-DD*.

 **releaseVersion** (*IPS* signature types only)
  Content release version.

 **sha256** (*Virus* signature types only)
  Sample SHA-256 hash value.

 **md5** (*Virus* signature types only)
  Sample MD5 hash value.

 **offset**
  Numeric offset used for response paging.  The default offset is 0.

 **limit**
  Numeric number of items to return in a response.  The default
  limit is 1,000 and the maximum is 1,000.

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution until the time specified in the ``x-minute-ratelimit-reset``
  response header, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

threats_all()
~~~~~~~~~~~~~

 The ``threats_all()`` method is a generator function which executes
 the ``threats()`` method until all items are returned.  Response
 paging is handled with the **offset** and **limit** specified, or a
 starting offset of 0 and limit of 1,000.  The arguments are the same
 as in the ``threats()`` method.

 The generator function yields a tuple containing:

  **status**: a boolean

   - True: the HTTP status code of the request is 200
   - False: the HTTP status code of the request is not 200

  **response**: a response item, or HTTP client library response object

   - **status** is True: an object in the response ``fileformat``,
     ``spyware`` or ``vulnerability`` list
   - **status** is False: HTTP client library response object

threats2(\*, type=None, id=None, name=None, sha256=None, md5=None, data=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``threats2()`` method performs the ``/threats`` API request to
 get threat prevention metadata information.  ``threats2()``
 uses the HTTP POST method.

 ``threats2()`` is used to perform bulk queries using multiple values
 for *id*, *name*, *sha256*, or *md5*.  Up to 100 query values can be
 specified.

 **type**
  Signature type.

  Signature types are grouped into *IPS* types (Intrusion Prevention
  System) and *Virus* types:

  - *IPS*

   **ips** - all IPS signature metadata

   **fileformat** - file-format signature metadata

   **spyware** - anti-spyware signature metadata

   **vulnerability** - vulnerability protection signature metadata

  - *Virus*

   **antivirus** - anti-virus signature metadata

   **dns** - DNS signature metadata

   **rtdns** - real-time DNS detection entries metadata

   **spywarec2** - spyware C2 signature metadata

 **id**
  List of threat signature ID numbers.

 **name**
  List of threat signature names.  A complete string comparison of
  name is performed; ``threats2()`` does not perform a fuzzy match on
  signature name like ``threats()``.

 **sha256**
  List of sample SHA-256 hash values.

 **md5**
  List of sample MD5 hash values.

 **data**
  JSON text to send in the body of the request.
  The text is a JSON object with key/values for *type* (optional)
  and one of: *id*, *name*, *sha256*, *md5*.

  **data** can be:

   a Python object that can be deserialized to JSON text

   a ``str``, ``bytes`` or ``bytearray`` type containing JSON text
 
 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution until the time specified in the ``x-minute-ratelimit-reset``
  response header, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

threats_history(\*, type=None, id=None, order=None, offset=None, limit=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``threats_history()`` method performs the ``/threats/history``
 API request to get threat content release and version history for a
 threat signature ID.

 **type**
  Signature type:

   **antivirus** - anti-virus release and version history

   **wildfire** - WildFire release and version history

 **id**
  Threat signature ID number.

 **order**
  Sort order for results:

   **asc** - ascending order (default)

   **desc** - descending order

  The ``version`` field is used to sort the results.

 **offset**
  Numeric offset used for response paging.  The default offset is 0.

 **limit**
  Numeric number of items to return in a response.  The default
  limit is 1,000 and the maximum is 1,000.

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution until the time specified in the ``x-minute-ratelimit-reset``
  response header, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

release_notes(\*, type=None, version=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``release_notes()`` method performs the ``/release-notes`` API
 request to get application and threat release note information.

 **type**
  Release note type:

   **content**

 **version**
  Content version.

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution until the time specified in the ``x-minute-ratelimit-reset``
  response header, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

atp_reports(\*, id=None, data=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``atp_reports()`` method performs the ``/atp/reports`` API
 request to get an Advanced Threat Prevention threat report.

 **id**
  List of Advanced Threat Prevention report IDs.  A report ID is a
  hexadecimal string.

 **data**
  JSON text to send in the body of the request.
  The text is a JSON object with key/values for *id*.

  **data** can be:

   a Python object that can be deserialized to JSON text

   a ``str``, ``bytes`` or ``bytearray`` type containing JSON text

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution until the time specified in the ``x-minute-ratelimit-reset``
  response header, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

atp_reports_pcaps(\*, id=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``atp_pcaps()`` method performs the ``/atp/reports/pcaps`` API
 request to get the packet capture file for an Advanced Threat
 Prevention threat.

 **id**
  Advanced Threat Prevention report ID.  A single report ID can be
  specified, which is a hexadecimal string.

 A successful response will contain a content type of
 ``application/octet-stream`` and the pcap is the response body
 content.

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution until the time specified in the ``x-minute-ratelimit-reset``
  response header, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

pantv.ApiVersion class Attributes and Methods
---------------------------------------------

 The ApiVersion class provides an interface to the API version of the
 ThreatVaultApi class instance.

 =================   ===========
 Attribute           Description
 =================   ===========
 version             version as an integer
 =================   ===========

__str__()
~~~~~~~~~

 version as a string in the format v\ **version**.  (e.g., *v2*).

__int__()
~~~~~~~~~

 version as an integer with the following layout:

 ==================  ===========
 Bits (MSB 0 order)  Description
 ==================  ===========
 0-7                 unused
 8-15                version
 16-31               reserved for future use
 ==================  ===========

Sample Usage
~~~~~~~~~~~~
::

  import json
  import sys
  
  import pantv


  def tvapi():
      path = '/etc/tv/keys/keys-acmecorp.json'
      try:
          with open(path, 'r') as f:
              args = json.load(f)
      except (IOError, ValueError) as e:
          print('%s: %s' % (path, e), file=sys.stderr)
          sys.exit(1)

      kwargs = {}
      for x in args:
          kwargs[x.replace('-', '_')] = args[x]

      try:
          api = pantv.ThreatVaultApi(**kwargs)
      except (pantv.ApiError, pantv.ArgsError) as e:
          print('pantv.ThreatVaultApi:', e, file=sys.stderr)
          sys.exit(1)
      print('api_version: %s, 0x%04x' %
            (api.api_version, int(api.api_version)))


  tvapi()

Debugging and Logging
---------------------

 The Python standard library ``logging`` module is used to log debug
 output; by default no debug output is logged.

 In order to obtain debug output the ``logging`` module must be
 configured: the logging level must be set to one of **DEBUG1**,
 **DEBUG2**, or **DEBUG3** and a handler must be configured.
 **DEBUG1** enables basic debugging output and **DEBUG2** and
 **DEBUG3** specify increasing levels of debug output.

 For example, to configure debug output to **stderr**:
 ::

  import logging

  if options['debug']:
      logger = logging.getLogger()
      if options['debug'] == 3:
          logger.setLevel(pantv.DEBUG3)
      elif options['debug'] == 2:
          logger.setLevel(pantv.DEBUG2)
      elif options['debug'] == 1:
          logger.setLevel(pantv.DEBUG1)

      handler = logging.StreamHandler()
      logger.addHandler(handler)

EXAMPLES
========

 The **tvapi.py** command line program calls each available
 ThreatVaultApi method, with and without ``async/await``, and can be
 reviewed for sample usage of the class and its methods.
 ::

  $ tvapi.py -F /etc/tv/keys-acmecorp.json --threats --id 30001 -j
  threats: 200 OK 1296
  {
      "count": 1,
      "data": {
          "antivirus": [],
          "fileformat": [],
          "spyware": [],
          "vulnerability": [
              {
                  "category": "overflow",
                  "cve": [
                      "CVE-2011-2663"
                  ],
                  "default_action": "reset-server",
                  "description": "Novell GroupWise 8.0 before HP3 is prone to a buffer overflow vulnerability while parsing certain crafted calendar requests. The vulnerability is due to an invalid array indexing error while parsing a crafted yearly RRULE variable in a VCALENDAR attachment. An attacker could exploit the vulnerability by sending a crafted VCALENDAR request in an e-mail message. A successful attack could lead to remote code execution with the privileges of the server.",
                  "details": {
                      "change_data": "updated associated default action to reset"
                  },
                  "id": 30001,
                  "latest_release_time": "2020-10-29T18:15:11Z",
                  "latest_release_version": 8337,
                  "max_version": "",
                  "min_version": "8.1.0",
                  "name": "Novell GroupWise iCal RRULE Time Conversion Invalid Array Indexing Vulnerability",
                  "ori_release_time": "2016-12-29T16:55:04Z",
                  "ori_release_version": 650,
                  "reference": [
                      "http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=945"
                  ],
                  "severity": "high",
                  "status": "released",
                  "vendor": []
              }
          ],
          "wildfire": []
      },
      "link": {
          "next": null,
          "previous": null
      },
      "message": "Successful",
      "success": true
  }

SEE ALSO
========

 tvapi.py command line program
  https://github.com/PaloAltoNetworks/pan-threat-vault-python/blob/main/doc/tvapi.rst

 Threat Vault API Reference
  https://pan.dev/cdss/threat-vault/api/

 Threat Vault API Developer Documentation
  https://pan.dev/cdss/threat-vault/docs

 OpenAPI Documents
  https://github.com/PaloAltoNetworks/pan.dev/tree/master/static/cdss/threat-vault/spec

AUTHORS
=======

 Palo Alto Networks, Inc.
