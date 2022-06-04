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
             async for ok, x in api.threats_all(signatureType='spyware'):
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

 +-----------------------------------+-----------------------+-----------------------------------------+
 | Request                           | ThreatVaultApi Method | API Resource Path                       |
 +===================================+=======================+=========================================+
 | | Get threat prevention metadata  | threats()             | /service/publicapi/v1/threats           |
 | | information                     |                       |                                         |
 +-----------------------------------+-----------------------+-----------------------------------------+
 | | Get application and threat      | release_notes()       | /service/publicapi/v1/release-notes     |
 | | release note information        |                       |                                         |
 +-----------------------------------+-----------------------+-----------------------------------------+
 | | Get Advanced Threat Prevention  | atp_reports()         | /service/publicapi/v1/atp/reports       |
 | | threat report                   |                       |                                         |
 +-----------------------------------+-----------------------+-----------------------------------------+
 | | Get Advanced Threat Prevention  | atp_reports_pcaps()   | /service/publicapi/v1/atp/reports/pcaps |
 | | threat pcap                     |                       |                                         |
 +-----------------------------------+-----------------------+-----------------------------------------+

 Convenience methods implemented as generator functions are provided,
 which can be used to process all items when response paging can
 occur, and which can automatically retry requests when rate limiting
 occurs:

 =========================   ================================
 ThreatVaultApi Method       API Resource Path
 =========================   ================================
 threats_all()               /service/publicapi/v1/threats
 =========================   ================================

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

  The default is "\https://tpp.tpcloud.paloaltonetworks.com".

 **api_key**
  The ``x-tpp-api-key`` request header value used to authenticate API
  requests.  This is the Threat Prevention API key available on the
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

threats(\*, id=None, name=None, cve=None, fromReleaseDate=None, toReleaseDate=None, fromReleaseVersion=None, toReleaseVersion=None, releaseDate=None, releaseVersion=None,  signatureType=None, offset=None, limit=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``threats()`` method performs the ``/threats`` API request to get
 threat prevention metadata information.

 **id**
  Threat signature ID number.

 **name**
  Threat signature name.  Words in *name* are used to perform a fuzzy
  match on the signature name; *name* must be at least 3 characters
  and only alphanumeric characters are allowed, other characters are
  ignored.

 **cve**
  CVE (Common Vulnerabilities and Exposures) name or partial CVE
  name.  Examples:

  - CVE-2022-21907
  - CVE-2022

 **fromReleaseDate**
  Start date for content release range.  Date format is *YYYY-MM-DD*.

 **toReleaseDate**
  End date for content release range.  Date format is *YYYY-MM-DD*.

 **fromReleaseVersion**
  Start version for content release range.

 **toReleaseVersion**
  End version for content release range.

 **releaseDate**
  Content release data.  Date format is *YYYY-MM-DD*.

 **releaseVersion**
  Content release version.

 **signatureType**
  Signature type:

   **ips** - return all IPS signature metadata

   **fileformat** - return file-format signature metadata

   **spyware** - return anti-spyware signature metadata

   **vulnerability** - return vulnerability protection signature metadata

 **offset**
  Numeric offset used for response paging.  The default offset is 0.

 **limit**
  Numeric number of items to return in a response.  The default
  limit is 10,000 and the maximum is 10,000.

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution until the time specified in the ``x-ratelimit-reset``
  response header, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

threats_all()
~~~~~~~~~~~~~

 The ``threats_all()`` method is a generator function which executes
 the ``threats()`` method until all items are returned.  Response
 paging is handled with the **offset** and **limit** specified, or a
 starting offset of 0 and limit of 10,000.  The arguments are the same
 as in the ``threats()`` method.

 The generator function yields a tuple containing:

  **status**: a boolean

   - True: the HTTP status code of the request is 200
   - False: the HTTP status code of the request is not 200

  **response**: a response item, or HTTP client library response object

   - **status** is True: an object in the response ``fileformat``,
     ``spyware`` or ``vulnerability`` list
   - **status** is False: HTTP client library response object

release_notes(\*, noteType=None, version=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``release_notes()`` method performs the ``/release-notes`` API
 request to get application and threat release note information.

 **noteType**
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
  execution until the time specified in the ``x-ratelimit-reset``
  response header, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

atp_reports(\*, report_id=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``atp_reports()`` method performs the ``/atp/reports`` API
 request to get an Advanced Threat Prevention threat report.

 **report_id**
  Advanced Threat Prevention report ID.  Multiple report IDs can be
  specified as a list/array of hexadecimal strings.

  **report_id** can be:

   a Python list

   a ``str``, ``bytes`` or ``bytearray`` type containing JSON text

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution until the time specified in the ``x-ratelimit-reset``
  response header, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

atp_reports_pcaps(\*, report_id=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``atp_pcaps()`` method performs the ``/atp/reports/pcaps`` API
 request to get the packet capture file for an Advanced Threat
 Prevention threat.

 **report_id**
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
  execution until the time specified in the ``x-ratelimit-reset``
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
  https://panos.pan.dev/api/tp/tp-public-api-overview

 Advanced Threat Prevention
  https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/threat-prevention/about-threat-prevention/advanced-threat-prevention

AUTHORS
=======

 Palo Alto Networks, Inc.
