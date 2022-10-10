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

========
tvapi.py
========

-----------------------------------------------------------------
command line interface to the Palo Alto Networks Threat Vault API
-----------------------------------------------------------------

NAME
====

 tvapi.py - command line interface to the Palo Alto Networks Threat Vault API

SYNOPSIS
========
::

 tvapi.py [options]
    --api-key key            API key
    --threats                threats API request
    --threats2               multiple threats bulk API request
    --threats-history        threats release history API request
    --release-notes          release-notes API request
    --atp-reports            ATP reports API request
    --atp-pcaps              ATP reports pcaps API request
    --all                    get all threats
    --id id                  signature/report ID (multiple --id's allowed)
    --name name              signature name (multiple --name's allowed)
    --cve id                 CVE ID
    --sha256 hash            SHA-256 hash (multiple --sha256's allowed)
    --md5 hash               MD5 hash (multiple --md5's allowed)
    --type type              signature/release-note type
    --note-version version   release-note version
    --offset num             items offset
    --limit num              number of items to return
    -Q json                  URL query string (multiple -Q's allowed)
    --data json              threats2, atp-reports POST data
    --url url                API URL
                             default https://api.threatvault.paloaltonetworks.com
    --verify opt             SSL server verify option: yes|no|path
    --aio                    Use asyncio (default)
    --noaio                  Don't use asyncio
    --api-version version    API version (default v1)
    -j                       print JSON
    -p                       print Python
    --rate-limits            print response header rate limits
    --dst dst                save pcap to directory or path
    -J expression            JMESPath expression for JSON response data
    -O                       optimized get all with JSON only output
    --timeout timeout        connect, read timeout
    -F path                  JSON options (multiple -F's allowed)
    --debug level            debug level (0-3)
    --dtime                  add time string to debug output
    --version                display version
    --help                   display usage

DESCRIPTION
===========

 **tvapi.py** is used to perform Threat Vault API requests.  It
 uses the ThreatVaultApi class from the **pantv** module to execute
 API requests.

 The Threat Vault API can be used to:

 - Get threat prevention metadata information
 - Get threat content release and version history
 - Get application and threat release note information
 - Get Advanced Threat Prevention threat report
 - Get Advanced Threat Prevention threat pcap

 The options are:

 ``--api-key`` *key*
  The ``x-api-key`` request header value used to authenticate API
  requests.  This is the *Threat Vault API* key available on the
  customer support portal under *Assets->API Key Management*.

 ``--threats``
  Perform the ``/threats`` API request to get threat prevention
  metadata information.

 ``--threats2``
  Performs the ``/threats`` API request to get threat prevention
  metadata information.  ``--threats2`` uses the HTTP POST method.

  ``--threats2`` is used to perform bulk queries using multiple values
  for *id*, *name*, *sha256*, or *md5*.  Up to 100 query values can be
  specified.

 ``--threats-history``
  Perform the ``/threats/history`` API request to get threat content
  release and version history for a threat signature ID and signature
  type.

 ``--release-notes``
  Perform the ``/release-notes`` API request to get application and
  threat release note information.

 ``--atp-reports``
  Perform the ``/atp/reports`` API request to get an Advanced Threat
  Prevention threat report.  One or more report IDs must be specified
  with the ``--id`` option.

 ``--atp-pcaps``
  Perform the ``/atp/reports/pcaps`` API request to get the packet
  capture file for an Advanced Threat Prevention threat.  A single
  report ID must be specified with the ``--id`` option.  By default
  the pcap is saved to the current directory with the filename
  ``reportid.pcap``; this can be changed with the ``--dst`` option.

 ``--all``
  Get all threats matching the search criteria.  This uses the
  ThreatVaultApi ``threats_all()`` method which performs the
  ``/threats`` API request until all items are returned.

  The resulting object contains a *data* name, and the value is an
  array of threat objects.

  ``--all`` can also be useful for data analysis because it
  consolidates all threats into a single list; the API response body
  object format for threats places threats into a separate object name
  for each category of threat, which are:

   **fileformat**

   **spyware**

   **vulnerability**

 ``--id`` *id*
  Threat signature ID number, or Advanced Threat Protection report ID.
  Multiple instances of the option are allowed.

 ``--name`` *name*
  Threat signature name.  Words in *name* are used to perform a fuzzy
  match on the signature name; *name* must be at least 3 characters
  and only alphanumeric characters are allowed, other characters are
  ignored.
  Multiple instances of the option are allowed.

 ``--cve`` *id*
  CVE (Common Vulnerabilities and Exposures) ID.

  An exact or partial CVE ID can be specified:

  - partial CVE ID format: *CVE-YYYY*
  - exact CVE ID format: *CVE-YYYY-NNNN* (NNNN can be 4 or more digits)

  Examples:

  - CVE-2022
  - CVE-2022-21907

 ``--sha256`` *hash*
  Sample SHA-256 hash value.
  Multiple instances of the option are allowed.

 ``--md5`` *hash*
  Sample MD5 hash value.
  Multiple instances of the option are allowed.

 ``--type`` *type*
  Specify type for:

  - ``--threats`` - threat signature type
  - ``--threats2`` - threat signature type
  - ``--threats-history`` - threat history signature type
  - ``--release-notes`` - release note type

  Threat signature types are grouped into *IPS* types (Intrusion
  Prevention System) and *Virus* types:

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

  Threat history signature type:

   **antivirus** - anti-virus release and version history

   **wildfire** - WildFire release and version history

  Release note type:

   **content**

 ``--note-version`` *version*
  Content version.

 ``--offset`` *num*
  Numeric offset used for response paging.  The default offset is 0.

 ``--limit`` *num*
  Numeric number of items to return in a response.  The default
  limit is 1,000 and the maximum is 1,000.

  Paging is used in the threats API request.

 ``-Q`` *json*
  Specify a JSON object to modify the query string used in the
  request.  This can be used to specify request parameters that are
  not supported by a class method or the command line interface.
  Multiple instances of the option are allowed.

  *json* can be a string, a path to a file containing a JSON object,
  or the value **-** to specify a JSON object is on *stdin*.

 ``--data`` *json*
  JSON text to send in the body of the request.

  ``--threats2`` request:

   The text is a JSON object with key/values for *type* (optional) and
   one of: *id*, *name*, *sha256*, *md5*.

  ``--atp-reports`` request:

   The text is a JSON object with key/values for *id*.

 ``--url`` *url*
  URL used in API requests.

  The default is "\https://api.threatvault.paloaltonetworks.com".

 ``--verify`` *opt*
  Specify the type of SSL server certificate verification to be
  performed:

   **yes**
    Perform SSL server certificate verification.  This is the default.

   **no**
    Disable SSL server certificate verification.

   ``path``
    Path to a file containing CA certificates to be used for SSL
    server certificate verification.

 ``--aio``
  Use the `asyncio <https://docs.python.org/3/library/asyncio.html>`_
  class interface.  This is the default.

  The asyncio class interface uses the
  `aiohttp library <https://docs.aiohttp.org/>`_.

 ``--noaio``
  Use the normal class interface.

  The normal class interface uses the
  `requests library <https://docs.python-requests.org/>`_.

 ``--api-version`` *api_version*
  API version is a string in the form v\ **version** or
  **version** (e.g., *v2*).  The API version is used to determine
  the ThreatVaultApi class implementation to use.

  The default API version can be displayed with ``tvapi.py --debug 1``.

 ``-j``
  Print JSON response to *stdout*.

 ``-p``
  Print JSON response in Python to *stdout*.

 ``--rate-limits``
  Print response header rate limits to *stdout*.

 ``--dst`` *dst*
  Save pcap to the directory or path specified in *dst*.  By default
  the pcap is saved to the current directory with the filename
  ``reportid.pcap``.

 ``-J`` *expression*
  `JMESPath expression
  <https://jmespath.org/>`_ to evaluate on the response JSON object.
  This requires the `jmespath package
  <https://pypi.org/project/jmespath/>`_.

 ``-O``
  This is an optimised version of ``-j`` for use with ``--all``, which
  does not place all the results in memory. The API response items are
  encoded to a JSON list and written to *stdout* as they are returned
  by the generator function.

  The print Python option (**-p**) and JMSEPath expression option
  (**-J**) are ignored for ``-O``.

  ``-O`` requires ``--noaio`` due to complications using the
  ``json.JSONEncoder`` class with an asynchronous generator.

 ``--timeout`` *timeout*
  Set client HTTP timeout values in seconds.

  **timeout** can be:

   a single value to set the total timeout (aiohttp) or the
   **connect** and **read** timeouts to the same value (requests)

   a tuple of length 2 to set the **connect** and **read** timeouts to
   different values (aiohttp and requests)

  The
  `asyncio library timeout
  <https://docs.aiohttp.org/en/stable/client_quickstart.html#timeouts>`_
  defaults to a total timeout of 300 seconds, meaning the operation
  must complete within 5 minutes.

  The
  `requests library timeout
  <https://docs.python-requests.org/en/latest/user/advanced/#timeouts>`_
  defaults to no timeout, meaning the timeouts are determined by the
  operating system TCP implementation.

 ``-F`` *path*
  Path to file containing a JSON a object with command options.  The allowed
  options are:

  - ``api-version``
  - ``api-key``
  - ``url``
  - ``verify``

  Because this file may contain the API key it should have strict
  file permissions (read/write for the owner and not accessible by
  group or other).

 ``--debug`` *level*
  Enable debugging in **tvapi.py** and the **pantv** module.
  *level* is an integer in the range 0-3; 0 specifies no
  debugging and 3 specifies maximum debugging.

 ``--dtime``
  Prefix debug output with a timestamp.

 ``--version``
  Display version.

 ``--help``
  Display command options.

EXIT STATUS
===========

 **tvapi.py** exits with 0 on success and 1 if an error occurs.

EXAMPLES
========

 The examples use a JSON config file containing the API key:
 ::

  $ cat /etc/tv/keys-acmecorp.json
  {
      "api-key": "******"
  }

 Get a single threat:
 ::

  $ tvapi.py -F /etc/tv/keys-acmecorp.json --debug 1 --threats --id 13200 -j
  Using selector: KqueueSelector
  api_version: v1, 0x0100
  GET https://api.threatvault.paloaltonetworks.com/service/v1/threats?id=13200 200 OK 632
  threats: 200 OK 632
  {
      "count": 1,
      "data": {
          "spyware": [
              {
                  "category": "spyware",
                  "cve": [],
                  "default_action": "reset-server",
                  "description": "This signature detects Gh0st.Gen Command and Control Traffic.",
                  "details": {
                      "change_data": "updated associated metadata information"
                  },
                  "id": "13200",
                  "latest_release_time": "2022-02-07T15:40:05Z",
                  "latest_release_version": "8524",
                  "max_version": "",
                  "min_version": "8.1.0",
                  "name": "Gh0st.Gen Command and Control Traffic",
                  "ori_release_time": "2017-03-09T14:00:08Z",
                  "ori_release_version": "671",
                  "reference": [],
                  "severity": "critical",
                  "status": "released",
                  "vendor": []
              }
          ]
      },
      "link": {
          "next": null,
          "previous": null
      },
      "message": "Successful",
      "success": true
  }
  closing aiohttp session

 Get release notes for the previous example threat release version and
 save to a file:
 ::

  $ tvapi.py -F /etc/tv/keys-acmecorp.json --debug 1 --release-notes --type content \
  > --note-version 8524 -j > note-8524.json
  Using selector: KqueueSelector
  api_version: v1, 0x0100
  GET https://api.threatvault.paloaltonetworks.com/service/v1/release-notes?type=content&version=8524 200 OK 48014
  release-notes: 200 OK 48014

  $ head note-8524.json 
  {
      "count": 1,
      "data": [
          {
              "content_version": "8524-7228",
              "release_notes": {
                  "applications": {
                      "modified": [],
                      "new": [],
                      "obsoleted": []

 Get all threats and save to a file:
 ::

  $ tvapi.py -F /etc/tv/keys-acmecorp.json --threats --type ips --all -j >threats-all.json

 Get threats updated in a specific one day window, and display the CVE
 IDs that are available:
 ::

  $ tvapi.py -F /etc/tv/keys-acmecorp.json --debug 1 --threats --all -Q \
  > '{"fromReleaseDate":"2022-03-22","toReleaseDate":"2022-03-23"}' \
  > -jJ 'data[?not_null(cve)].cve'
  Using selector: KqueueSelector
  api_version: v1, 0x0100
  GET https://api.threatvault.paloaltonetworks.com/service/v1/threats?offset=0&limit=1000&fromReleaseDate=2022-03-22&toReleaseDate=2022-03-23 200 OK 8698
  count 9 current 9 total 9
  [
      [
          "CVE-2021-2390"
      ],
      [
          "CVE-2021-43983"
      ],
      [
          "CVE-2021-44224"
      ],
      [
          "CVE-2022-23967"
      ],
      [
          "CVE-2013-7179"
      ],
      [
          "CVE-2021-38389"
      ],
      [
          "CVE-2021-22802"
      ],
      [
          "CVE-2021-35598"
      ]
  ]
  closing aiohttp session

 Get threats which reference a CVE ID in year 2021 using a partial match
 and display the ``count`` object member value in the response:
 ::

  $ tvapi.py -F /etc/tv/keys-acmecorp.json  --debug 1 --threats --cve CVE-2021 -jJ count
  Using selector: KqueueSelector
  api_version: v1, 0x0100
  GET https://api.threatvault.paloaltonetworks.com/service/v1/threats?cve=CVE-2021 200 OK 943732
  threats: 200 OK 943732
  1098
  closing aiohttp session

SEE ALSO
========

 pantv module
  https://github.com/PaloAltoNetworks/pan-threat-vault-python/blob/main/doc/pantv.rst

 Threat Vault API Reference
  https://pan.dev/cdss/threat-vault/api/

 Threat Vault API Developer Documentation
  https://pan.dev/cdss/threat-vault/docs

 OpenAPI Documents
  https://github.com/PaloAltoNetworks/pan.dev/tree/master/static/cdss/threat-vault/spec

 JMESPath query language for JSON
  https://jmespath.org/

AUTHORS
=======

 Palo Alto Networks, Inc.
