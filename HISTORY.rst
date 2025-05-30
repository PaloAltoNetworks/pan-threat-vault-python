Release History
===============

0.4.0 (2025-05-26)
------------------

- Fix typo in documentation: extended -> external.

- Update threats test for added antivirus id.

- Add tests for edl().

- urllib3 v2 emits NotOpenSSLWarning when the ssl module does not use
  OpenSSL; suppress this in tvapi.py for debug 0 and 1.  Systems
  including macOS and OpenBSD use LibreSSL.

0.3.0 (2023-04-30)
------------------

- Add EDL (external dynamic list) API request:

    https://pan.dev/threat-vault/api/edl/

  tvapi.py --note-version is deprecated for --release-notes; use
  --content-version.

0.2.0 (2023-04-04)
------------------

- tvapi.py, tvapy.rst: Fix typo in usage.

- Documentation fixes.

- Add optional test to compare threat IDs to PAN-OS exported threat
  content IDs.

- Add test for release_notes(version='latest').

- tvapi.py, tvapy.rst: Allow path or '-' (stdin) for id, name, md5,
  sha256 arguments.

- tvapi.py: IOError merged into OSError as of Python 3.3.

- Rework /threats/history tests to take into account retention policy.

0.1.0 (2022-08-29)
------------------

- Documentation fixes and improvements.

- Add missing 'vendor' argument to /threats API request.

- Add '--cve id' argument to bin/tvapi.py.

0.0.0 (2022-08-12)
------------------

- Initial release.
