# Changelog

All notable changes to this project are documented here. The bundle has one
version for all three components; it is written once in `src/version.py` and a
release is a tag with that number.

## Unreleased

- Hardening (cleaner): the hash check of a freshly written file - the quarantine
  copy after `--apply`, the replaced file after `--replace-core` - now retries
  briefly when the read is locked. Real-time antivirus keeps a short lock on
  freshly written files while it scans them, and a collision used to fail the
  file with a raw `PermissionError` in the middle of `--apply`. With no lock the
  behavior is unchanged; when a lock outlives the retry the cleaner gives up with
  a message that names the cause instead of a traceback.
- New tool (`joomla_baseline.py`): given a version, downloads the official
  Joomla Full_Package from the `joomla/joomla-cms` GitHub releases, verifies it
  (the API sha256 digest when the API provides one, otherwise the version of the
  unpacked distribution must match the request), unpacks it into a local cache
  and writes a sha256 manifest for every file. The result is passed as
  `--baseline-dir` to the scanner or the cleaner; a re-run verifies the cached
  baseline offline and re-downloads only if a file changed.
- Bug fix (cleaner): the Joomla version is now detected for 3.7 and earlier in
  the `--replace-core` baseline check (the real files use `const RELEASE` /
  `const DEV_LEVEL`, which the old pattern could not match); such versions were
  reported as "undetermined" and the replacement was refused.

## v3.1 — 2026-11-26

- One version for the bundle: `src/version.py` is the only place the number is
  written, the scanner, the GUI and the cleaner import it. They keep the same
  value as a fallback literal so that a lone `scan_backdoors.py` uploaded to a
  server still starts; a test compares the fallbacks with `version.py`.
- `scan_backdoors_gui.py --version` exists (`scan_backdoors_gui 3.1`), like the
  other two scripts. `python start.bat` and the browser page show the same number.
- The scanner and the cleaner, which used to carry `2.1` and `1.0`, now report the
  bundle version too. The version mismatch between the tag of 2026-10-14 ("v2.1.1")
  and `VERSION = "2.1"` in the file is gone with this.
- Test suite in `tests/`, stdlib `unittest` only: synthetic clean and infected
  sites, the signature and severity each planted sample must produce, "a dry run
  changes nothing" and the plan → apply → restore cycle of the cleaner, exit codes
  and report formats, the allowlist dataset, the GUI over its HTTP API, and
  release hygiene (one version, documented flags, nothing private in the tree).
  Malicious samples live in `tests/payloads/*.b64` and are unsealed only into a
  temporary fixture folder.
- `.github/workflows/ci.yml`: the suite on Linux and Windows on Python 3.8/3.11/3.13.
- Bug fix (scanner): the "code after class JConfig" signature looked for the end
  of the class at the LAST `}` of the file. An appended backdoor carries braces
  of its own, so the signature could never fire on exactly the injections it was
  written for. The class end is now found by counting braces from the class
  opening brace (braces inside string literals and comments are ignored).
- Bug fix (cleaner): the "the quarantine must not be inside the site" check
  compared a resolved path against an absolute one. On machines where the two
  spellings differ (8.3 short names, junctions, reparse points) the check was
  silently disabled and a quarantine could end up in the web root. Both sides
  are now normalized the same way, and when the containment cannot be
  established the cleaner refuses instead of running (fail closed).
- CI: the Linux leg is pinned to `ubuntu-24.04` (newer images no longer ship
  Python 3.8), `actions/checkout` and `actions/setup-python` are on v7.

## v3.0 — 2026-10-19

- Browser GUI front end (`src/scan_backdoors_gui.py`): a local web server on
  127.0.0.1 plus one page — scan, findings table, show file, quarantine, delete,
  add to whitelist, mass cleanup with a plan-and-confirm step, reports in
  CSV/XLSX/JSON. Replaces the earlier `tkinter` desktop front end.
- Scanner and cleaner unchanged in this release.

## v2.1 — 2026-10-14

First commits in this repository; the drafts before this date (07–11 October,
including the `tkinter` versions) were never committed.

- `src/scan_backdoors.py` 2.1: signature scan of PHP/JS/HTML and images for
  embedded code, multi-processing, `--baseline-dir` diff against a clean Joomla
  distribution, `--whitelist`, `--since`, severity scores, CSV/JSON/XLSX reports,
  exit codes `0`/`1`/`2`.
- `src/clean_malware.py` 1.0: mass cleanup of known malware families with
  quarantine, `manifest.json` rollback (`--restore`), and core-file restore from
  a clean distribution of the same version (`--replace-core`) guarded by version
  and modified-percentage checks.
- `start.bat` Windows launcher.
