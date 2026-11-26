# Changelog

All notable changes to this project are documented here. The bundle has one
version for all three components; it is written once in `src/version.py` and a
release is a tag with that number.

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
