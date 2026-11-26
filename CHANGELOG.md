# Changelog

All notable changes to this project are documented here. Versions of the three
components are tagged together as one release; the components themselves carry
independent `VERSION` values (see the table in the README).

## Unreleased

- Repository layout: the three scripts moved to `src/`, the logo and icon to
  `assets/`, the Russian manual to `docs/`, the known-clean allowlist to `data/`.
  `start.bat` stays in the project root and launches `src\scan_backdoors_gui.py`.
- Published `data/whitelist-known-clean.txt`: 3 571 SHA-256 hashes of legitimate
  third-party files (TCPDF, Akeeba `phpfinder`, VirtueMart `vrequest.php`,
  RSFirewall/Komento helpers, `.phar` pubkeys) with a note per entry on why it is
  clean. Collected during real cleanups; contains no site names or paths outside
  the extension folders.
- Added `LICENSE` (MIT), `SECURITY.md` and this file.
- README aligned with the versions that actually ship (scanner 2.1, GUI 3.0,
  cleaner 1.0) instead of the old "2.1 parameter reference" title.
- To settle in the next release: the tag message of 2026-10-14 says "v2.1.1"
  while `scan_backdoors.py` reports `VERSION = "2.1"`.

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
