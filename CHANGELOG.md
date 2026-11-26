# Changelog

All notable changes to this project are documented here. The bundle has one
version for all three components; it is written once in `src/version.py` and a
release is a tag with that number.

## v3.2 — 2026-11-27

- Scanner: webshell detection no longer requires the request array to be written
  into the sink directly. New signatures follow the value: a superglobal read
  (optionally through `base64_decode`/`urldecode`/`rawurldecode`/`strrev`)
  assigned to a local variable that later reaches `system`/`exec`/`shell_exec`/
  `passthru`/`popen`/`proc_open`/`eval`/`assert`/`include`/`require` is
  CRITICAL ("exec sink fed by a variable from request data"), and the same taint
  into a file function (`fopen`/`opendir`/`readfile`/`file`/`file_get_contents`/
  `copy`/`rename`/`unlink`/…) is OBFUSCATED. This is how the July-2026
  wp2shell campaign web shell (`$cmd = $_GET['c']; system($cmd);`) evades
  one-line greps.
- Scanner: a file path taken from the request is now flagged whether the file is
  opened or written: `copy(…, $_POST['remotefile'])` and its siblings
  (`rename`/`move_uploaded_file`/`link`/`symlink`/`touch`/`unlink`/`chmod`/
  `mkdir`/`rmdir`) are CRITICAL, and `opendir`/`fopen`/`readfile`/
  `file_get_contents`/`file` straight from `$_GET`/`$_POST` are CRITICAL - the
  classic uploader and LFI shells.
- Scanner: the July-2026 campaign tells. A plugin folder named
  `<name>-<6 hex digits>` under `wp-content/plugins/` or `mu-plugins/`
  (real plugin slugs end in a version, never in a bare hex id) is OBFUSCATED,
  as is a plugin header claiming `Author: WordPress.org Community`
  (impersonation). `hash_equals()` against request data is OBFUSCATED on
  non-WordPress sites (the classic `?t=<hash>` webshell gate) and switched off
  on detected WordPress, where it is the ordinary nonce verification - on
  WordPress the campaign shell is still caught by the taint, name and folder
  signatures.
- Scanner: the webshell-name check now knows the classic shell families with
  version suffixes: a stem that *starts* with `c99`, `r57` or `b374k`
  (`c99_madnet.php`, `r57shell.php`) is a typical webshell filename, not only
  the bare family name. Cross-checked against a published 772-name backdoor
  list: only the unambiguous prefixes were added, because bulk-adding the rest
  would flag legitimate files (`client.php`, `config.inc.php`).
- Tests: four new sealed payloads pin the new signatures - the campaign web
  shell (taint + folder + header), a taint LFI in `/tmp/`, an uploader with a
  request-driven destination, and a prefixed shell name.
- README: a "How does it compare to other tools?" section (wp2shell-scan,
  wp-guard, LMD, public signature lists), including what a file scanner
  deliberately does not cover (the database side, runtime protection).
- `--self-test` on all three scripts: a built-in liveness check, no network and no
  real site needed. The scanner unseals four embedded test payloads into a throwaway
  folder under `%TEMP%/sbd-fixtures` and each must be detected; the cleaner does the
  same with one sample per family (htaccess / backdoor / filemanager); the GUI runs
  a doctor (11 checks: the settings file, the scanner, its version, the cleaner next
  to it, and the path settings). Exit 0 iff all checks pass.
- The whitelist loader (`--whitelist`, scanner and cleaner) now reports every
  malformed line by line number - a hex string of another length, binary garbage -
  and skips it; the scan goes on instead of silently losing the suppression.
- The GUI validates all path settings at boot (a bad field is named in the log) and
  refuses a scan or cleanup job that would run on bad settings; the silent
  `scanner_path` reset is gone. `--self-test` checks the same things without a server.
- Release assets now include `sha256sums.txt` with the zip's SHA-256 (retro-attached
  to v3.1.1 and v3.1); GitHub issue templates added (false positive first).
- Scanner: CMS detection. The scanner now tells a WordPress site from a Joomla one
  by its root files (`wp-config.php`/`wp-load.php` vs `configuration.php`/`administrator/`)
  and prints which it decided. Joomla-specific heuristics are switched off on
  WordPress: the credential-harvester pattern, the "wp-*.php in Joomla" filename
  check, and the file-manager feature check plus the webshell-filename check inside
  `wp-includes/` and `wp-admin/` (core files, e.g. the legitimate diff engine
  `wp-includes/Text/Diff/Engine/shell.php`).
- Scanner: PHP comments no longer count as code. A comment mask (state machine for
  `//`, `#`, `/* */`, strings and `<?php` boundaries) is applied before the pattern
  search for files of pure PHP kind, so a `$_POST` mentioned in a docblock is not a
  "backticks with request data" or "dynamic variable" anymore. Applied only to
  `.php` files: in `.htaccess`/`.js`/`.html` with embedded PHP the `#` comments are
  not PHP comments and must stay visible.
- Scanner: the credential harvester no longer reads an assignment as a read
  (`$_POST['passwd'] = ''` is a field reset, not an exfiltration; a comparison with
  `==` still is), and the "response-header leak" fires only on custom `X-*` headers
  (`header('HTTP/1.1 403')` is not a leak).
- Scanner: the exec family is graded by its argument. `shell_exec`/`passthru`/
  `pcntl_exec` with a literal argument is OBFUSCATED, not CRITICAL (the getID3
  player and the Symfony console do that legitimately); but a request-driven
  argument is still CRITICAL, and a new pattern catches the concatenation forms:
  `shell_exec('cat ' . $_GET['f'])` and `system('...' . $_REQUEST[...])` were
  invisible before.
- Scanner: variable-variables `${$var}` are OBFUSCATED, not CRITICAL (legitimate
  code in every framework), but a request superglobal in the braces — `${$_POST[...`
  — is a new CRITICAL.
- Scanner: a hidden iframe is counted only when its `src`/`srcdoc` looks like a
  payload (a URL, a path, a variable, `data:`, `<?`); the `src="javascript:"` and
  the JS-built `iframe.src = 'about:blank'` of legitimate libraries no longer are.
- Scanner: filename heuristics trimmed. `filemanager` is out of the webshell-name
  list (two legitimate plugins use it; `tinyfilemanager`/`fm`/`filesman` stay), and
  `moderation.php`, `system_log.php`, `inputs.php` are out of the malware-name list
  (they collide with WordPress core files in `wp-admin/`).
- Scanner: small false-positive trims - mtime backdating counts only when the
  backdating expression is an argument of the `touch()` call itself; `autoload*.php`
  in a cache folder is not a "hidden PHP file"; `.phpt` test files and
  `#!/usr/bin/env php` scripts are not "PHP tag inside a file"; `.pem`/`.crt`/
  `.cer`/`.asc`/`.base64` data blobs are not "high-entropy content"; and ten
  standard `X-*` headers (`X-Frame-Options`, `X-Content-Type-Options`, `X-Sendfile`,
  `X-UA-Compatible`, ...) are whitelisted from the exfiltration pattern.
- On a clean WordPress reference site this batch takes the false CRITICALs from 82
  to 0 (and the false HIGH files to 0); on a compromised Joomla reference the true
  positives are untouched: the backdoored `.htaccess` template and its allow-list
  entries and the web shell in `/tmp/` are still reported.
- New tool (`tools/build_allowlist.py`): point it at a site you consider clean and
  it writes a known-clean allowlist in the exact format `--whitelist` reads - one
  line per file, the file's SHA-256 (the default, so a later modification re-arms
  the file) or its path (`--format paths`), with a header carrying the scanner
  version, the source folder, the date and the counters. `--skip-matching` keeps
  only files without findings, `--min-score N` keeps only files below N, `--out`
  writes a file (default: standard output). It warns loudly if any file it
  whitelists still carries findings.
- Scanner: `--sarif PATH` writes the report as SARIF 2.1.0, so the findings can be
  imported into code-scanning UIs (GitHub code scanning, Azure DevOps, CodeQL CLI
  `sarif` upload). One result per finding: the rule is the signature, the level is
  the severity (CRITICAL -> `error`, OBFUSCATED -> `warning`, WARNING -> `note`),
  the location is the file with the line of the finding.

## v3.1.1 — 2026-11-26

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
