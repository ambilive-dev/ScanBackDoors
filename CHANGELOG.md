# Changelog

All notable changes to this project are documented here. The bundle has one
version for all components; it is written once in `src/version.py` and a
release is a tag with that number.

## Unreleased
- **CMS audit** (TZ v2 Sprint 3): three new passes over *what is installed* instead of what is
   inside a file, all off by default so an ordinary scan is byte-for-byte what it was.
   `--inventory` lists the CMS and its components (WordPress core/plugins/mu-plugins/themes,
   Joomla version/extensions) with only the version each component *declares*; a component
   without one is reported as unauditable, never as clean. `--check-integrity` compares WordPress
   core files with the official checksums from `api.wordpress.org` and turns a modified core file
   or a PHP file the release does not ship into an ordinary `[CRITICAL]` finding on that file
   (a missing file is reported in the integrity section - there is nothing to quarantine;
   `readme.html`/`license.txt`/`wp-config-sample.php` are translated by distributors and never
   suspicious; plugins and themes have no upstream checksums, so they have no reference file).
   `--audit-cve` reports the known vulnerabilities of the inventoried components from a local
   database (`--vuln-db`, JSON schema 2, shipped empty on purpose) and - with `--online` - from
   `api.wpvulnerability.com`; they are a section of their own in every format (JSON
   `vulnerabilities`, `Vulnerabilities` sheet in XLSX, a separate `<report>-vulnerabilities.csv`
   next to the findings CSV - never a block inside it, because that file is parsed by the GUI and
   by other tools as findings, SARIF results with `ruleId` = CVE)
   and are never offered for quarantine or delete. `--online` is what opens the door: it says
   before the first request that the WordPress version and the component slugs/versions leave the
   machine, works over HTTPS to two pinned hosts with a redirect re-check, a per-run request
   budget and a 24-hour cache in the data folder, so the next run of the same site is offline;
   without it the report states what could not be checked. A CVE changes the exit code only with
   `--fail-on {critical,high,medium}` (code `4`), and never when the verdict was undecidable.
   If the integrity pass flags the file the CMS version was read from, all verdicts in that run
   drop to low confidence - a hacked site can lie about its version. In the GUI the audit is four
   ticks in a new *5. CMS audit* card (all off by default; the network is a separate tick) and the
   answers go to a fourth bottom panel tab **Vulnerabilities** - component, version, CVE, CVSS,
   severity, KEV, fixed-in, confidence, source, sortable and KEV-filterable - where no file action
   is offered at all: the verdicts have no checkbox and Quarantine/Delete/Mass cleanup do not reach
   them. Hostile manifests are parsed
   under size caps with `DOCTYPE`/`ENTITY` refused, no site PHP is executed, symlinks are not
   followed and nothing is written into the site. New engines: `engines/versions.py`
   (PHP-style version comparison, no false "not affected"), `engines/inventory.py`,
   `engines/cms_api.py`, `engines/integrity_wp.py`, `engines/vuln_engine.py`; tests:
   `tests/test_versions.py`, `test_inventory.py`, `test_cms_api.py`, `test_integrity_wp.py`,
   `test_vuln_engine.py`, `test_audit_cli.py` (which traps `socket` to prove a default run and an
   audit without `--online` never reach the network) and `test_gui_audit.py`.
- Signature updates can now be verified by **who published the package**, not only by
  "the bytes did not change": `updater.py` checks the [minisign](https://github.com/jedisct1/minisign)
  format (Ed25519) against a public key pinned in `sources.json` (`package_source.minisign_pub`,
  or `minisign_pub_file` / per-upstream `minisign_pub`), looking for `<url>.minisig` next to the
  package or at `signature_url`. Both of minisign's algorithms are understood (`Ed` signs the
  file, `ED` signs its BLAKE2b-512), the signature's key id must be the pinned one, and both the
  file signature and the global signature have to verify - a signature that is present and wrong
  is a refusal, never a downgrade to the hash. `--signature FILE` brings the same property to an
  offline `--update-from-bundle` install. Checking uses the optional `cryptography` package
  (`requirements-optional.txt`), imported inside one function and only when a source pins a key:
  without it the updater keeps working by pinned sha256 and says so - `Signature NOT checked: …`
  in the output, `"signature": "not-checked"` in the manifest - while `--require-signature`
  refuses instead of falling back. `--status` reports `signature`, `key_id` and
  `signature_library`; the GUI's Engines card shows "signed by minisign key …" or warns that the
  pinned signature went unchecked. The `minisign` binary is never executed; the format handling
  is tested against signatures the real `minisign` produced (fixtures from its author's reference
  port, jedisct1/go-minisign). Key generation and publication remain the owner's decision
  (OPEN_QUESTIONS #13) - `minisign -G` / `minisign -S`, recipe in the README.
- One data folder (OPEN_QUESTIONS #3): everything the tools keep between runs now lives in
   `$SBD_DATA_DIR` (or `~/.scan_backdoors`) - the `.yarac` rule cache (`<data>/yarac`),
   the whitelist the GUI appends to (`<data>/whitelist.txt`), the Joomla baseline cache
   (`<data>/joomla-baselines/`) and the installed signature releases. Nothing is written
   next to the code or inside a scanned site any more. What older versions kept there is
   moved into the data folder once, and nothing is merged or deleted while doing it: the
   GUI moves `whitelist.txt` and `joomla-baselines/` on startup and updates its own
   `whitelist_path`/`baseline_dir` settings, the scanner moves a rule cache left in the
   temp folder before its first YARA scan, `joomla_baseline.py` a cache left next to
   itself; when the destination already exists the old copy simply stays where it is (a
   missing baseline is downloaded again, a missing cache is rebuilt). `--yara-cache` and
   `--out` keep their meaning and still override the location - no flag changed shape.
   Tests: `tests/test_data_paths.py`.
- Signature updates (TZ v2 Sprint 2): a new shipped tool, `src/updater.py`, installs
  YARA rule packages for the optional engine and nothing else. Trust model: a rule set
  becomes active only as a whole and only after checks - download (HTTPS only, host
  allowlist, every redirect re-checked, streamed with a hard size cap) → the pinned
  archive sha256 → safe unpacking (only `.yar`/`.yara`/license files, no `extractall`,
  zip-slip / absolute-path / symlink / compression-bomb guards, nothing written outside
  the staging folder, which lives on the same filesystem as the target) → every rule
  file compiled in a separate `engines/yara_check.py` subprocess with its own timeout →
  the release directory moved into place with one `os.replace` → the `ACTIVE` pointer
  switched and the manifest rewritten atomically (tmp + fsync + `os.replace`). Nothing
  that is downloaded is executed. Channels: `--update-signatures` (the project's own
  package, URL+sha256 pinned in `sources.json`), `--update-from-bundle FILE` (offline,
  same checks, the package manifest must declare every rule file), `--update-from-upstream`
  (only sources pinned to a full 40-hex commit SHA **and** a pinned archive sha256 - a
  branch is refused before any request; one merged release from all sources, a failing
  source carries over the rules it contributed instead of erasing them, exit `3`
  PARTIAL), `--rollback-signatures`, `--status`, `--rules-path`. A package nothing can
  verify is refused unless `--allow-unverified` is passed, and is then recorded
  `"verified": false`; signature schemes (minisign/cosign) are not implemented yet.
  Data lives in `$SBD_DATA_DIR` (or `~/.scan_backdoors`): `signatures/{releases,ACTIVE,
  manifest.json,sources.json}` plus a rotating `logs/updater.log` with secrets masked
  and external strings sanitized (no log injection). Exit codes: `0` / `1` config /
  `3` partial / `4` verification-or-network failure (the previous release stays
  active). GUI: `GET /api/signatures/status`, `POST /api/signatures/update`,
  `POST /api/signatures/rollback` (no client-supplied paths or URLs - the sources are
  updater's own config; the work runs as a background job like the baseline fetch), the
  Engines tab shows the active package with *Update signatures* / *Roll back*, and a
  scan automatically receives `--yara-rules` for the active release when the installed
  scanner understands the flag. Tests: `tests/test_updater.py` (URL policy, strict
  redirects, log masking/sanitization, safe unpacking attacks, download limits, the CLI
  contract, upstream sync against a fake downloader - no test opens a socket) and
  `SignaturesTest` in `tests/test_gui.py`; `tests/harness.py` gained `have_yara()`.
- Scanner (TZ v2 Sprint 1): an optional YARA rules engine behind a new first-party
  `engines/` package (`base_engine.py`: ScanCtx + BaseEngine returning
  `(hits, gap_reasons)`; `yara_engine.py`: optional yara-python, imported lazily).
  `--yara-rules FILE_OR_DIR` compiles rule files per file (a broken file is reported
  and skipped, the rest keep working), refuses `include` directives, binds the
  externals `file_name`/`extension`/`path`/`folder`/`file_size`/`cms`/`wp_root`/
  `joomla_root`/`rule_language` per file at match time, and caches the compiled set
  as a content-keyed `.yarac` (`--yara-cache`, `--no-yara-cache`). A rule hit is a
  signature `YARA: <file>.<rule>`; meta `severity`/`score` map to severities and
  weights, a rule without meta is never more than `[WARNING]`. A file that runs up
  to `--yara-timeout` (yara-python returns incomplete matches silently) becomes a
  visible scan gap: a `[WARNING]` hit plus `YARA: files scanned / scan gaps` in the
  statistics - never a silent pass. `--no-yara` force-disables the engine; without
  yara-python installed the scanner says so and behaves exactly as before (the
  detection golden master is byte-identical with the engine off). New flags are
  documented in README (EN/RU); `requirements-optional.txt` lists the optional
  dependency. The GUI does not pass the new flags yet (settings schema unchanged).
  Tests: `tests/test_yara_engine.py` (contract sync, wiring, isolation, externals,
  cache self-heal, CLI degradation/end-to-end); `tests/test_compat.py` now holds
  `engines/` to the same Python 3.6/stdlib-only floor and allows only lazy imports
  of third-party modules.
- Tests/tools (TZ v2 Sprint 0, no behavior change): a characterization golden master
  (`tests/test_golden_scan.py` + `tests/golden/planted_scan.json`, re-recorded by
  `tools/record_golden.py`) pins the current detection result of the planted fixture
  (files, scores/verdicts, signatures, lines, sizes, sha256), the exit codes, the
  clean-fixture floor of zero findings, and the invariant that a scan never writes
  into the scanned tree. `tools/fp_measure.py` + `tests/golden/fp_baseline_synthetic.json`
  record the false-positive profile of the clean synthetic corpus (28 files, 0 flagged).
  `docs/RECON.md` maps thresholds/scoring/report fields/whitelist precedence and the
  complete inventory of disk-write locations of all four tools; `docs/OPEN_QUESTIONS.md`
  carries every unverified assumption of the plan.
- Browser GUI: a *Fetch baseline* button next to the *Clean Joomla (optional)* setting. It detects the site's exact Joomla version from its own files (`libraries/src/Version.php`, or `libraries/cms/version/version.php` on 3.x), asks `Download the clean Joomla x.y.z baseline?`, then runs `joomla_baseline.py` as a job - the official Full_Package from the `joomla/joomla-cms` GitHub releases over HTTPS, sha256/version verified, cached under `joomla-baselines` next to the scanner - with the download progress in the Log tab, and fills the setting with the unpacked folder automatically. The GUI itself still performs no downloads: the network work stays inside the standalone tool and runs only after the confirmation. Tests in `tests/test_gui.py` (detection, refusal without a site, the fetch job filling the setting - against a stub fetcher, no network).
- Browser GUI: a baseline check before every scan. Start compares the site's detected Joomla version with the version inside the loaded *Clean Joomla* folder; on a mismatch (or with no baseline at all) a dialog offers *Fetch Joomla x.y.z first* (the scan resumes automatically when the download completes), *Scan without baseline* (explicit consent; the Log states that core files are judged by heuristics only) or *Cancel*. The footer now shows the detected engines of the site - the Joomla core version plus third-party extensions that publish their version (install-manifest `<version>` or a `VERSION` define, e.g. VirtueMart) - the originals one can download freely; bundled core extensions are filtered out. The same information gets a third tab, **Engines**, in the Details/Log panel: every detected engine with its version and an original-loaded mark for the Joomla core (✓ loaded / ✗ the folder holds another version / not downloaded, with the folder path) and a *Fetch baseline* shortcut; the marks stay current as the settings or the fetched baseline change. Tests in `tests/test_gui.py` (modes ok/mismatch/no_baseline/no_engine, engines list, baseline mark in `/api/state`).
- Scanner: `--baseline-dir` pointing at a folder downloaded by `joomla_baseline.py` reuses the sha256 manifest written next to it at download time (`Joomla_<v>.baseline.json`) instead of re-hashing thousands of files; files present in the tree but missing from the manifest are hashed as before, so a hand-edited baseline can never make a modified core file look clean. Tests in `tests/test_baseline_fetch.py`.
- Browser GUI: full visual redesign to match the v3.3.1 dashboard mockup (cyber-dark by design). Self-contained hand-written CSS (no external fonts, no CDN - the strict CSP is unchanged), the user's embedded logo kept in the header, and both themes (dark default / light) persisted per browser with prefers-color-scheme honoured. Header: the Settings / Run-and-results tabs carry line icons (gear, chart), the connection badge is a bordered pill with a pulsing dot, the theme control is a round sun/moon pill (white+amber sun on light, blue moon on dark), the Quit button turns rose on hover. Run tab: a run row (Start scan with a play triangle, Stop with a square that arms rose when a job runs, a 8 px gradient progress bar blue→indigo→cyan with a hairline track, the AI cluster with a flask Candidates button and a rose count badge) and a two-row toolbar (live level chips - active chip solid blue, counts colored per level; a search box with an inset icon and a blue focus ring; an AI select; Reset; a mono right-aligned 'Showing X of Y · hidden as handled: N' counter; and the actions row Show file / Quarantine / Delete from disk (rose-tinted) / Mass cleanup / Select all, each with its mockup line icon). The results table: proportional fixed columns with the signature column absorbing the slack (no min-width, no horizontal scroll at the tab width), a non-uppercase 11 px semibold header with a blue ▼ sort arrow, solid level badges (rose HIGH, amber MEDIUM, slate LOW), mono score (light text) and mono muted line/size, 11 px mono dates, and an AI column rendered as colored text with a leading mark (⚠ threat, ✓ false positive, ? uncertain, ⚠ error, —) instead of filled cells. The details/log panel: below the table on narrow screens (230 px, a 6 px gutter handle with a blue hover glow), in a right column (one third, resizable by the gutter) on wide screens (at least 1100 px), table taking two thirds there. The details pane: full file path with a Copy chip, SHA-256 digest and signature rule cards (mono, signature amber), an AI heuristic verdict box tinted by the verdict (rose/emerald/amber/orange), and a scrollable source-snippet panel; the AI badge in the drawer header is the same colored text. Settings tab: a centered 896 px two-column grid of four cards - 1. Scan scope & targets, 2. Heuristic scoring & flags, 3. Mass cleanup, 4. AI review (local model) - with blue/amber/emerald/indigo uppercase legends, labels above monospace 12 px inputs and a blue 'Go to run →' button. The Reports popup, the context menu (208 px, flat hover rows) and the modal footer follow the mockup; toasts moved to the bottom-right above the footer. Results table: a leading checkbox column like the mockup (a per-row checkbox, a header select-all checkbox with an indeterminate state, all synced with the existing click/Ctrl/Shift selection, the Select all button and the 'N selected' counter). AI review honours the selection: with rows selected it reviews exactly the files behind them - all of them, without the 100-file cap; with no selection it reviews the whole report as before, still capped at the 100 most critical files for the sake of local models. Everything about behaviour is otherwise unchanged: same tab/JS IDs, same persistence, same endpoints, localhost-only AI, same widths and clamps (the narrow-mode gutter stays a row-resize with the fold button; only its handle was slimmed to the mockup's 6 px).
- Browser GUI: the AI cluster in the run row now keeps the review alive afterwards. A threats/errors counter appears right of the AI review button (\🤖 threats: N · ⚠ errors: M\ - real threats and errored files, both shown even when one is 0) once a review has produced verdicts; the **Candidates (K)** button shows how many signature groups the review offers (the real-threat files grouped by signature); and a separate **Remove false positives (M)** button is available at any time - not only right after the review - with the same persistence as the post-review flow (rows stay in the CSV, marked \AI Handled=false_positive\, hidden from the table). While a job runs or when the AI is disabled, the counter is hidden and the buttons are greyed out.
- Browser GUI: a wide-screen layout. At window widths of 1100 px or more the results table takes two thirds of the tab and the Details/Log panel moves into the right column (one third, resizable by dragging the gutter; the fold button is hidden there). Narrower screens keep the classic stacked layout (table on top, panel below). In wide mode the gutter drag resizes the panel by width instead of height.
- Browser GUI: a post-AI-review flow. Right after the AI review finishes, the GUI asks whether to remove the false positives from the threat list (the rows stay in the CSV, marked `AI Handled=false_positive`, and are hidden from the table; never deleted, never whitelisted) and, when real threats were found, offers to add AI-prepared signatures to the scanner's library. The proposals come from the AI itself (bounded evidence, same discipline as the review), are shown before anything is written, and are only written on your confirmation - never automatically; invalid entries are reported and skipped. The accepted library is `%USERPROFILE%\.scan_backdoors_user_signatures.json`, and the GUI passes `--user-signatures` to the scanner when the file exists and is not empty.
- Scanner: `--user-signatures FILE` loads extra signatures from a JSON library (one array, or an object with a `signatures` array). Entries are validated (label 2-200 chars, valid regex pattern 2-400 chars that does not match `""` or `" "`, severity `critical`|`obfuscated`|`warning`, kinds from `php`/`js`/`html`/`htaccess`/`ini`/`text`, optional integer weight 1-30, `flags` `i`/`none`); malformed entries are reported by number and skipped, never silently swallowed; a missing file stops the run. Scanner output: a finding line for each user-signature hit (the signature label and the line number). Regression tests in `tests/test_gui_ai.py`.
- Browser GUI: a full redesign of the Run and results tab, built around the results table as the main element of the tab. Slim top bar (logo, tabs, connection badge, a segmented dark/light sun/moon pill with the active segment filled in the same tone as the selected table rows - dark by default, persisted per browser with `prefers-color-scheme` honoured - and the Quit server button); a single run row (Start/Stop, progress bar, status line with files done, elapsed, ETA and the file currently processed, AI review, Candidates and a *Reports* dropdown menu with Open folder / Open reports / Download anchors); level chips with live per-level counts (All / High / Medium / Low, computed by the backend from the query + AI-filtered base); a search box (press `/`), an AI verdict filter and a Reset button; an actions row (Show file / Quarantine / Delete from disk / Mass cleanup); a table in its own scroll region with a sticky header, 9 fixed columns, sortable headers (Score descending by default, `▲`/`▼` arrows) and a compact AI badge column; and a resizable bottom panel with Details/Log tabs (drag the gutter to resize, double-click the gutter or the fold button to collapse, Copy log button). The AI filter offers: all / malicious (`real_threat`) / clean (`false_positive`) / not reviewed (no verdict) / hide false positives. The details pane shows the finding in a key/value grid (file, level, size, date, signature, SHA-256) plus the snippet and the AI badge/comment, and handles multi-selection. The table API now returns per-level `counts` (All / High / Medium / Low) alongside the usual totals. The Settings tab is unchanged.

- Browser GUI: an optional AI review. A new Settings section (*AI review (local model)*) enables the feature, picks the local OpenAI-compatible endpoint and the model to request (when empty, the model the gateway has loaded is discovered via its `/v1/models` endpoint and used). After the scan, the **Run and results** tab offers one button: **AI review** (the robot icon) sends each suspicious file - one request per unique path, with the finding's metadata, snippets and a bounded context, never the whole file - to the configured localhost endpoint and stores a verdict per file. The verdicts are written to new CSV columns **AI Verdict** / **AI Comment** (never overwriting the scanner's own `Verdict` column, and the `Delete` mark stays untouched), shown in the table as an AI badge, and filterable (all / malicious / clean / not reviewed / hide false positives). A second button (the test-tube icon) composes, from the real-threat verdicts, the grouped signatures with their evidence as candidates for the signature library - presented as evidence and labels, never as fabricated regexes. Only localhost endpoints are allowed (validated before any request), the review runs in-process with the same stop machinery as the other jobs, and the results persist in the CSV across restarts. Regression tests in `tests/test_gui_ai.py` (prompt contract, CSV persistence, false-positive filtering, candidates, localhost validation, error handling, dry run).
- Docs: README gains the AI review section (settings, buttons, CSV columns) and the CSV report column table documents the two new columns.

## v3.3.1 — 2026-11-28

- Browser GUI: the startup port fallback now walks a 100-port range (8765-8864 by default) instead of only 20 ports, so a port excluded by the operating system no longer makes the server die on startup. When every port in the range refuses to bind, the console says which reason was seen - EACCES (the port is excluded on Windows, or below 1024 elsewhere) with the `netsh int ipv4 show excludedportrange protocol=tcp` hint, or EADDRINUSE (the port is busy) with the actual bind errors - and exits with code 1. `--port` is validated up front (1-65535) and an invalid value exits with code 2.
- Docs: README port section explains the fallback range, the excluded-range diagnosis and how to pick a `--port` outside it. Regression tests in `tests/test_gui_port.py` (fallback, busy-port NOTE, already-running detection, invalid `--port`, all-ports-busy failure path).

## v3.3 — 2026-11-27

External code review of v3.2: findings verified against the code, fixes and
regression tests added (the reviewer's tests are adapted to the test harness).

**False negatives closed (missed backdoors):**

- Scanner: a `//` or `#` line comment no longer swallows the rest of the line
  when the line contains a closing tag: PHP ends a line comment at `?>`, so
  `<?php // note ?><?php system($_GET['c']); ?>` is masked only up to `?>` and
  the live code after it is scanned. Previously the whole line was blanked and
  the shell went unreported.
- Scanner: on detected WordPress the webshell-name exemption is now the single
  legitimate core file `wp-includes/Text/Diff/Engine/shell.php` (exact path)
  instead of the whole `wp-includes/` + `wp-admin/` folders, which also hid a
  dropped `wp-admin/c99.php`.
- Scanner: one planted `wp-load.php` no longer flips a Joomla site to "WordPress"
  (which would have switched off the Joomla-specific checks for the whole site):
  WordPress now needs a marker file *and* both core folders, and conflicting
  evidence yields `ambiguous` - CMS-specific suppressions stay off.
- Scanner: a symlink to a directory inside the web root is now reported
  ("symlink inside web root"). `os.walk` lists such links but never enters or
  reports them; a directory link is a classic place to hide a shell folder.
- Scanner and cleaner: a whitelist mask never spans folders -
  `components/com_k2/*.php` matches `components/com_k2/x.php` but no longer
  `components/com_k2/sub/x.php` (fnmatch's `*` crosses `/`). **Behaviour
  change**: existing `*`-style entries in user whitelist files cover less;
  use the trailing-slash folder form for a whole folder.
- Cleaner: `--restore` no longer trusts the manifest blindly. A file is
  restored only inside the site folder recorded in the manifest, and only if
  the quarantined copy still matches its recorded SHA-256 (the manifest lives
  next to the quarantine, where a compromised account can write); a violation
  is `[REFUSED]` with exit code 2.

**Robustness:**

- Scanner: on Python 3.6 + Windows (`--workers > 1`) the pool workers were never
  initialised (the pool `initializer` argument is 3.7+), so every file silently
  counted as an error and the scan reported nothing. The configuration now
  travels with the batch on 3.6, and an uninitialised worker fails loudly
  (`RuntimeError`) instead of returning "error" per file.
- Scanner: "PHP tag inside a None file" for unknown extensions is now "PHP tag
  inside a non-PHP file".
- Cleaner: the same no-folder-spanning mask rule as the scanner.
- Baseline: a download shorter than its `Content-Length` is refused (it used to
  be kept as the final archive), a truncated/corrupt zip is an explained error
  instead of a `BadZipFile` traceback, a download URL taken from the release
  API must be HTTPS on GitHub's own hosts (the docstring promised this, the
  code did not check), and a sha256-verified release is still cross-checked
  against the version the distribution reports.

**New options:**

- Scanner: `--audit-whitelisted` - scan files matched by a path/folder/mask
  whitelist entry and report `[CRITICAL]` hits only (off by default).
- Scanner: `--strict` - exit code 3 (instead of 0) when there are no critical
  findings but some files could not be read, i.e. the scan is incomplete.
  The summary gains a separate "Whitelisted by path (content NOT scanned)"
  counter and an INCOMPLETE warning when files could not be processed.

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
