<p align="center"><img src="assets/emblem_ScanBackDoors_512.png" alt="Scan Backdoors" width="200"></p>

# Scan Backdoors

A scanner for backdoors, web shells and malicious code on Joomla/PHP sites, with a mass-cleanup tool and a browser-based GUI.
Only Python 3.6+ is required, nothing needs to be installed (no Tk, no pip). No data ever leaves your machine: the tool only reads the folder you point it at and writes reports you ask for.

| Component | Version | What it is |
|---|---|---|
| `src/scan_backdoors.py` | 3.3.1 | The scanner: signatures, baseline diff against a clean Joomla, multi-processing, CSV/JSON/XLSX reports |
| `src/scan_backdoors_gui.py` | 3.3.1 | Browser-based GUI: a local web server on 127.0.0.1 plus one page (scan, findings, quarantine, mass cleanup) |
| `src/clean_malware.py` | 3.3.1 | Mass cleanup of known malware families, with quarantine and core-file restore from a clean distribution |
| `src/updater.py` | 3.3.1 | Signature updates: safe install, activation and rollback of YARA rule packages (HTTPS, pinned hashes, nothing is ever executed) |

The components are one product and carry one version, written once in
[`src/version.py`](src/version.py). `--version` on any of them prints the same number, so
`scan_backdoors_gui.py --version` tells you which release you are actually running.

## Repository layout

```
start.bat                     Windows launcher (double-click)
src/                          the scripts (scanner, GUI, cleaner, updater) + version.py; they must stay in one folder
engines/                      optional detection engines (YARA) + yara_check.py, the rule-set compile checker
assets/                       logo PNG and the .ico for a desktop shortcut
data/                         known-clean hash allowlist (see below)
docs/                         Russian manual (docs/README_RU.md)
tests/                        test suite: synthetic sites, planted samples, CI
```

## Known-clean allowlist

`data/whitelist-known-clean.txt` is a curated list of SHA-256 hashes of legitimate third-party files that the signatures otherwise flag (TCPDF, Akeeba `phpfinder`, VirtueMart `vrequest.php`, RSFirewall and Komento helper classes, `.phar` pubkeys and the like). Pass it to the scanner to silence those findings:

```
python3 src/scan_backdoors.py /path/to/site --whitelist data/whitelist-known-clean.txt
```

In the GUI, set the same file as *Whitelist* on the **Settings** tab. Entries are hashes plus a comment explaining why the file is clean; the false positives of your own project are welcome as pull requests.

## Where the tools keep their data

Everything the tools keep between runs lives in ONE folder: **`$SBD_DATA_DIR`**, or `~/.scan_backdoors` when that variable is empty (on Windows `%USERPROFILE%\.scan_backdoors`). Never next to the code, never inside a scanned site.

```
<data>/yarac/                the compiled .yarac rule cache (scanner --yara-cache)
<data>/whitelist.txt         the file the GUI's "Add to whitelist" appends to (until you pick another one)
<data>/joomla-baselines/     baselines downloaded by joomla_baseline.py (also the GUI's *Fetch baseline*)
<data>/signatures/           installed rule releases + ACTIVE + manifest.json + sources.json (updater.py)
<data>/logs/updater.log      what the updater did (rotating, secrets masked)
```

The GUI moves what older versions kept next to the scanner (`whitelist.txt`, `joomla-baselines/`) into this folder on startup and updates its own settings accordingly; the scanner does the same with a rule cache left in the temp folder, and `joomla_baseline.py` with a cache left next to itself. Nothing is merged or deleted: an existing destination wins and the old copy simply stays where it is (a baseline that turns out to be missing is downloaded again, a missing cache is rebuilt). Pointing `SBD_DATA_DIR` at a folder on a USB stick or a scratch disk is fine - the tools only ever put their own files there.

## Launching

The scripts in `src/` must stay in the same folder: the GUI looks for `scan_backdoors.py` next to itself, uses `clean_malware.py` next to the scanner, and `updater.py` next to itself for signature updates.

| File | Purpose |
|---|---|
| `start.bat` | Windows launcher for the GUI |
| `src/scan_backdoors_gui.py` | Browser-based GUI: a small local web server plus a page in your browser (scan, results table, quarantine/delete, mass cleanup) |
| `src/scan_backdoors.py` | The scanner (command line) |
| `src/clean_malware.py` | Mass cleanup (command line; also used by the GUI "Mass cleanup" button) |
| `src/updater.py` | Signature updates for the optional YARA engine (see below) |

Optional files: `assets/emblem_ScanBackDoors_512.png` (the logo; the GUI has a small copy of it built in, so it works without this file) and `assets/scan_backdoors.ico` (an icon for a desktop shortcut to `start.bat`: right-click the shortcut, *Properties*, *Change Icon…*, choose this file).

### Windows: `start.bat`

Double-click `start.bat`. It switches to its own folder, finds Python (`py -3`, otherwise `python`), starts `src\scan_backdoors_gui.py` and your default browser opens the page.
If Python is not found, or the server exits with an error, the window stays open with a hint.

Requirements: Python 3.6+ (tick "Add python.exe to PATH" in the installer from python.org).
Keep the console window open while you work: closing it stops the server. You can also stop it with the **Quit server** button in the page.

### Any OS: `scan_backdoors_gui.py`

```
python3 src/scan_backdoors_gui.py                 # start and open the browser
python3 src/scan_backdoors_gui.py --no-browser    # start without opening the browser
python3 src/scan_backdoors_gui.py --port 9000     # use another port
python3 src/scan_backdoors_gui.py --self-test     # doctor: settings, scanner, save paths (no browser)
```

A path field that does not check out (missing scanner, missing save folder, unreadable settings file) is reported in the boot log by field name; a scan or cleanup job is refused until it is fixed.

### Open it from a browser bookmark

The server always uses the same address, **http://127.0.0.1:8765/** (the port is fixed on purpose). Bookmark it and the page opens from the bookmark whenever the server is running.
Starting the script a second time while it is already running does not start another copy, it only opens the page again.
If port 8765 is taken by another program or excluded by the operating system, the next free port in a 100-port range from it (8765-8864) is used and the console prints the new address and the reason (the bookmark then has to be updated). If every port in that range is unusable, the console explains why and exits with code 1.

On Windows, ports in the excluded range cannot be bound at all. List them with:

```
netsh int ipv4 show excludedportrange protocol=tcp
```

Pick a `--port` outside the excluded range, e.g. `--port 8800`, and start the GUI with it; the printed address is then stable. On Linux/macOS, values below 1024 need elevated privileges - pick a port at or above 1024.

An invalid `--port` (below 1 or above 65535) is rejected up front with exit code 2.

To have the server running all the time without a console window, on Windows put a shortcut to `pythonw src\scan_backdoors_gui.py --no-browser` into the Startup folder (`Win+R`, `shell:startup`).
The page remembers the last state (log, results) while the server runs, so you can close and reopen the tab at any moment.

### Security

- The server listens on **127.0.0.1 only**, it is not reachable from other computers.
- Requests are accepted only for the host names `127.0.0.1`/`localhost` on its own port (protects against DNS rebinding) and only with a custom header and a JSON body (protects against requests from other web sites).
- File names and code snippets from the scanned site are shown as plain text, never as HTML.
- To use the GUI on a remote server, do not open the port, use an SSH tunnel instead: `ssh -L 8765:127.0.0.1:8765 user@server`, then open http://127.0.0.1:8765/ locally.

### First run in the GUI

1. **Settings** tab: choose the *Site folder* (optionally a *Clean Joomla* folder, a *Whitelist* and the report paths). No clean copy of the same version at hand? The *Fetch baseline* button next to the *Clean Joomla (optional)* field detects the site's Joomla version from its own files, asks you to confirm (`Download the clean Joomla x.y.z baseline?`), downloads the official Full_Package from the `joomla/joomla-cms` GitHub releases over HTTPS with progress in the Log tab, and fills the field in automatically. This is the only part of the app that reaches the internet, and only after that confirmation. The tab is a centered two-column grid of five cards — *1. Scan scope & targets* (paths), *2. Heuristic scoring & flags* (thresholds, exclusions, flags), *3. Mass cleanup* (mode, family, core-file restore), *4. AI review (local model)* (endpoint, model, flags) and *5. CMS audit* (inventory, WordPress core integrity, known vulnerabilities, and the separate tick that allows the two audit services to be asked) — with a *Go to run →* button in the header. **Browse…** opens a file chooser that lists the folders of the machine where the server runs.
2. **Run and results** tab: press *Start scan*. Before the scan starts the GUI checks that the loaded *Clean Joomla* folder matches the site's detected Joomla version; on a mismatch (or when no baseline is set) it offers to fetch the matching baseline first - the scan then resumes automatically when the download finishes - or to scan without originals with your consent (core files are then judged by heuristics only, and the Log says so). The footer shows what the site runs: the detected Joomla version plus third-party engines that publish their version (VirtueMart and similar extensions whose originals are freely downloadable). The Details/Log panel has a third tab, **Engines**, listing every detected engine with its version and an original-loaded mark for the Joomla core (✓ loaded, ✗ the Clean Joomla folder holds another version, or not downloaded, with the folder path) and a *Fetch baseline* shortcut; the same tab shows the installed YARA signature package (active release, rule count, verified/not verified, update date) with *Update signatures* and *Roll back to the previous package* buttons - both run `updater.py` as a background job after a confirmation, and a scan then uses the installed rules automatically. A baseline downloaded through the GUI makes the next scan faster: the scanner reuses the sha256 manifest `joomla_baseline.py` wrote at download time instead of re-hashing the baseline tree. The tab is built around the results table in a self-contained, dark-first theme (light mode available; both persisted per browser, `prefers-color-scheme` honoured, no external fonts or CDNs): a slim top bar with the embedded logo, the icon-bearing Settings / Run and results tabs, a connection badge, a round dark/light sun/moon pill and the *Quit server* button; below it a run row (Start/Stop, progress bar, status line with files done, elapsed, estimated remaining time and the file currently processed, *AI review* with a threats/errors counter next to it, a *Remove false positives* button, *Candidates* with a count of the signature groups it offers and a *Reports* menu); a two-row toolbar — live level chips (All / High / Medium / Low with colored per-level counts, computed by the backend from the query + AI-filtered base), a search box (press `/`), an AI verdict filter and a Reset button on the first row, the actions row (Show file / Quarantine / Delete from disk / Mass cleanup / Select all, each with a line icon) on the second; and, in its own scroll region with a sticky table header, a table that is almost the whole tab. On wide screens (at least 1100 px) the table takes two thirds of the tab and the Details/Log panel sits in the right column (one third, resizable by dragging the gutter) instead of underneath the table; the fold button is hidden there, because the panel no longer collapses vertically. On narrower screens the layout is the classic stacked one: table on top, panel below it. Click a column header to sort (Score sorts descending by default).
3. Select rows (click, Ctrl/Shift+click, Ctrl+A, or the leading checkboxes — the header checkbox selects or clears all visible rows) and the Details/Log panel — below the table on narrow screens, in the right column on wide screens — shows the selected finding: the full file path with a Copy button, the SHA-256 digest and the signature rule as cards, an AI heuristic verdict box with the badge and the comment, and the source snippet in a scrollable panel (the AI column in the table itself is colored text — ⚠ threat / ✓ false positive — and the verdict box is tinted to match; the level column uses solid rose/amber/slate badges). Switch between the **Details** and **Log** tabs; drag the gutter to resize the panel, double-click the gutter or the fold button to collapse it. Use *Show file*, *Quarantine*, *Delete from disk* (or the Delete key) or the right-click menu (copy path, copy SHA-256, add to whitelist). *Mass cleanup* handles the known malware families across the whole site: it first shows a plan and asks for confirmation. The level chips and the search/AI filters combine — the chip counts stay live and reflect the current query and AI filter.
4. Open the reports (CSV/XLSX/JSON) with the *Reports* menu (*Open reports folder* for the folder, then *Open CSV/XLSX/JSON* to open a report, or the *Download CSV/XLSX/JSON* anchors to save one through the browser).

Settings are saved automatically in `~/.scan_backdoors_gui.json` (the same file the older desktop version used). The command-line options are described below.


### CMS audit in the GUI

Section *5. CMS audit* on the Settings tab has four independent ticks: *Inventory of the installed components*, *WordPress core integrity*, *Known vulnerabilities of the components* and *Allow the two audit services to be asked*. All four default to off, so a scan from the GUI is what it always was. Only the last tick lets anything leave the machine, and what leaves it is the WordPress version and the plugin/theme names and versions the scan found — no site name, no paths, no file contents; answers are cached for a day in the data folder. The GUI logs the exact command line of every scan, so the ticks are checkable in the Log tab.

After a scan with the audit on, the bottom panel gets a fourth tab, **Vulnerabilities**: the CMS and its components at the top, the core-integrity counts under it (verified / modified / extra / missing), and one row per verdict — component, version, CVE, CVSS, severity, KEV, fixed in, confidence, source. Click a column header to sort, tick *only known exploited (KEV)* to filter, and the panel states in its own words what the audit could not do (an offline run says so plainly). The verdicts are **not** rows of the findings table: they have no checkbox, and *Quarantine*, *Delete from disk* and *Mass cleanup* are not offered for them — the fix for a known vulnerability is to update the component, not to delete a file. Modified and unexpected core files found by the integrity check *are* ordinary findings and are in the table like any other suspicious file, and a `WordPress integrity` notice points at them.

### AI review (local model)


After a scan, the **Run and results** tab offers two optional actions:

* **🤖 AI review** — sends each suspicious file (one request per unique path, the highest-priority finding of each) to a local AI endpoint you choose, and stores a verdict per file. If rows are selected in the table, the review covers exactly the files behind the selection — all of them, without the 100-file cap; with no selection it covers the whole report, capped at the 100 most critical files. Only *localhost* endpoints are allowed (`127.0.0.1`, `localhost`, `[::1]`), the endpoint is validated before any request is sent, and the request carries the evidence — the finding's metadata, snippets and a bounded context — never the whole file. The verdict lands in the CSV report in the columns **AI Verdict** / **AI Comment** (the scanner's own `Verdict` column is never overwritten), and in the table as an AI badge. The table filter **AI** offers: all rows, malicious only (`real_threat`), clean only (`false_positive`), not reviewed yet (no verdict) and hide false positives (everything except `false_positive`).
* **🧪 Candidates for the signature library** — composes, from the real-threat verdicts, the grouped signatures with their evidence (files, lines, snippets, AI comments) as candidates for the scanner's signature library. The candidates are presented as evidence and labels, *not* as fabricated regexes — review them and add the confirmed ones by hand; the scanner is never modified automatically.

Right after the review finishes, the GUI asks two more questions (neither is applied without confirmation):

* **Remove false positives from the threat list?** — if the review marked files as `false_positive`, the GUI asks whether to remove them from the threat list. The rows are hidden from the table and kept in the CSV report, marked `AI Handled=false_positive`. They are never deleted, and the whitelist is never touched — a later scan still lists the rows; only this AI-review-era list changes.
* **Add AI-prepared signatures to the library?** — if the review found real threats, the AI is asked, per real-threat file, to prepare one scanner signature (the same bounded-evidence discipline as the review). The proposals are shown, and only on your confirmation are they written to the user signature library (`%USERPROFILE%\.scan_backdoors_user_signatures.json`, a separate JSON file). The scanner reads that library on the next scan via `--user-signatures` (the GUI passes the flag automatically when the file exists and is not empty). Nothing is written otherwise.

The run row keeps the AI cluster alive afterwards: once a review has produced verdicts, a counter appears right of the AI review button (`🤖 threats: N · ⚠ errors: M` — the number of real threats and the number of errored files; both numbers are shown even when one is 0), the **Candidates (K)** button shows how many signature groups the review offers (the real-threat files grouped by signature), and a separate **Remove false positives (M)** button is available at any time — not only right after the review — with the same persistence as the post-review flow: the rows stay in the CSV report, marked `AI Handled=false_positive`, and are only hidden from the table. While a job runs or when the AI is disabled, the counter is hidden and the buttons are greyed out.

The settings live on the Settings tab (section *AI review (local model)*):

| Setting | Meaning |
|---|---|
| Enable AI review | Turn the feature on/off. When disabled, the AI buttons are greyed out. |
| Endpoint | The local OpenAI-compatible base URL (e.g. `http://127.0.0.1:8080/v1`). Only `http`/`https` URLs on localhost are accepted, without credentials, query string or fragment. |
| Model | The model to request (optional). When empty, the model the gateway has loaded (queried from its `/v1/models` endpoint) is used. |


## Command line

```
python3 scan_backdoors.py [folder] [options]
```

The examples below are written as if you are inside the `src/` folder; run them from the repository root, prefix the script with `src/` (and the allowlist with `data/`).

If no folder is given, the current one is scanned. **All** folders are checked by default, including `cache`, `tmp`, `logs`, `media`.

---

## Quick start

```bash
# Regular check: the report goes to report-data.csv
python3 scan_backdoors.py /home/user/site

# Only the most dangerous findings, last 14 days
python3 scan_backdoors.py /home/user/site --since 14d --only-critical

# Most accurate check: comparison with a clean Joomla + the shipped known-clean allowlist
python3 scan_backdoors.py /home/user/site --baseline-dir /tmp/Joomla_5.1.0 \
    --whitelist data/whitelist-known-clean.txt
```

---

## Options

### What to scan

| Option | Default | Description |
|---|---|---|
| `folder` (positional) | `.` | Site root. |
| `--max-size MB` | `5` | Files larger than this are not read. A PHP file above the limit is not skipped silently, it is flagged as `[OBFUSCATED]`. |
| `--since DATE` | off | Check only files modified after the date. Format: `2026-09-01` or `14d` (last 14 days). |
| `--exclude-ext LIST` | empty | Comma-separated extensions that are not checked. The leading dot is optional. |
| `--exclude-dir LIST` | empty | Folder names that are not entered (at any nesting level). All folders are scanned by default. |

```bash
python3 scan_backdoors.py . --max-size 10
python3 scan_backdoors.py . --since 2026-09-01
python3 scan_backdoors.py . --since 7d
python3 scan_backdoors.py . --exclude-ext .js,.json,xml
python3 scan_backdoors.py . --exclude-dir vendor,node_modules
```

> `--since` is handy after a compromise: it shows what has changed since the infection.

### What to look for

| Option | Description |
|---|---|
| `--only-critical` | Search only for `[CRITICAL]`. The fastest mode, minimum noise. |
| `--no-warnings` | Do not search for `[WARNING]` (single `$_POST`, `eval(` and the like; a clean Joomla has plenty of them). |
| `--min-score N` | Show only files with a score of at least `N` in the report. Default `0`. |

```bash
python3 scan_backdoors.py . --only-critical
python3 scan_backdoors.py . --no-warnings --min-score 10
```

### Reports

| Option | Default | Description |
|---|---|---|
| `--csv PATH` | `report-data.csv` | CSV report. Always created unless `--no-csv` is given. |
| `--no-csv` | | Do not create the CSV. |
| `--xlsx PATH` | off | Additionally save the report as Excel (sheets Files, Hits, Summary). |
| `--json PATH` | off | Full report as JSON (for scripts and automation). |
| `--sarif PATH` | off | Report as SARIF 2.1.0 for CI code scanning (GitHub, Azure DevOps, CodeQL upload). |
| `--max-matches N` | `60` | Maximum findings of one level per file in the report. The overall counters include all findings. |

```bash
python3 scan_backdoors.py . --csv /tmp/scan.csv
python3 scan_backdoors.py . --xlsx report.xlsx --json report.json
python3 scan_backdoors.py . --no-csv --json report.json
python3 scan_backdoors.py . --no-csv --sarif report.sarif
python3 scan_backdoors.py . --max-matches 20
```

### Reducing false positives

| Option | Description |
|---|---|
| `--whitelist FILE` | A file with exclusions (format below). |
| `--audit-whitelisted` | Do not skip files matched by a path/folder/mask whitelist entry: scan them and report `[CRITICAL]` hits only. A path-based entry normally keeps the file's content out of the scan entirely; this flag is for whitelisted folders (say, a vendor directory) that must stay quiet for everything except a real web shell. Off by default. |
| `--baseline-dir FOLDER` | A folder with a **clean** Joomla of the same version (where `index.php` lives). Files that match by SHA-256 are skipped as clean. Modified and extra files in `libraries/`, `includes/`, `administrator/includes/` and in the root are flagged. |

```bash
python3 scan_backdoors.py /home/user/site --baseline-dir /tmp/Joomla_5.1.0
python3 scan_backdoors.py /home/user/site --whitelist whitelist.txt
```

**`whitelist.txt` format** (one entry per line, `#` starts a comment):

```text
# SHA-256 of a specific file
5a854ecf8072125e4fabdad558afb7c5fcca486d18107dc8af9d7add60f2c25c

# exact path from the site root
templates/mytpl/helper.php

# a whole folder (trailing slash)
libraries/vendor/

# a mask
components/com_k2/*.php
```

A mask never spans folders: `components/com_k2/*.php` matches `components/com_k2/x.php` but not `components/com_k2/sub/x.php`. For a whole folder use the trailing-slash form (`libraries/vendor/`) instead.

A line that is neither a 64-hex hash nor a path (a hex string of another length, binary garbage) is reported by line number and skipped; the scan goes on. A whitelist file that cannot be read at all still stops the run.

### User signatures (AI-prepared or hand-written)

The scanner can load extra signatures from a JSON library. The GUI's signature flow writes this file automatically (confirmed by you); you can also create it by hand.

| Option | Description |
|---|---|
| `--user-signatures FILE` | Extra signatures to load (one JSON array, or an object with a `signatures` array). Entries are validated: a malformed entry is reported and skipped, never silently swallowed. A missing file stops the run. |

```bash
python3 scan_backdoors.py /home/user/site --user-signatures my-signatures.json
```

**Library format** (one entry per signature):

```json
[
  {"label": "my-webshell", "pattern": "some_literal_or_regex",
   "severity": "critical", "kinds": "php", "weight": 25,
   "flags": "i", "reason": "why this signature matches"}
]
```

* `label` (2-200 chars; the GUI writes 2-120), `pattern` (valid regex, 2-400 chars, must not match `""` or `" "`), `severity` (`critical`, `obfuscated` or `warning`), `kinds` (at least one of: `php`, `js`, `html`, `htaccess`, `ini`, `text`, space-separated), `weight` (optional, integer 1-30), `flags` (`i` for case-insensitive, the default when omitted; `none` for case-sensitive), `reason` (optional, up to 400 chars), `created` (ISO date, set by the GUI).
* Entries are validated on load; the scanner never crashes on a broken pattern.
* The GUI writes its confirmed proposals to `%USERPROFILE%\.scan_backdoors_user_signatures.json` (you can inspect the file; entries with the same label and pattern are replaced, not duplicated) and passes `--user-signatures` on the next scan when the file exists and is not empty.

### YARA rules (optional extra engine)

The scanner can additionally run [YARA](https://github.com/VirusTotal/yara) rule files as one more detection engine. This is fully optional: without `--yara-rules` nothing changes, and without the `yara-python` package installed the scanner prints that the YARA engine is OFF and scans with the built-in heuristics exactly as before (`pip install -r requirements-optional.txt` adds it).

| Option | Default | Description |
|---|---|---|
| `--yara-rules PATH` | | A `.yar`/`.yara` file, or a folder of them (non-recursive). Every hit appears as a signature `YARA: <file>.<rule>`. A rule's `meta` may set `severity` (critical/high/medium/low/…) and `score` (1-50); a rule without meta is always a `[WARNING]`. Rules may use the bound externals `file_name`, `extension`, `path`, `folder`, `file_size`, `cms`, `wp_root`, `joomla_root`, `rule_language`. A rule file that fails to compile is reported and skipped - the rest keep working. `include` directives are refused: every rule file must stand on its own. |
| `--no-yara` | | Never run the YARA engine, even with `--yara-rules` given. |
| `--yara-cache DIR` | `<data>/yarac` | Folder for the compiled `.yarac` cache (keyed by rule content; a corrupt cache file is rebuilt automatically). `<data>` is `$SBD_DATA_DIR` or `~/.scan_backdoors` (see [Where the tools keep their data](#where-the-tools-keep-their-data)); an old cache left in the temp folder is moved there automatically. |
| `--no-yara-cache` | | Do not read or write the `.yarac` cache; compile in every process. |
| `--yara-timeout SEC` | `5` | Per-file time limit for the YARA scan. A file that hits the limit is reported as a scan gap (`[WARNING]` hit + a STATISTICS line), never as clean. |

```bash
python3 scan_backdoors.py /home/user/site --yara-rules /path/to/rules/
```

An installed signature package is the ready-made argument: `--yara-rules "$(python3 src/updater.py --rules-path)"` (see [Signature updates](#signature-updates-updaterpy)); the GUI passes it automatically when a release is installed.

Scan-gap semantics matter: yara-python silently returns incomplete matches when a rule hits its timeout, so the scanner double-checks the elapsed time itself and flags any file that ran up to the limit. Statistics show `YARA: rules loaded / files scanned / scan gaps`.

### CMS audit: inventory, integrity, known vulnerabilities

Three related passes over what is installed, as opposed to what is inside a file. All three are off by default: a normal scan does exactly what it did before, reads nothing about the CMS beyond its own heuristics and makes no requests.

| Option | Default | Description |
|---|---|---|
| `--inventory` | | List the CMS and its components (WordPress: core, plugins, mu-plugins, themes; Joomla: version and extensions). A version is only what the component **declares** (`Version:` header, `style.css`, `*.xml` manifest); a component that declares nothing is reported as "version unknown", never as clean. Manifests are hostile input: XML with a `DOCTYPE`/`ENTITY` is refused, nothing of the site's PHP is executed, symlinks are not followed, and the scanner never writes inside the scanned site. |
| `--check-integrity` | | Compare WordPress core files with the **official checksums** from `api.wordpress.org`: which files match, which are modified, which files the official release does not ship (in `wp-admin/`, `wp-includes/`, code in the root, inside a shipped component), which are missing. A modified core file or a new PHP file in `wp-admin/` becomes an ordinary `[CRITICAL]` finding on that file: it gets a score, appears in the table, can be quarantined. A missing file is reported in the integrity section only — there is nothing to quarantine. `readme.html`, `license.txt` and `wp-config-sample.php` are translated or reworded by distributors and are reported separately, never as suspicious. Plugin/theme checksums do not exist upstream, so components have no reference file and are not part of this check. |
| `--audit-cve` | | Report the **known vulnerabilities** of the inventoried components: first the local database (`--vuln-db`), then, with `--online`, the WPVulnerability service. These findings are a section of their own in every report format (JSON `vulnerabilities`, a `Vulnerabilities` sheet in XLSX, a separate `<report>-vulnerabilities.csv` beside the findings CSV - never a block inside it, since that file is read back as findings, SARIF results whose `ruleId` is the CVE) and they are never offered for quarantine or delete: an outdated plugin is not a piece of malware. Joomla extensions have no verified public feed yet, so a Joomla audit is local-database only. |
| `--online` | | Allow the two pinned services that `--check-integrity` and `--audit-cve` need: `api.wordpress.org` and `api.wpvulnerability.com`. Without it only the one-day cache and the local database are used, and the report says exactly what could not be checked. **What leaves the machine:** the WordPress version it found, and every plugin/theme slug and version it found. Nothing is uploaded, no site name, no path, no file contents. HTTPS only, host allowlist re-checked after every redirect, response size caps, a per-run request budget, answers cached for 24 h in the data folder (so the next run of the same site works offline). No telemetry, no other host. |
| `--vuln-db FILE` | `<data>/audit/vulnerabilities.json` | Local vulnerability database (JSON, schema 2) used by `--audit-cve`. It ships empty on purpose: the scanner will not invent CVE data, and an audit against an empty or missing database says so. A broken entry is dropped with a note, never guessed at. |
| `--fail-on LEVEL` | | Exit with code `4` when a vulnerability verdict reaches `critical`, `high` or `medium`. Without this option a CVE **never** changes the exit code. Requires `--audit-cve`; a verdict whose version could not be read ("unauditable") never fails a run. |

```bash
python3 scan_backdoors.py /home/user/site --inventory --check-integrity --audit-cve --online
python3 scan_backdoors.py /home/user/site --audit-cve --fail-on high          # CI, offline, local DB only
```

The console gets a `CMS AUDIT` block after the findings; `STATISTICS` gains `CMS`, `CMS version`, `Components inventoried`, `WordPress core: verified/modified/extra/missing`, `Vulnerabilities: verdicts / known exploited (KEV) / unauditable components`. In JSON, `integrity.verified_for_skipping` counts the files proven identical to the release; files that differ are never treated as clean, whatever else the run concluded. If the integrity pass flags the file the CMS version was read from (`wp-includes/version.php`), every vulnerability verdict in that run is downgraded to low confidence: a hacked site can lie about which version it is.

### Performance and output

| Option | Default | Description |
|---|---|---|
| `--workers N` | `0` (auto) | Number of processes. `0` = auto (up to 4), `1` = no parallelism. If parallel mode is unavailable on the host, the script falls back to a single thread by itself. |
| `--strict` | | Exit with code `3` (instead of `0`) when there are no `[CRITICAL]` findings but some files could not be read: the scan is incomplete and "clean" is not proven. For CI/cron. |
| `--no-progress` | | Do not show the progress indicator. |
| `--progress-lines` | | Print machine-readable lines `@@PROGRESS`, `@@FILE`, `@@STATS`, `@@DONE`. Needed by the GUI (progress bar, report buttons); works without a terminal too. |
| `--self-test` | | Run the built-in liveness check: four embedded test payloads are unsealed into a throwaway folder under `%TEMP%/sbd-fixtures` (the antivirus exclusion folder) and each must be detected. Exit 0 if all are detected. |
| `--version` | | Show the version. |
| `-h`, `--help` | | Option help. |

```bash
python3 scan_backdoors.py . --workers 1
python3 scan_backdoors.py . --workers 4 --no-progress
```

---

## CSV report columns

| Column | Meaning |
|---|---|
| Score | The file score (the higher, the more dangerous). The report is sorted in descending order. |
| Verdict | `HIGH`, `MEDIUM` or `LOW`. |
| Severity | `[CRITICAL]`, `[OBFUSCATED]` or `[WARNING]`. |
| File | File path from the site root. |
| Line | Line number (empty for findings by name, location or binary content). |
| Signature | Name of the signature that fired. |
| Snippet | A code fragment with the finding. |
| Size | Size in bytes. |
| Modified | File modification date. |
| Delete | Your own mark. `No` everywhere by default, change it to `Yes` after review. |
| SHA-256 | File hash (for the whitelist and for lookups in online databases). |
| AI Verdict | The AI's verdict for the file: `real_threat`, `false_positive`, `uncertain` or `error`. Empty when the file was not reviewed - the scanner's own `Verdict` column is untouched and never overwritten. |
| AI Comment | The AI's short evidence for the verdict (truncated to 1200 characters). |
| AI Handled | The GUI's mark: alse_positive means the rows are hidden from the table (they stay in the CSV; never delete them by hand). |

---

## Levels and scores

**Finding severity**

| Level | Meaning | Default score |
|---|---|---|
| `[CRITICAL]` | Almost certainly malware: eval of `$_POST`, names of known shells, PHP in an image, `auto_prepend_file`. | 10 (obvious signs: 15 to 30) |
| `[OBFUSCATED]` | Decoding chains, suspicious names, long lines, high entropy. | 3 |
| `[WARNING]` | Single primitives (`$_GET`, `exec(`). Common in a clean Joomla. | 1 |

**File verdict:** `HIGH` from a score of 25, `MEDIUM` from 10, otherwise `LOW`.

What the script additionally checks:
- PHP code inside images, fonts and CSS;
- double extensions (`image.php.jpg`) and backups (`.php.bak`, `.suspected`);
- PHP in `images/` and `tmp/`;
- extra code in `configuration.php` after `class JConfig`;
- dangerous rules in `.htaccess` (`auto_prepend_file`, `AddType` for images, cloaking by User-Agent and Referer).

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No critical findings |
| `2` | There are `[CRITICAL]` findings |
| `3` | With `--strict`: no critical findings, but some files could not be read (incomplete scan) |
| `4` | With `--fail-on LEVEL`: a known-vulnerability verdict reached that severity and nothing was `[CRITICAL]`. Only `--fail-on` can produce this code. |
| `1` | Startup error (folder not found, invalid option format) |

Automation example (cron, CI):

```bash
python3 scan_backdoors.py /home/user/site --only-critical --no-csv --json /tmp/scan.json
if [ $? -eq 2 ]; then echo "Critical files found!" | mail -s "Alert" admin@example.com; fi
```

---

## Recommended workflow

1. Download a clean Joomla of the same version and unpack it, for example into `/tmp/Joomla_clean`.
2. Run a full scan: `python3 scan_backdoors.py /home/user/site --baseline-dir /tmp/Joomla_clean`.
3. Open `report-data.csv` and review `HIGH` first.
4. Add the legitimate files of third-party extensions to `whitelist.txt`.
5. Delete the infected files or restore them from a clean copy, and mark `Yes` in the "Delete" column.
6. Repeat the scan until no critical findings remain, and change the passwords (admin panel, FTP, database).
7. Later, run it regularly: `--since 7d --only-critical`.

---

# clean_malware.py: mass cleanup

Recursively finds and removes **known malicious** files of known families. It works by content, not only by name. Files whose name is on the list but that have no signatures are shown for manual review and are not touched.

```
python3 clean_malware.py /path/to/site                  # 1. dry run: nothing is changed
python3 clean_malware.py /path/to/site --apply          # 2. move to quarantine (can be rolled back)
python3 clean_malware.py --restore /path/_quarantine_.../manifest.json   # rollback
python3 clean_malware.py /path/to/site --apply --delete # delete permanently
```

| Option | Default | Description |
|---|---|---|
| `folder` | `.` | Site root. A disk root is rejected. |
| `--apply` | off | Without it only the plan is shown. |
| `--delete` | off | Delete permanently, without quarantine. |
| `--families` | `htaccess,backdoor` | `htaccess` (`.htaccess` locks), `backdoor` (the `BiaoJiOk` marker, goto/eval loaders, a tiny `index.php` with `include base64_decode("…")` and its payload in `.flv`/an image), `filemanager` (web file managers without authentication, like `elp.php`). |
| `--htaccess-mode` | `clean` | `clean`: cut out only the malicious blocks, keep the legitimate rules (if nothing is left, the file is deleted). `delete`: delete the whole file. |
| `--quarantine-dir` | next to the site | Where to put the copies. Must be outside the site folder. |
| `--exclude-dir` | empty | Folder names to leave alone. |
| `--whitelist` | off | The same format as in the scanner: SHA-256, paths, folders (trailing `/`), masks `*`. |
| `--report` | `cleanup-report.csv` | CSV: status, family, action, file, size, hash, error. |
| `--restore MANIFEST` | | Restore files from quarantine. For cleaned `.htaccess` files it restores the original content. The manifest is not trusted blindly: a file is restored only inside the site folder recorded in the manifest, and only if the quarantined copy still matches its recorded SHA-256. A tampered manifest or a swapped quarantine copy is refused (`[REFUSED]`, exit `2`). |
| `--replace-core` | off | Replace modified Joomla core files with originals from `--baseline-dir`. `--apply` is required to execute. The modified file is kept in quarantine (`*.modified`), the original is written over it in place (owner and permissions are kept), the hash is verified after writing. |
| `--baseline-dir` | | A folder with a clean full Joomla distribution of the **same version** (where `index.php` lives). |
| `--core-ext` | `.php,.js,.html,.htm` | Extensions that are replaced. Language `.ini` files are not touched by default (translators edit them). |
| `--max-modified-percent` | `30` | If more than N% of core files are "modified", the replacement is cancelled: most likely the baseline is of a different version. |
| `--force-version` | off | Skip the version and percentage checks (**dangerous**). |
| `--no-media` | off | Do not check images/video for PHP code inside (faster on large sites). By default `.jpg .png .gif .ico .flv .mp3 .mp4` and others are checked. |
| `--progress-lines` | | Service lines `@@...` for the GUI. |
| `--self-test` | | Run the built-in liveness check: one sample per family (htaccess / backdoor / filemanager) is unsealed into a throwaway folder under `%TEMP%/sbd-fixtures` and must be recognized. Exit 0 if all are recognized. |

**How it stays safe:** quarantine with hash verification before deletion; files with 0444 permissions and 0555 directories are handled (directory permissions are restored); symbolic links are skipped; a repeated run finds nothing.

Exit codes: `0` success, `1` startup error (including a baseline version mismatch), `2` some files could not be processed or a `--restore` entry was refused.

**Replacing core files (example):**
```
python3 clean_malware.py /path/to/site --replace-core --baseline-dir /tmp/Joomla_5.1.2        # plan
python3 clean_malware.py /path/to/site --replace-core --baseline-dir /tmp/Joomla_5.1.2 --apply  # execute
```
Safeguards: the site and baseline versions must match (otherwise it refuses); if more than 30% of files are modified, the replacement is cancelled; files that are not in the baseline (extensions, templates, `configuration.php`) are not touched; files from `--whitelist` (your own core edits) are not replaced. Extra files in `libraries/`, `includes/`, `administrator/includes/` (not in the baseline) are only listed for manual review. Rollback: `--restore .../manifest.json`.

**In the GUI:** the "🧹 Mass cleanup" button on the results tab. First a dry run with the numbers, then a confirmation, then the cleanup. The mode (quarantine or permanent), the `filemanager` family and the "Replace modified core files with originals" checkbox (it takes the "Clean Joomla" folder from the settings) are set on the "Settings" tab. `clean_malware.py` must be placed next to the scanner.

---

## Getting a clean Joomla baseline (`joomla_baseline.py`)

```
python3 joomla_baseline.py 3.9.27
```

downloads the official Joomla 3.9.27 Full_Package from the `joomla/joomla-cms` GitHub releases, verifies it (the API sha256 digest when the API provides one, otherwise the version of the unpacked distribution must match the request), unpacks it, and writes a hash manifest:

```
<data>/joomla-baselines/Joomla_3.9.27/                <- pass this folder as --baseline-dir
<data>/joomla-baselines/Joomla_3.9.27.baseline.json   <- manifest: every file and its sha256
```

| flag | meaning |
|---|---|
| `--out DIR` | cache directory (default: `joomla-baselines` inside the [data folder](#where-the-tools-keep-their-data); a cache that still lives next to the script is moved there once) |
| `--force` | re-download even when the cached baseline is valid |
| `--keep-archive` | keep the downloaded zip |

The scanner uses the manifest directly: with `--baseline-dir` pointing at a downloaded folder it reuses the recorded hashes instead of re-hashing thousands of files (files missing from the manifest are hashed on the spot, so a hand-edited baseline can never make a modified core file look clean). A re-run verifies the cached baseline offline (no network) and re-downloads only if a file changed. The resulting folder is accepted by both `scan_backdoors.py --baseline-dir` and `clean_malware.py --replace-core --baseline-dir`. The tool talks to `api.github.com` and GitHub's download CDN over HTTPS only: a download URL taken from the release API must point at those hosts, a truncated download (fewer bytes than `Content-Length`) and a corrupted archive are reported as a clear error, never left behind as a partial baseline.

---

## Signature updates (`updater.py`)

`updater.py` installs YARA rule packages for the optional [YARA engine](#yara-rules-optional-extra-engine), so the rule set can grow between releases of the tool. It is deliberately conservative: a rule set becomes active only as a whole (`atomic` — the last step is switching a pointer), only after it has passed integrity and compile checks, and the previous release always stays on disk for a rollback. Nothing that is downloaded is ever executed — rule files are only compiled by `yara-python` in a checked subprocess.

```
python3 updater.py --update-signatures              # the project's own package (URL pinned in sources.json)
python3 updater.py --update-from-bundle sigs.zip    # offline: a package you obtained yourself
python3 updater.py --update-from-upstream           # sync upstreams pinned by commit SHA in sources.json
python3 updater.py --status                         # what is active right now (JSON)
python3 updater.py --rules-path                     # print the folder to pass to --yara-rules
python3 updater.py --rollback-signatures            # make the previous release active again
```

| flag | meaning |
|---|---|
| `--update-signatures` | install the project's own rule package: the URL and the archive sha256 are pinned in `sources.json`, HTTPS and a host allowlist are enforced |
| `--update-from-bundle FILE` | install a package from a local zip (the offline path; every check still runs) |
| `--update-from-upstream` | re-download the upstream rule sources pinned in `sources.json`; only sources pinned to a full 40-hex commit SHA **and** a pinned archive sha256 are synced — a branch reference is refused before any request. A source that fails keeps the rules it contributed to the previous release (a falling source never erases what works), and the run exits 3 (PARTIAL) |
| `--rollback-signatures` | activate the previous release again |
| `--status` | print the active release, its rule count, verification and any failed sources as JSON |
| `--rules-path` | print the `rules` folder of the active release (exit 1 when nothing is installed) — what you pass to `scan_backdoors.py --yara-rules` |
| `--package-sha256 HEX` | out-of-band sha256 of the archive; with it the update is **verified**, without it the updater refuses |
| `--signature FILE` | with `--update-from-bundle`: the package's `.minisig` file, checked against the key pinned as `package_source.minisign_pub` — the offline path to a signature-verified install |
| `--require-signature` | trust only what a pinned minisign key signed: no falling back to a pinned sha256, and it will not run without the optional `cryptography` package |
| `--allow-unverified` | accept a package nothing can verify — loudly, and the manifest records `"verified": false` |
| `--only SOURCE` | with `--update-from-upstream`: sync only this source (the others are carried over) |
| `--data-dir DIR` | data folder (default: `%SBD_DATA_DIR%`, otherwise `~/.scan_backdoors`) |
| `--version` | print the bundle version |

**What one update does**: download (streamed, size-capped) → check the pinned sha256 → check the minisign signature when a key is pinned → unpack safely (only `.yar`/`.yara`/license files, zip-slip / symlink / compression-bomb guards, nothing outside the staging folder) → compile every rule file in a separate subprocess with its own timeout (`engines/yara_check.py`) → move the staged release into place atomically → switch the `ACTIVE` pointer → rewrite the manifest. Any failure at any step leaves the previous release active; a source that fails during `--update-from-upstream` keeps its rules.

**Trust model**: the strongest anchor is a pinned **minisign public key** — the updater then activates only a package whose bytes that key signed (`verification: "minisign-ed25519"`, or `minisign-ed25519-prehashed` for `minisign -prehash` output). A pinned **archive sha256** (in `sources.json` or given with `--package-sha256`) is the weaker anchor: it proves the file did not change since you pinned it, not who made it. Pin both while a channel is young; when both are pinned, both are checked. A signature that is present and wrong is always a refusal — never a quiet downgrade to the hash. `--allow-unverified` remains the explicit, logged escape hatch (`"verified": false` in the manifest).

A **package manifest is mandatory** for a project package (and any `--update-from-bundle` file): it must declare every rule file with its sha256, and an undeclared rule file makes the whole package refused. An upstream commit zip carries no manifest of its own, so there the pinned archive sha256 is the whole trust — which is why pinning is mandatory.

**Signatures need the optional `cryptography` package** (`pip install -r requirements-optional.txt`), and only where a source pins a key: without it the updater keeps working exactly as before by pinned sha256, prints `Signature NOT checked: …` and records `"signature": "not-checked"` in the manifest, so nobody mistakes a hash-only install for a signed one. The `minisign` program itself is never run — the key and the signature file are parsed and verified in-process, and the updater ships a test that checks that parsing against signatures the real `minisign` produced.

**Publishing a signed package** (the project's own channel):

```
minisign -G -p minisign.pub -s minisign.key        # once, keep the secret key offline
minisign -S -m rules.zip -x rules.zip.minisig -s minisign.key
```

then publish both files, and put the single base64 line of `minisign.pub` into `sources.json` as `package_source.minisign_pub` (plus the `sha256` of the archive while the channel is young). Users need nothing but the pinned key: `updater.py` looks for `<url>.minisig` next to the package, or at `package_source.signature_url`.

**Where things live** (under `--data-dir`, created on first run):

```
signatures/ACTIVE                  the name of the active release (one line)
signatures/manifest.json           what is active, what is installed, what failed
signatures/sources.json            the pinned channels (edit this one by hand)
signatures/releases/<name>/rules/  the rule files of each release
logs/updater.log                   rotating log (secrets and tokens are masked)
```

`sources.json` is created as a template: `package_source` (the project's own package: `url` + `sha256` + `minisign_pub`, optionally `signature_url`) and `upstream` (a list of `{name, repo, commit, archive_sha256, license}`, optionally `minisign_pub`). Pinned hashes, pinned keys and third-party rule licences must be reviewed by a human before anything is put there — see `docs/OPEN_QUESTIONS.md`. A pinned key is the anchor of the whole scheme: replacing it in this file is what replaces who you trust, so treat this file like a config of trust, not like settings. Upstream rules are third-party content: review their licence before pinning them, the updater records `license` but does not judge it.

**Using the installed rules**: `python3 src/scan_backdoors.py /path/to/site --yara-rules "$(python3 src/updater.py --rules-path)"`. The GUI does this automatically: when a release is installed, scans pass its rules folder to the scanner (a path the browser page can never influence), and the **Engines** tab shows the active package with *Update signatures* and *Roll back* buttons.

**Compile check needs `yara-python`** (`pip install yara-python`): without it the updater refuses to activate a package it cannot compile-check. **Signature check needs `cryptography`** (optional, same file): without it a pinned key cannot be honoured and the update falls back to its pinned sha256 — visibly (see above), or not at all with `--require-signature`. Exit codes: `0` everything updated, `1` usage/config error, `3` PARTIAL (at least one upstream source failed — see the manifest), `4` verification or network failure (the previous release is unchanged).

---

## Documentation

- **[docs/README_RU.md](docs/README_RU.md)** — Russian command-line reference.
- **[CHANGELOG.md](CHANGELOG.md)** — what changed in each version.
- **[SECURITY.md](SECURITY.md)** — what the tool guarantees, what it does not, and how to report a vulnerability.

## How does it compare to other tools?

The tools below solve adjacent problems; most pairs of them are meant to be used
together, not as alternatives.

| Tool | What it is | Where it looks |
|---|---|---|
| **Scan Backdoors** (this repo) | a standalone forensic file scanner for a web root | file contents, file names, folder layout, mtimes |
| **wp2shell-scan** (InstaWP) | a bash script for the July-2026 WordPress campaign (CVE-2026-63030) | that campaign's filesystem patterns **and** the WordPress database |
| **wp-guard** (cbuntingde) | a security plugin that runs *inside* a live WordPress | runtime protection of the site it is installed on |
| **LMD** (rfxn/linux-malware-detect) | a host-level Linux malware detector | known-bad hashes, file entropy, host filesystem anomalies |

- **vs wp2shell-scan.** The scanner now carries the filesystem side of that
  campaign as ordinary signatures: a fake plugin folder named `<name>-<6 hex>`
  in `wp-content/plugins/`, the `hash_equals(token, $_GET[…])` gate, the
  command arriving through a local variable, and the impersonation author
  header. So a campaign web shell is found on *any* site without a
  campaign-specific script. What wp2shell-scan additionally covers — and a file
  scanner cannot — is the *database* side: backdoor admin accounts and their
  mail addresses in `wp_users`. After cleaning a compromised WordPress, check
  the database separately.
- **vs wp-guard.** It is a runtime shield for a *live* installation; it does not
  audit a web root after the fact and does not understand Joomla at all. The
  scanner is the post-incident complement: wp-guard may stop the attack, but it
  does not tell you what the attacker already dropped.
- **vs LMD.** LMD works at the *host* level (known-bad binary hashes, entropy,
  SUID/hidden-file anomalies) and does not read PHP for webshell patterns, so a
  fresh PHP shell with no known hash is not its finding. Use LMD for the host,
  this scanner for the web root.
- **vs signature lists (SecLists, FuzzDB, backdoor name lists).** The
  signatures were cross-checked against published sample corpora: the
  direct-sink classics (`system($_GET['cmd'])`, `file_put_contents(…,
  $_POST[…])`) were already covered; this batch adds the *taint* form — request
  data → variable → sink — which is how campaign shells dodge one-line greps.
  For the ~300 PHP names in public backdoor lists only the unambiguous family
  prefixes (`c99*`, `r57*`, `b374k*`) were added to the name check: bulk-adding
  the rest would flag legitimate files like `client.php`.

One deliberate asymmetry: the `hash_equals()`-against-request-data tell is
switched **off** on a detected WordPress site, where it is the ordinary nonce
check (`wp_verify_nonce`). On WordPress the campaign shell is still caught by
the taint and name/location signatures, which run everywhere.

## Versioning

One version for the whole bundle, written once in `src/version.py`; a release is
a tag with that number (`v3.1` = scanner 3.1, GUI 3.1, cleaner 3.1). Each script
keeps the same number as a fallback literal, because the scanner is routinely
uploaded to a server as a single file - a test compares the fallbacks with
`version.py`, so they cannot drift apart.

The GUI needs a scanner that can report machine-readable progress (`--progress-lines`,
introduced with scanner 2.1); with an older one it still works and warns that exact
progress is unavailable. Run `--version` on any of the three scripts to see what you have.

A release ships `sha256sums.txt` alongside the zip with the zip's SHA-256 (verify with
`Get-FileHash -Algorithm SHA256` on Windows or `sha256sum -c sha256sums.txt` on Linux).

## Development

The test suite needs nothing but Python - no pytest, no network, no real site:

```
python -m unittest discover -s tests -v        # everything
python -m unittest tests.test_scanner     # one module
```

It builds two synthetic sites in a fixture folder - a legitimate Joomla-like tree
that must produce no findings at all, and the same tree with planted backdoors that
must produce exactly the expected signatures and severities - then covers the
cleaner's plan → apply → restore cycle (including "a dry run changes nothing"),
the exit codes and report formats, the allowlist dataset, and the GUI driven
through its own HTTP API on a private port with a private settings file.

The malicious samples are stored in `tests/payloads/*.b64` (base64 plus a
description) so that a clone of this repository is not a folder full of copy-paste
web shells; `python tests/seal_payloads.py --show filefuns.php` prints any of them.
They are unsealed only into the fixture folder while a test runs - which is where
real-time antivirus sometimes deletes them: the suite detects that, says which
sample vanished and how to exclude the folder, rather than reporting a missed
backdoor. `.github/workflows/ci.yml` runs the suite on Linux and Windows across
supported Python versions.

## Why no dependencies

Sites get cleaned under pressure, often on a machine with no package access and
sometimes no internet. The scanner, the GUI and the cleaner run on a stock
Python 3.6+ and nothing else; XLSX reports are written by hand for the same
reason. Adding a dependency needs to beat that property, not just look tidier.

## Contributing

The most useful contributions are false positives: an entry for
`data/whitelist-known-clean.txt` (a SHA-256 plus one line on why the file is
clean), or a signature for a family the scanner does not yet know. Keep the code
compatible with Python 3.6, free of third-party packages, and run
`python -m unittest discover -s tests` before a pull request.

## License

MIT — see [LICENSE](LICENSE).
