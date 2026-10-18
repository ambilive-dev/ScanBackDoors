# scan_backdoors 2.1: parameter reference

A scanner for backdoors, web shells and malicious code on Joomla/PHP sites, with a mass-cleanup tool and a browser-based GUI.
Only Python 3.6+ is required, nothing needs to be installed (no Tk, no pip).

## Launching

The package consists of four files that must stay in the same folder:

| File | Purpose |
|---|---|
| `scan_backdoors_gui.py` | Browser-based GUI: a small local web server plus a page in your browser (scan, results table, quarantine/delete, mass cleanup) |
| `scan_backdoors.py` | The scanner (command line) |
| `clean_malware.py` | Mass cleanup (command line; also used by the GUI "Mass cleanup" button) |
| `start.bat` | Windows launcher for the GUI |

### Windows: `start.bat`

Double-click `start.bat`. It switches to its own folder, finds Python (`py -3`, otherwise `python`), starts `scan_backdoors_gui.py` and your default browser opens the page.
If Python is not found, or the server exits with an error, the window stays open with a hint.

Requirements: Python 3.6+ (tick "Add python.exe to PATH" in the installer from python.org).
Keep the console window open while you work: closing it stops the server. You can also stop it with the **Quit server** button in the page.

### Any OS: `scan_backdoors_gui.py`

```
python3 scan_backdoors_gui.py                 # start and open the browser
python3 scan_backdoors_gui.py --no-browser    # start without opening the browser
python3 scan_backdoors_gui.py --port 9000     # use another port
```

### Open it from a browser bookmark

The server always uses the same address, **http://127.0.0.1:8765/** (the port is fixed on purpose). Bookmark it and the page opens from the bookmark whenever the server is running.
Starting the script a second time while it is already running does not start another copy, it only opens the page again.
If port 8765 is taken by another program, the next free port is used and the console prints the new address (the bookmark then has to be updated).

To have the server running all the time without a console window, on Windows put a shortcut to `pythonw scan_backdoors_gui.py --no-browser` into the Startup folder (`Win+R`, `shell:startup`).
The page remembers the last state (log, results) while the server runs, so you can close and reopen the tab at any moment.

### Security

- The server listens on **127.0.0.1 only**, it is not reachable from other computers.
- Requests are accepted only for the host names `127.0.0.1`/`localhost` on its own port (protects against DNS rebinding) and only with a custom header and a JSON body (protects against requests from other web sites).
- File names and code snippets from the scanned site are shown as plain text, never as HTML.
- To use the GUI on a remote server, do not open the port, use an SSH tunnel instead: `ssh -L 8765:127.0.0.1:8765 user@server`, then open http://127.0.0.1:8765/ locally.

### First run in the GUI

1. **Settings** tab: choose the *Site folder* (optionally a *Clean Joomla* folder, a *Whitelist* and the report paths). **Browse…** opens a file chooser that lists the folders of the machine where the server runs.
2. **Run and results** tab: press *Start scan*. The progress bar and the log show the scan, the table lists the findings.
3. Select rows (click, Ctrl/Shift+click, Ctrl+A) and use *Show file*, *Quarantine*, *Delete from disk* (or the Delete key), or the right-click menu (copy path, copy SHA-256, add to whitelist). *Mass cleanup* handles the known malware families across the whole site: it first shows a plan and asks for confirmation.
4. Open the reports (CSV/XLSX/JSON) with the buttons above the table, or download them through the links next to them.

Settings are saved automatically in `~/.scan_backdoors_gui.json` (the same file the older desktop version used). The command-line options are described below.

## Command line

```
python3 scan_backdoors.py [folder] [options]
```

If no folder is given, the current one is scanned. **All** folders are checked by default, including `cache`, `tmp`, `logs`, `media`.

---

## Quick start

```bash
# Regular check: the report goes to report-data.csv
python3 scan_backdoors.py /home/user/site

# Only the most dangerous findings, last 14 days
python3 scan_backdoors.py /home/user/site --since 14d --only-critical

# Most accurate check: comparison with a clean Joomla + whitelist
python3 scan_backdoors.py /home/user/site --baseline-dir /tmp/Joomla_5.1.0 --whitelist whitelist.txt
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
| `--max-matches N` | `60` | Maximum findings of one level per file in the report. The overall counters include all findings. |

```bash
python3 scan_backdoors.py . --csv /tmp/scan.csv
python3 scan_backdoors.py . --xlsx report.xlsx --json report.json
python3 scan_backdoors.py . --no-csv --json report.json
python3 scan_backdoors.py . --max-matches 20
```

### Reducing false positives

| Option | Description |
|---|---|
| `--whitelist FILE` | A file with exclusions (format below). |
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

### Performance and output

| Option | Default | Description |
|---|---|---|
| `--workers N` | `0` (auto) | Number of processes. `0` = auto (up to 4), `1` = no parallelism. If parallel mode is unavailable on the host, the script falls back to a single thread by itself. |
| `--no-progress` | | Do not show the progress indicator. |
| `--progress-lines` | | Print machine-readable lines `@@PROGRESS`, `@@FILE`, `@@STATS`, `@@DONE`. Needed by the GUI (progress bar, report buttons); works without a terminal too. |
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
| `--restore MANIFEST` | | Restore files from quarantine. For cleaned `.htaccess` files it restores the original content. |
| `--replace-core` | off | Replace modified Joomla core files with originals from `--baseline-dir`. `--apply` is required to execute. The modified file is kept in quarantine (`*.modified`), the original is written over it in place (owner and permissions are kept), the hash is verified after writing. |
| `--baseline-dir` | | A folder with a clean full Joomla distribution of the **same version** (where `index.php` lives). |
| `--core-ext` | `.php,.js,.html,.htm` | Extensions that are replaced. Language `.ini` files are not touched by default (translators edit them). |
| `--max-modified-percent` | `30` | If more than N% of core files are "modified", the replacement is cancelled: most likely the baseline is of a different version. |
| `--force-version` | off | Skip the version and percentage checks (**dangerous**). |
| `--no-media` | off | Do not check images/video for PHP code inside (faster on large sites). By default `.jpg .png .gif .ico .flv .mp3 .mp4` and others are checked. |
| `--progress-lines` | | Service lines `@@...` for the GUI. |

**How it stays safe:** quarantine with hash verification before deletion; files with 0444 permissions and 0555 directories are handled (directory permissions are restored); symbolic links are skipped; a repeated run finds nothing.

Exit codes: `0` success, `1` startup error (including a baseline version mismatch), `2` some files could not be processed.

**Replacing core files (example):**
```
python3 clean_malware.py /path/to/site --replace-core --baseline-dir /tmp/Joomla_5.1.2        # plan
python3 clean_malware.py /path/to/site --replace-core --baseline-dir /tmp/Joomla_5.1.2 --apply  # execute
```
Safeguards: the site and baseline versions must match (otherwise it refuses); if more than 30% of files are modified, the replacement is cancelled; files that are not in the baseline (extensions, templates, `configuration.php`) are not touched; files from `--whitelist` (your own core edits) are not replaced. Extra files in `libraries/`, `includes/`, `administrator/includes/` (not in the baseline) are only listed for manual review. Rollback: `--restore .../manifest.json`.

**In the GUI:** the "🧹 Mass cleanup" button on the results tab. First a dry run with the numbers, then a confirmation, then the cleanup. The mode (quarantine or permanent), the `filemanager` family and the "Replace modified core files with originals" checkbox (it takes the "Clean Joomla" folder from the settings) are set on the "Settings" tab. `clean_malware.py` must be placed next to the scanner.
