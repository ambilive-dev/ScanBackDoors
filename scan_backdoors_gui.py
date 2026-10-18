#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Browser front end for scan_backdoors.py (requires scanner v2.1+ placed next to it).
Python standard library only (3.6+). No Tk, no pip.

It starts a small web server that listens on 127.0.0.1 ONLY and opens the UI in your default browser.
The port is fixed (default 8765), so you can bookmark  http://127.0.0.1:8765/  and come back to it.
Starting the script again while it is already running just opens the browser tab.

    python3 scan_backdoors_gui.py                  # start and open the browser
    python3 scan_backdoors_gui.py --no-browser     # start without opening the browser
    python3 scan_backdoors_gui.py --port 9000
"""
import argparse
import csv
import json
import os
import re
import shutil
import signal
import stat
import string
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

APP_ID = "scan_backdoors_gui"
VERSION = "3.0"
DEFAULT_PORT = 8765
HERE = Path(__file__).resolve().parent
CONFIG_PATH = Path.home() / ".scan_backdoors_gui.json"
API_HEADER = "X-Requested-With"
API_HEADER_VALUE = "scan-backdoors-gui"
MAX_TABLE_ROWS = 5000          # a bigger table is heavy for the browser; the full list is in the CSV
LOG_KEEP = 4000
LEVEL_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
# Files whose deletion may "take the site down": the server insists on an extra confirmation
PROTECTED_FILES = {"configuration.php", "index.php", ".htaccess", "administrator/index.php"}

DEFAULTS = {
    "scanner_path": str(HERE / "scan_backdoors.py"), "site_dir": "", "csv_path": str(Path.cwd() / "report-data.csv"),
    "xlsx_path": "", "json_path": "", "baseline_dir": "", "whitelist_path": "", "since": "", "max_size": "5",
    "max_matches": "60", "min_score": "0", "workers": "0", "exclude_ext": "", "exclude_dir": "",
    "only_critical": False, "no_warnings": False, "no_csv": False, "auto_open": False,
    "clean_permanent": False, "clean_fm": False, "clean_core": False,
}
BOOL_KEYS = {k for k, v in DEFAULTS.items() if isinstance(v, bool)}


# ---------------------------------------------------------------------------
# helper functions
# ---------------------------------------------------------------------------

def clean_cell(v):
    """The scanner protects the CSV from formulas: a cell '=x' is written as "'=x". Restore the original name."""
    v = v or ""
    return v[1:] if v[:1] == "'" and v[1:2] in ("=", "+", "-", "@") else v


def fmt_size(v):
    try:
        n = float(v)
    except (TypeError, ValueError):
        return v or ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def fmt_duration(sec):
    sec = int(max(sec, 0))
    m, s = divmod(sec, 60)
    h, m = divmod(m, 60)
    return "%d:%02d:%02d" % (h, m, s) if h else "%d:%02d" % (m, s)


def open_path(path):
    if sys.platform.startswith("win"):
        os.startfile(str(path))
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def reveal_path(path):
    """Open the folder and highlight the file (if the OS can)."""
    path = Path(path)
    if sys.platform.startswith("win"):
        subprocess.Popen(["explorer", "/select,%s" % path])
    elif sys.platform == "darwin":
        subprocess.Popen(["open", "-R", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path.parent)])


def python_exe():
    """sys.executable, but never pythonw.exe: the scanner is started with piped output and needs a normal python.exe
    (it does not open a console window anyway, we pass CREATE_NO_WINDOW)."""
    exe = sys.executable
    if os.name == "nt" and os.path.basename(exe).lower() == "pythonw.exe":
        cand = os.path.join(os.path.dirname(exe), "python.exe")
        if os.path.isfile(cand):
            return cand
    return exe


def kill_tree(proc):
    """Stop the scanner TOGETHER with its child processes (--workers)."""
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except OSError:
            pass


class ApiError(Exception):
    def __init__(self, message, code=400, **extra):
        Exception.__init__(self, message)
        self.code, self.extra = code, extra


# ---------------------------------------------------------------------------
# application state and logic (everything the desktop window used to do)
# ---------------------------------------------------------------------------

class App(object):
    def __init__(self, port):
        self.port = port
        self.boot = str(int(time.time() * 1000))
        self.lock = threading.RLock()
        self.settings = dict(DEFAULTS)
        self._load_config()
        self.job = None
        self.log, self.log_first = [], 0
        self.status = "Ready to run"
        self.idle_text = ""
        self.findings, self.next_id, self.findings_version, self.hidden_done = [], 1, 0, 0
        self.report_files, self.scanned_site, self.last_stats = {}, None, None
        self.notice, self.notice_seq = None, 0
        self.cleaned, self.stripped, self.replaced, self.clean_summary = [], [], [], None
        self.shutdown_cb = None
        self.load_findings()                  # show the previous report right away, if there is one

    # ------------------------------------------------------------ settings
    def s(self, key):
        return self.settings.get(key, DEFAULTS.get(key))

    def _load_config(self):
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.update_settings(data, save=False)
        if not Path(self.s("scanner_path")).is_file():
            self.settings["scanner_path"] = DEFAULTS["scanner_path"]

    def update_settings(self, data, save=True):
        if not isinstance(data, dict):
            return
        for k, v in data.items():
            if k not in DEFAULTS:
                continue
            if k in BOOL_KEYS:
                self.settings[k] = bool(v)
            elif isinstance(v, (str, int, float)):
                self.settings[k] = str(v)
        if save:
            try:
                CONFIG_PATH.write_text(json.dumps(self.settings, ensure_ascii=False, indent=1), encoding="utf-8")
            except OSError:
                pass

    # ------------------------------------------------------------ log / notices
    def log_add(self, text):
        with self.lock:
            self.log.append(text)
            if len(self.log) > LOG_KEEP:
                drop = len(self.log) - LOG_KEEP + 500
                self.log, self.log_first = self.log[drop:], self.log_first + drop

    def notify(self, kind, title, text, **data):
        with self.lock:
            self.notice_seq += 1
            self.notice = dict(data, seq=self.notice_seq, kind=kind, title=title, text=text)

    # ------------------------------------------------------------ reports
    def abs_from_setting(self, raw):
        path = Path(raw.strip()).expanduser()
        if not path.is_absolute():
            path = Path(self.s("scanner_path")).expanduser().resolve().parent / path
        return path

    def report_path(self, kind):
        p = self.report_files.get(kind)
        if p:
            path = Path(p)
        else:
            raw = {"csv": "" if self.s("no_csv") else self.s("csv_path"),
                   "xlsx": self.s("xlsx_path"), "json": self.s("json_path")}[kind]
            if not raw.strip():
                return None
            path = self.abs_from_setting(raw)
        return path if path.is_file() else None

    def reports_info(self):
        out = {}
        for kind in ("csv", "xlsx", "json"):
            p = self.report_path(kind)
            out[kind] = {"exists": bool(p), "path": str(p) if p else ""}
        return out

    def reports_directory(self):
        for kind in ("csv", "xlsx", "json"):
            p = self.report_path(kind)
            if p:
                return p.parent
        for raw in ("" if self.s("no_csv") else self.s("csv_path"), self.s("xlsx_path"), self.s("json_path")):
            if raw.strip():
                return self.abs_from_setting(raw).parent
        return Path.cwd()

    def open_report(self, kind):
        if kind not in ("csv", "xlsx", "json"):
            raise ApiError("Unknown report.")
        path = self.report_path(kind)
        if not path:
            raise ApiError("The report has not been created yet.", 404)
        try:
            open_path(path)
        except Exception as exc:
            raise ApiError("Could not open the file: %s (%s)" % (path, exc), 500)

    def open_reports_folder(self):
        folder = self.reports_directory()
        try:
            folder.mkdir(parents=True, exist_ok=True)
            open_path(folder)
        except Exception as exc:
            raise ApiError("Could not open the folder: %s (%s)" % (folder, exc), 500)

    # ------------------------------------------------------------ findings
    def site_root(self):
        return self.scanned_site or self.s("site_dir")

    @staticmethod
    def _read_csv(path):
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f))

    @staticmethod
    def _read_json(path):
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = []
        for fl in data.get("files", []):
            for h in fl.get("hits", []):
                rows.append({"Score": fl.get("score", ""), "Verdict": fl.get("verdict", ""),
                             "Severity": h.get("severity", ""), "File": fl.get("path", ""),
                             "Line": h.get("line") or "", "Signature": h.get("signature", ""),
                             "Snippet": h.get("snippet", ""), "Size": fl.get("size", ""),
                             "Modified": fl.get("modified", ""), "Delete": "No", "SHA-256": fl.get("sha256", "")})
        return rows

    def load_findings(self):
        with self.lock:
            self.findings, self.hidden_done = [], 0
            path, loader = self.report_path("csv"), self._read_csv
            if path is None:
                path, loader = self.report_path("json"), self._read_json
            if path is not None:
                try:
                    rows = loader(path)
                except (OSError, ValueError, csv.Error) as exc:
                    rows = []
                    self.log_add("\nCould not read the report: %s\n" % exc)
                site = self.site_root()
                root = Path(site).expanduser() if site else None
                for row in rows:
                    rel = clean_cell(row.get("File", ""))
                    row["File"] = rel
                    # marked 'Yes' and the file no longer exists on disk -> it was deleted/handled, do not show it
                    mark = (row.get("Delete") or "").strip().lower()
                    if (mark == "yes" and root and root.is_dir() and not os.path.lexists(str(root / rel))) \
                            or mark == "replaced":
                        self.hidden_done += 1
                        continue
                    level = (row.get("Verdict") or "").upper().strip()
                    row["_level"] = level if level in LEVEL_ORDER else "LOW"
                    row["_id"] = self.next_id
                    self.next_id += 1
                    self.findings.append(row)
            self.findings_version += 1

    @staticmethod
    def _sort_key(row, col):
        if col == "level":
            return LEVEL_ORDER.get(row.get("_level"), 3)
        if col in ("score", "line", "size"):
            try:
                return float(row.get({"score": "Score", "line": "Line", "size": "Size"}[col]) or -1)
            except ValueError:
                return -1.0
        if col == "date":
            return row.get("Modified", "")
        if col == "delete":
            return row.get("Delete", "")
        if col == "file":
            return row.get("File", "").lower()
        return row.get("Signature", "").lower()

    def findings_list(self, params):
        level = params.get("level", "All")
        query = params.get("q", "").casefold().strip()
        sort, desc = params.get("sort", ""), params.get("desc", "0") == "1"
        try:
            limit = max(1, min(int(params.get("limit", MAX_TABLE_ROWS)), MAX_TABLE_ROWS))
        except ValueError:
            limit = MAX_TABLE_ROWS
        with self.lock:
            rows = self.findings
            if sort in ("level", "score", "file", "line", "size", "date", "delete", "signature"):
                rows = sorted(rows, key=lambda r: self._sort_key(r, sort), reverse=desc)
            out, matched = [], 0
            for r in rows:
                if level != "All" and r["_level"] != level:
                    continue
                if query and query not in (r.get("File", "") + " " + r.get("Signature", "")).casefold():
                    continue
                matched += 1
                if len(out) < limit:
                    out.append({"id": r["_id"], "level": r["_level"], "score": r.get("Score", ""),
                                "file": r.get("File", ""), "line": r.get("Line", ""),
                                "size": fmt_size(r.get("Size", "")), "date": r.get("Modified", ""),
                                "delete": r.get("Delete", ""), "signature": r.get("Signature", "")})
            return {"total": len(self.findings), "matched": matched, "shown": len(out), "limit": limit,
                    "hidden_done": self.hidden_done, "version": self.findings_version, "rows": out}

    def finding_detail(self, fid):
        with self.lock:
            for r in self.findings:
                if r["_id"] == fid:
                    return {"id": fid, "file": r.get("File", ""), "level": r["_level"], "score": r.get("Score", ""),
                            "line": r.get("Line", ""), "size": fmt_size(r.get("Size", "")),
                            "date": r.get("Modified", ""), "signature": r.get("Signature", ""),
                            "severity": r.get("Severity", ""), "sha256": r.get("SHA-256", ""),
                            "snippet": r.get("Snippet", "")}
        raise ApiError("The row no longer exists.", 404)

    def _rows_by_ids(self, ids):
        try:
            want = set(int(i) for i in ids)
        except (TypeError, ValueError):
            raise ApiError("Bad row ids.")
        with self.lock:
            return [r for r in self.findings if r["_id"] in want]

    # ------------------------------------------------------------ file actions
    def resolve_target(self, rel):
        """Safely resolve a file path inside the site folder (protection against '..' and symlinks pointing outside)."""
        site = self.site_root()
        root = Path(site).expanduser() if site else None
        if not root or not root.is_dir():
            raise ApiError("Site root folder not found: %s" % (root or ""))
        root_real = Path(os.path.realpath(str(root)))
        target = Path(os.path.normpath(str(root_real / rel)))
        try:
            target.relative_to(root_real)
            Path(os.path.realpath(str(target.parent))).relative_to(root_real)
        except ValueError:
            raise ApiError("The path leaves the site folder: %s" % rel)
        return root_real, target

    def file_paths(self, ids):
        rows = self._rows_by_ids(ids)
        if not rows:
            raise ApiError("Nothing selected")
        return [str(self.resolve_target(r.get("File", ""))[1]) for r in rows]

    def reveal(self, fid):
        rows = self._rows_by_ids([fid])
        if not rows:
            raise ApiError("Nothing selected")
        _root, target = self.resolve_target(rows[0].get("File", ""))
        if not target.parent.is_dir():
            raise ApiError("The folder does not exist: %s" % target.parent)
        try:
            reveal_path(target)
        except Exception as exc:
            raise ApiError("Could not open the folder: %s" % exc, 500)

    def _unique_files(self, ids):
        rows = self._rows_by_ids(ids)
        if not rows:
            raise ApiError("Nothing selected")
        by_file = {}
        for r in rows:                      # one file may have many findings -> work with unique files
            rel, lvl = r.get("File", ""), r.get("_level", "LOW")
            if rel not in by_file or LEVEL_ORDER.get(lvl, 3) < LEVEL_ORDER.get(by_file[rel], 3):
                by_file[rel] = lvl
        targets, missing = [], []
        for rel in by_file:
            _root, target = self.resolve_target(rel)
            (targets if os.path.lexists(str(target)) else missing).append((rel, target))
        return by_file, targets, missing

    def files_preview(self, ids):
        by_file, targets, missing = self._unique_files(ids)
        return {"files": [{"rel": rel, "level": by_file[rel],
                           "protected": rel.lower().replace("\\", "/") in PROTECTED_FILES} for rel, _t in targets],
                "missing": [rel for rel, _t in missing],
                "warn_levels": any(by_file[rel] != "HIGH" for rel, _t in targets)}

    def files_do(self, ids, action, confirm_protected=False):
        quarantine = (action == "quarantine")
        by_file, targets, missing = self._unique_files(ids)
        protected = [rel for rel, _t in targets if rel.lower().replace("\\", "/") in PROTECTED_FILES]
        if protected and not confirm_protected:
            raise ApiError("Protected files need an extra confirmation.", 409, protected=protected)
        qdir = None
        if quarantine and targets:
            root, _t = self.resolve_target(targets[0][0])
            qdir = root.parent / ("_quarantine_" + (root.name or "site")) / datetime.now().strftime("%Y%m%d_%H%M%S")
        done, failed = [], []
        for rel, target in targets:
            try:
                if quarantine:
                    dest = qdir / (rel.replace("\\", "/") + ".quarantine")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(target), str(dest))
                    with (qdir / "manifest.txt").open("a", encoding="utf-8") as mf:
                        mf.write("%s\t<-\t%s\n" % (dest, target))
                    self.log_add("[QUARANTINE] %s -> %s\n" % (target, dest))
                else:
                    try:
                        target.unlink()
                    except PermissionError:
                        os.chmod(str(target), stat.S_IWRITE | stat.S_IREAD)
                        target.unlink()
                    self.log_add("[DELETED] %s\n" % target)
                done.append(rel)
            except Exception as exc:
                failed.append([rel, str(exc)])
                self.log_add("[ERROR] %s: %s\n" % (target, exc))
        if not targets:
            text = "The files are already missing on disk, removed from the list: %d" % len(missing)
        else:
            text = "%s: %d" % ("Moved to quarantine" if quarantine else "Deleted", len(done))
        self.finish_removal(done + [rel for rel, _t in missing], text, failed, qdir if quarantine and done else None)
        return {"ok": True, "text": self.status, "failed": failed}

    def finish_removal(self, rels, text, failed=(), qdir=None, replaced=()):
        """Remove the files from the in-memory list, mark them in the CSV and refresh the table (without re-reading the CSV)."""
        gone = set(rels) | set(replaced)
        with self.lock:
            if gone:
                self.findings = [r for r in self.findings if r.get("File") not in gone]
                self.findings_version += 1
                err = self.mark_deleted_in_csv(set(rels), set(replaced))
                if err:
                    self.log_add("CSV not updated (%s). Close the file in Excel.\n" % err)
            if qdir:
                text += " · quarantine: %s" % qdir
            if failed:
                text += " · failed: %d" % len(failed)
            self.status = text

    def mark_deleted_in_csv(self, rels, replaced=()):
        path = Path(self.report_files["csv"]) if self.report_files.get("csv") else self.report_path("csv")
        if not path or not path.is_file():
            return None
        tmp = path.with_name(path.name + ".tmp")
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                fields = reader.fieldnames or []
                if "Delete" not in fields:
                    return None
                rows = list(reader)
            for row in rows:
                name = clean_cell(row.get("File", ""))
                if name in rels:
                    row["Delete"] = "Yes"
                elif name in replaced:
                    row["Delete"] = "Replaced"
            with tmp.open("w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                w.writerows(rows)
            os.replace(str(tmp), str(path))
            return None
        except (OSError, csv.Error) as exc:
            try:
                tmp.unlink()
            except OSError:
                pass
            return str(exc)

    def whitelist_add(self, ids):
        rows = self._rows_by_ids(ids)
        hashes = {}
        for r in rows:
            if r.get("SHA-256"):
                hashes[r["SHA-256"]] = r.get("File", "")
        if not hashes:
            raise ApiError("The report has no SHA-256 for the selected files.")
        wl = self.s("whitelist_path").strip()
        if not wl:                                   # a browser has no 'save as' dialog: default next to the scanner
            wl = str(Path(self.s("scanner_path")).expanduser().resolve().parent / "whitelist.txt")
            self.update_settings({"whitelist_path": wl})
        try:
            wl_path = Path(wl).expanduser()
            prefix = ""
            if wl_path.is_file() and wl_path.stat().st_size and not wl_path.read_bytes().endswith(b"\n"):
                prefix = "\n"
            with wl_path.open("a", encoding="utf-8") as f:
                f.write(prefix + "".join("%s  # %s\n" % (h, rel) for h, rel in hashes.items()))
        except OSError as exc:
            raise ApiError("Could not write the whitelist: %s" % exc, 500)
        self.status = "Hashes added to the whitelist: %d (effective from the next scan)" % len(hashes)
        return {"ok": True, "count": len(hashes), "path": str(wl_path), "text": self.status}

    # ------------------------------------------------------------ jobs: scan / mass cleanup
    def _num(self, key, name, kind=float, minimum=0):
        s = str(self.s(key)).strip().replace(",", ".")
        if not s:
            return ""
        try:
            v = kind(s)
        except ValueError:
            raise ApiError("The field '%s' must be a number." % name)
        if v < minimum:
            raise ApiError("The field '%s' cannot be less than %s." % (name, minimum))
        return s

    def build_scan_command(self):
        scanner = Path(self.s("scanner_path")).expanduser()
        site = Path(self.s("site_dir")).expanduser()
        if not scanner.is_file():
            raise ApiError("The scanner file scan_backdoors.py was not found.")
        if not self.s("site_dir").strip() or not site.is_dir():
            raise ApiError("Select an existing site folder.")
        since = self.s("since").strip()
        if since and not re.match(r"^\d+d$", since):
            try:
                datetime.strptime(since, "%Y-%m-%d")
            except ValueError:
                raise ApiError("The field 'Modified after': use 14d or 2026-09-01.")
        try:
            markers = "--progress-lines" in scanner.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            markers = False
        cmd = [python_exe(), "-u", str(scanner), str(site)]

        def add(flag, value):
            value = value.strip()
            if value:
                cmd.extend([flag, value])
        add("--max-size", self._num("max_size", "File size", float, 0.01))
        add("--max-matches", self._num("max_matches", "Max findings", int, 1))
        add("--min-score", self._num("min_score", "Minimum score", int, 0))
        add("--workers", self._num("workers", "Processes", int, 0))
        add("--since", since)
        add("--exclude-ext", self.s("exclude_ext"))
        add("--exclude-dir", self.s("exclude_dir"))
        add("--baseline-dir", self.s("baseline_dir"))
        add("--whitelist", self.s("whitelist_path"))
        outputs = [("--xlsx", self.s("xlsx_path")), ("--json", self.s("json_path"))]
        if self.s("no_csv"):
            cmd.append("--no-csv")
        else:
            outputs.append(("--csv", self.s("csv_path") or "report-data.csv"))
        for flag, raw in outputs:
            if raw.strip():
                p = self.abs_from_setting(raw)
                try:
                    p.parent.mkdir(parents=True, exist_ok=True)
                except OSError as exc:
                    raise ApiError("Cannot create the report folder: %s" % exc)
                cmd.extend([flag, str(p)])
        if self.s("only_critical"):
            cmd.append("--only-critical")
        if self.s("no_warnings"):
            cmd.append("--no-warnings")
        if markers:
            cmd.append("--progress-lines")
        return cmd, markers

    def build_clean_command(self, apply):
        cleaner = Path(self.s("scanner_path")).expanduser().with_name("clean_malware.py")
        if not cleaner.is_file():
            raise ApiError("clean_malware.py was not found next to the scanner.")
        site_s = self.site_root()
        site = Path(site_s or "").expanduser()
        if not site_s or not site.is_dir():
            raise ApiError("Select an existing site folder.")
        report_dir = self.reports_directory()
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ApiError("Cannot create the report folder: %s" % exc)
        families = "htaccess,backdoor" + (",filemanager" if self.s("clean_fm") else "")
        cmd = [python_exe(), "-u", str(cleaner), str(site), "--families", families, "--progress-lines",
               "--report", str(report_dir / "cleanup-report.csv")]
        if self.s("whitelist_path").strip():
            cmd += ["--whitelist", self.s("whitelist_path").strip()]
        if self.s("clean_core"):
            base = self.s("baseline_dir").strip()
            if not base or not Path(base).expanduser().is_dir():
                raise ApiError("To replace core files, specify the 'Clean Joomla' folder (same version) on the 'Settings' tab.")
            cmd += ["--replace-core", "--baseline-dir", base]
        if apply:
            cmd.append("--apply")
            if self.s("clean_permanent"):
                cmd.append("--delete")
        return cmd

    def _start_job(self, kind, cmd, markers=True):
        with self.lock:
            if self.job is not None:
                raise ApiError("Another job is already running.", 409)
            self.job = {"kind": kind, "proc": None, "t0": time.time(), "text": "Starting…", "indeterminate": True,
                        "done": 0, "total": 0, "stopped": False, "got_done": False, "markers": markers,
                        "report_error": False}
            self.idle_text = ""
            self.log_add("\n" + "=" * 76 + "\nCommand: " + subprocess.list2cmdline(cmd) + "\n\n")
            if not markers:
                self.log_add("WARNING: old scanner version (no --progress-lines), exact progress is unavailable. "
                             "Update scan_backdoors.py to 2.1.\n\n")
        threading.Thread(target=self._run_job, args=(cmd,), daemon=True).start()

    def start_scan(self):
        cmd, markers = self.build_scan_command()
        with self.lock:
            if self.job is not None:
                raise ApiError("Another job is already running.", 409)
            self.report_files, self.last_stats = {}, None
            self.scanned_site = str(Path(self.s("site_dir")).expanduser())
            self.findings, self.hidden_done = [], 0
            self.findings_version += 1
            self.status = "Scan in progress…"
            self._start_job("scan", cmd, markers)

    def start_clean_plan(self):
        cmd = self.build_clean_command(False)
        with self.lock:
            self.cleaned, self.stripped, self.replaced, self.clean_summary = [], [], [], None
            self.status = "Mass cleanup: searching for malicious files…"
            self._start_job("clean-plan", cmd)

    def start_clean_apply(self):
        cmd = self.build_clean_command(True)
        with self.lock:
            self.cleaned, self.stripped, self.replaced, self.clean_summary = [], [], [], None
            self.status = "Mass cleanup: working…"
            self._start_job("clean-apply", cmd)

    def clean_cancel(self):
        self.status = "Mass cleanup cancelled."

    def stop_job(self):
        with self.lock:
            job = self.job
            if job is None:
                return
            job["stopped"] = True
            self.status = "Stopping…"
            proc = job["proc"]
        kill_tree(proc)

    def _run_job(self, cmd):
        env = os.environ.copy()
        env.update(PYTHONIOENCODING="utf-8", PYTHONUTF8="1", PYTHONUNBUFFERED="1")   # else the output comes in one batch at the end
        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            kwargs["start_new_session"] = True          # so that the whole process group can be killed
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                                    encoding="utf-8", errors="replace", bufsize=1, env=env,
                                    cwd=str(Path(self.s("scanner_path")).expanduser().resolve().parent), **kwargs)
        except Exception as exc:
            with self.lock:
                self.job = None
                self.status = "Could not start the process"
                self.log_add("\nStartup error: %s\n" % exc)
                self.notify("error", "Startup error", str(exc))
            return
        with self.lock:
            self.job["proc"] = proc
            stopped = self.job["stopped"]
        if stopped:
            kill_tree(proc)
        for line in proc.stdout:
            self._on_line(line)
        code = proc.wait()
        try:
            self._job_finished(code)
        except Exception as exc:                       # never leave the UI stuck in "running"
            with self.lock:
                self.job = None
                self.status = "Internal error while finishing the job: %s" % exc

    def _on_line(self, line):
        with self.lock:
            job = self.job
            if job is None:
                return
            if line.startswith("@@"):
                tag, _, payload = line[2:].rstrip("\r\n").partition(" ")
                self._handle_marker(job, tag, payload)
            else:
                self.log_add(line)
                if "Could not write the report" in line:
                    job["report_error"] = True

    def _handle_marker(self, job, tag, payload):
        """Service lines of the scanner (--progress-lines): they do not go to the log."""
        if tag == "PHASE":
            job["indeterminate"] = True
            job["text"] = {"baseline": "Building the clean Joomla baseline…", "walk": "Collecting the file list…",
                           "finish": "Generating the report…", "clean": "Cleaning files…"}.get(payload, "Working…")
        elif tag == "PROGRESS":
            try:
                done, total = (int(x) for x in payload.split())
                job["done"], job["total"], job["indeterminate"] = done, total, False
            except ValueError:
                pass
        elif tag == "FILE":
            kind, _, path = payload.partition(" ")
            if path:
                self.report_files[kind] = path
        elif tag == "STATS":
            try:
                self.last_stats = json.loads(payload)
            except ValueError:
                pass
        elif tag == "DONE":
            job["got_done"] = True
        elif tag == "CLEANED":
            self.cleaned.append(payload)
        elif tag == "STRIPPED":
            self.stripped.append(payload)
        elif tag == "REPLACED":
            self.replaced.append(payload)
        elif tag == "SUMMARY":
            try:
                self.clean_summary = json.loads(payload)
            except ValueError:
                pass

    def _job_finished(self, code):
        with self.lock:
            job = self.job
            kind, stopped, report_error = job["kind"], job["stopped"], job["report_error"]
            valid = job["got_done"] or not job["markers"]    # exit code 2 from argparse != 'there are critical findings'
            elapsed = time.time() - job["t0"]
            self.job = None
            if kind == "scan":
                self._finish_scan(code, valid, stopped, report_error, elapsed)
            elif kind == "clean-plan":
                self._finish_clean_plan(code, stopped)
            else:
                self._finish_clean_apply(code, stopped)

    def _finish_scan(self, code, valid, stopped, report_error, elapsed):
        stats = self.last_stats or {}
        summary = ""
        if stats:
            summary = " Files scanned: %s, flagged: %s (HIGH %s, MEDIUM %s, LOW %s)." % (
                stats.get("Files scanned", "?"), stats.get("Files flagged", "?"),
                stats.get("HIGH", 0), stats.get("MEDIUM", 0), stats.get("LOW", 0))
        if stopped:
            msg = "Scan stopped by the user."
        elif not valid or code not in (0, 2):
            msg = "The scanner finished with an error (code %s). See the log for details." % code
        elif code == 0:
            msg = "Finished: no critical findings." + summary
        else:
            msg = "Finished: critical findings detected." + summary
        if report_error:
            msg += " The report was not written: close the file in Excel and try again."
        self.idle_text = "Done in %s" % fmt_duration(elapsed) if (not stopped and valid and code in (0, 2)) else ""
        self.status = msg
        self.log_add("\n" + msg + "\n")
        self.load_findings()
        if stopped or report_error:
            return
        if not valid or code not in (0, 2):
            self.notify("error", "Scan error", msg)
        elif self.s("auto_open") and self.report_path("csv"):
            try:
                open_path(self.report_path("csv"))
            except Exception as exc:
                self.log_add("Could not open the CSV: %s\n" % exc)
        elif code == 2:
            if self.report_path("csv"):
                self.notify("offer_csv", "Scan finished", msg + "\n\nOpen the CSV report?")
            else:
                self.notify("warn", "Scan finished", msg)

    def _finish_clean_plan(self, code, stopped):
        summary = self.clean_summary or {}
        if stopped:
            self.status = "Mass cleanup stopped by the user."
            return
        if not summary or code not in (0, 2):
            self.status = "Mass cleanup finished with an error (code %s), see the log." % code
            self.notify("error", "Mass cleanup",
                        "The cleanup finished with an error (code %s). See the log for details." % code)
            return
        n = summary.get("planned", 0)
        if n == 0:
            self.status = "Mass cleanup: no known malicious files found."
            extra = ("\n\nFiles with suspicious names but no signatures: %d. Check them manually (list in the log)."
                     % summary["suspects"]) if summary.get("suspects") else ""
            self.notify("info", "Mass cleanup", "No known malicious files found." + extra)
            return
        fam = ", ".join("%s: %d" % (k, v) for k, v in sorted(summary.get("families", {}).items()))
        permanent = self.s("clean_permanent")
        action = "PERMANENTLY DELETED" if permanent else "moved to quarantine (can be restored)"
        text = ("Files to process: %d\n(%s)\n\nMalicious files will be %s.\n"
                "In mixed .htaccess files only the malicious blocks are cut out.\n" % (n, fam, action))
        if summary.get("families", {}).get("core/replace"):
            text += ("Modified Joomla core files (%d) will be replaced with originals"
                     % summary["families"]["core/replace"]
                     + ("." if permanent else "; the previous versions will be kept in quarantine.") + "\n")
        if summary.get("extras"):
            text += "%d extra files found in core folders: they are NOT touched (list in the log).\n" % summary["extras"]
        if summary.get("suspects"):
            text += "\n%d more files with suspicious names but no signatures will NOT be touched, check them manually." % summary["suspects"]
        text += "\n\nContinue?"
        self.status = "Mass cleanup: waiting for your confirmation."
        self.notify("clean_plan", "Mass cleanup", text, permanent=bool(permanent))

    def _finish_clean_apply(self, code, stopped):
        summary = self.clean_summary or {}
        if stopped:
            self.status = "Mass cleanup stopped by the user."
            return
        if not summary or code not in (0, 2):
            self.status = "Mass cleanup finished with an error (code %s), see the log." % code
            self.notify("error", "Mass cleanup",
                        "The cleanup finished with an error (code %s). See the log for details." % code)
            return
        text = "Deleted/moved: %d · .htaccess cleaned: %d" % (summary.get("removed", 0), summary.get("stripped", 0))
        if summary.get("replaced"):
            text += " · replaced with originals: %d" % summary["replaced"]
        if summary.get("failed"):
            text += " · errors: %d" % summary["failed"]
        q = summary.get("quarantine")
        self.finish_removal(self.cleaned, text, qdir=Path(q) if q else None, replaced=self.replaced)
        if summary.get("failed"):
            self.notify("warn", "Mass cleanup", text + "\n\nNot all files could be processed, see the log for details.")
        else:
            self.notify("info", "Mass cleanup",
                        text + "\n\nChange the passwords, find the cause of the compromise and rescan the site.")

    # ------------------------------------------------------------ state for the page
    def state(self, since):
        with self.lock:
            job_view = None
            if self.job is not None:
                job = self.job
                text, pct = job["text"], 0
                if not job["indeterminate"]:
                    done, total = job["done"], job["total"]
                    pct = 100.0 * done / total if total else 100.0
                    elapsed = time.time() - job["t0"]
                    text = ("%s files: %s of %s (%.0f%%) · elapsed %s" % (
                        "Processed" if job["kind"].startswith("clean") else "Scanned",
                        "{:,}".format(done).replace(",", " "), "{:,}".format(total).replace(",", " "), pct,
                        fmt_duration(elapsed)))
                    if 0 < done < total and elapsed > 1:
                        text += " · ~%s left" % fmt_duration((total - done) / (done / elapsed))
                job_view = {"kind": job["kind"], "indeterminate": job["indeterminate"], "percent": round(pct, 1),
                            "text": text, "stopping": job["stopped"]}
            start = max(since, self.log_first)
            lines = self.log[start - self.log_first:]
            return {"app": APP_ID, "version": VERSION, "boot": self.boot, "job": job_view, "status": self.status,
                    "idle_text": self.idle_text, "log": {"from": start, "lines": lines, "next": start + len(lines)},
                    "reports": self.reports_info(), "findings_version": self.findings_version,
                    "findings_total": len(self.findings), "notice": self.notice}

    # ------------------------------------------------------------ server-side file browser
    def fs_list(self, path, mode):
        if mode not in ("dir", "file", "save"):
            mode = "dir"
        if not path:
            if os.name == "nt":
                drives = ["%s:\\" % d for d in string.ascii_uppercase if os.path.exists("%s:\\" % d)]
                return {"path": "", "parent": None, "sep": "\\", "home": str(Path.home()), "drives": drives,
                        "entries": [{"name": d, "kind": "dir"} for d in drives], "mode": mode}
            path = str(Path.home())
        p = Path(path).expanduser()
        try:
            p = p.resolve()
        except (OSError, RuntimeError):
            pass
        if p.is_file():
            p = p.parent
        if not p.is_dir():
            raise ApiError("Folder not found: %s" % path, 404)
        try:
            names = sorted(os.listdir(str(p)), key=lambda x: x.lower())
        except OSError as exc:
            raise ApiError("Cannot read the folder: %s" % exc, 403)
        dirs, files = [], []
        for n in names[:5000]:
            full = p / n
            try:
                if full.is_dir():
                    dirs.append({"name": n, "kind": "dir"})
                elif mode in ("file", "save"):
                    files.append({"name": n, "kind": "file", "size": fmt_size(full.stat().st_size)})
            except OSError:
                continue
        parent = str(p.parent) if p.parent != p else ("" if os.name == "nt" else None)
        return {"path": str(p), "parent": parent, "sep": os.sep, "home": str(Path.home()),
                "drives": [], "entries": dirs + files, "mode": mode}


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = (os.name != "nt")      # on Windows SO_REUSEADDR would let a second copy bind the same port
    app = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ScanBackdoorsGUI/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # ----- security: bind to loopback only + Host check (DNS rebinding) + custom header / JSON (CSRF) -----
    def _allowed_hosts(self):
        port = self.server.server_address[1]
        return {"127.0.0.1:%d" % port, "localhost:%d" % port, "[::1]:%d" % port}

    def _host_ok(self):
        return self.headers.get("Host", "").lower() in self._allowed_hosts()

    def _origin_ok(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        return origin.lower() in set("http://%s" % h for h in self._allowed_hosts())

    def _send(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=True).encode("ascii"), "application/json; charset=utf-8")

    def _error(self, code, message, **extra):
        d = {"error": message}
        d.update(extra)
        self._json(d, code)

    def _guard(self, api):
        if not self._host_ok() or not self._origin_ok():
            self._error(403, "Forbidden host or origin.")
            return False
        if api and self.headers.get(API_HEADER) != API_HEADER_VALUE:
            self._error(403, "Missing %s header." % API_HEADER)
            return False
        return True

    def do_GET(self):
        url = urlparse(self.path)
        path, q = url.path, {k: v[0] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
        app = self.server.app
        try:
            if path in ("/", "/index.html"):
                if not self._guard(False):
                    return
                page = PAGE.replace("__VERSION__", VERSION)
                self._send(200, page.encode("utf-8"), "text/html; charset=utf-8", {
                    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                                               "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'"})
            elif path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
            elif path == "/api/ping":
                if not self._host_ok():
                    return self._error(403, "Forbidden host.")
                self._json({"app": APP_ID, "version": VERSION})
            elif path.startswith("/download/"):
                if not self._guard(False):
                    return
                self._download(app, path.rsplit("/", 1)[1])
            elif path.startswith("/api/"):
                if not self._guard(True):
                    return
                self._json(self._route_get(app, path, q))
            else:
                self._error(404, "Not found")
        except ApiError as e:
            self._error(e.code, str(e), **e.extra)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:                                  # pragma: no cover
            self._error(500, "Internal error: %s" % e)

    def do_POST(self):
        app = self.server.app
        try:
            if not self._guard(True):
                return
            if not (self.headers.get("Content-Type", "").lower().startswith("application/json")):
                return self._error(415, "JSON body required.")
            length = int(self.headers.get("Content-Length") or 0)
            if length > 4 * 1024 * 1024:
                return self._error(413, "Body too large.")
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8") or "{}") if length else {}
            except ValueError:
                return self._error(400, "Invalid JSON.")
            self._json(self._route_post(app, urlparse(self.path).path, body if isinstance(body, dict) else {}))
        except ApiError as e:
            self._error(e.code, str(e), **e.extra)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:                                  # pragma: no cover
            self._error(500, "Internal error: %s" % e)

    def _download(self, app, kind):
        if kind not in ("csv", "xlsx", "json"):
            return self._error(404, "Not found")
        p = app.report_path(kind)
        if not p:
            return self._error(404, "The report has not been created yet.")
        data = p.read_bytes()
        ctype = {"csv": "text/csv; charset=utf-8", "json": "application/json",
                 "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}[kind]
        self._send(200, data, ctype, {"Content-Disposition": 'attachment; filename="%s"' % re.sub(r'[^\w.\-]', "_", p.name)})

    # ----- routes -----
    def _route_get(self, app, path, q):
        if path == "/api/settings":
            return {"settings": app.settings, "defaults": DEFAULTS, "port": self.server.server_address[1]}
        if path == "/api/state":
            try:
                since = int(q.get("since", "0"))
            except ValueError:
                since = 0
            return app.state(since)
        if path == "/api/findings":
            return app.findings_list(q)
        if path == "/api/finding":
            try:
                return app.finding_detail(int(q.get("id", "0")))
            except ValueError:
                raise ApiError("Bad id.")
        if path == "/api/fs":
            return app.fs_list(q.get("path", ""), q.get("mode", "dir"))
        raise ApiError("Not found", 404)

    def _route_post(self, app, path, body):
        ids = body.get("ids") or []
        if path == "/api/settings":
            app.update_settings(body.get("settings") or {})
            return {"ok": True}
        if path == "/api/scan/start":
            if "settings" in body:
                app.update_settings(body["settings"])
            app.start_scan()
            return {"ok": True}
        if path == "/api/clean/plan":
            if "settings" in body:
                app.update_settings(body["settings"])
            app.start_clean_plan()
            return {"ok": True}
        if path == "/api/clean/apply":
            app.start_clean_apply()
            return {"ok": True}
        if path == "/api/clean/cancel":
            app.clean_cancel()
            return {"ok": True}
        if path == "/api/job/stop":
            app.stop_job()
            return {"ok": True}
        if path == "/api/files/preview":
            return app.files_preview(ids)
        if path == "/api/files/do":
            if body.get("action") not in ("quarantine", "delete"):
                raise ApiError("Unknown action.")
            return app.files_do(ids, body["action"], bool(body.get("confirm_protected")))
        if path == "/api/files/paths":
            return {"paths": app.file_paths(ids)}
        if path == "/api/files/reveal":
            try:
                app.reveal(int(body.get("id", 0)))
            except (TypeError, ValueError):
                raise ApiError("Bad id.")
            return {"ok": True}
        if path == "/api/files/whitelist":
            return app.whitelist_add(ids)
        if path == "/api/report/open":
            app.open_report(body.get("kind", ""))
            return {"ok": True}
        if path == "/api/report/folder":
            app.open_reports_folder()
            return {"ok": True}
        if path == "/api/shutdown":
            if app.shutdown_cb:
                app.stop_job()
                t = threading.Timer(0.4, app.shutdown_cb)      # let the HTTP answer reach the browser first
                t.daemon = True
                t.start()
            return {"ok": True}
        raise ApiError("Not found", 404)


# ---------------------------------------------------------------------------
# the page (one self-contained HTML document, no external resources)
# ---------------------------------------------------------------------------

PAGE = r'''<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Backdoors</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270 0 100 100%27%3E%3Ctext y=%27.9em%27 font-size=%2790%27%3E%F0%9F%9B%A1%3C/text%3E%3C/svg%3E">
<style>
:root{--bg:#171a21;--panel:#222733;--field:#11151c;--fg:#e6eaf2;--muted:#aab4c5;--accent:#4f8cff;--accent2:#3976e8;
--border:#394252;--sel:#294a7a;--danger:#7a2a33;--danger2:#9a3440}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{display:flex;flex-direction:column;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
button,input,select{font:inherit;color:inherit}
header{display:flex;align-items:center;gap:12px;padding:8px 14px;background:var(--panel);border-bottom:1px solid var(--border)}
.brand{font-weight:600;font-size:16px;white-space:nowrap}
nav{display:flex;gap:4px}
.tabbtn{background:transparent;border:1px solid transparent;border-radius:6px;padding:6px 14px;cursor:pointer;color:var(--muted)}
.tabbtn:hover{background:var(--border)}
.tabbtn.active{background:var(--sel);color:var(--fg)}
.spacer{flex:1}
.pill{padding:2px 10px;border-radius:99px;font-size:12px;background:#1b4332;color:#b7f0cd}
.pill.off{background:#5a2028;color:#ffdce0}
main{flex:1;min-height:0;position:relative}
.tab{display:none;height:100%;padding:12px 14px;overflow:auto}
.tab.active{display:block}
#tab-run.active{display:grid;grid-template-rows:auto auto auto minmax(150px,3fr) auto minmax(80px,1fr);gap:8px;overflow:hidden}
button{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:6px 12px;cursor:pointer}
button:hover:not(:disabled){background:var(--sel)}
button:disabled{opacity:.45;cursor:default}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover:not(:disabled){background:var(--accent2)}
button.danger{background:var(--danger);border-color:var(--danger);color:#fff}
button.danger:hover:not(:disabled){background:var(--danger2)}
button.ghost{background:transparent}
input[type=text],select{background:var(--field);border:1px solid var(--border);border-radius:6px;padding:6px 9px;min-width:0}
input[type=text]:focus,select:focus{outline:1px solid var(--accent)}
fieldset{border:1px solid var(--border);border-radius:8px;margin:12px 0;padding:10px 14px}
legend{padding:0 6px;color:var(--muted)}
.grid{display:grid;grid-template-columns:230px 1fr auto;gap:8px 10px;align-items:center}
.opts{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px 16px}
.opts label{display:flex;flex-direction:column;gap:3px;color:var(--muted);font-size:13px}
.flags{display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:10px}
.flags label{display:flex;align-items:center;gap:6px;cursor:pointer}
.hint{color:var(--muted);font-size:12px}
.row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.bar{flex:1;min-width:120px;height:14px;background:var(--field);border:1px solid var(--border);border-radius:7px;overflow:hidden;position:relative}
.bar>div{height:100%;width:0;background:var(--accent);transition:width .3s}
.bar.indet>div{width:30%;position:absolute;animation:slide 1.2s infinite ease-in-out}
@keyframes slide{0%{left:-30%}100%{left:100%}}
#progText{color:var(--muted);min-height:20px}
.panel{border:1px solid var(--border);border-radius:8px;padding:8px;display:flex;flex-direction:column;min-height:0}
.panel>h4{margin:0 0 6px;font-weight:500;color:var(--muted)}
.tablewrap{flex:1;min-height:0;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--field);outline:none}
table{border-collapse:collapse;width:100%;min-width:900px;table-layout:fixed}
th{position:sticky;top:0;background:var(--panel);text-align:left;padding:6px 8px;cursor:pointer;user-select:none;border-bottom:1px solid var(--border);white-space:nowrap}
th:hover{background:var(--sel)}
th .arr{color:var(--accent)}
td{padding:4px 8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;border-bottom:1px solid #1d222c}
tr.lv-HIGH td{background:#5a2028;color:#ffdce0}
tr.lv-MEDIUM td{background:#5b451d;color:#fff0c2}
tr.lv-LOW td{background:#174a43;color:#d5fff5}
tr.sel td{background:var(--sel);color:#fff;box-shadow:inset 0 1px 0 var(--accent),inset 0 -1px 0 var(--accent)}
tr{cursor:default}
pre{margin:0;white-space:pre-wrap;word-break:break-all;font:12.5px/1.45 ui-monospace,Consolas,Menlo,monospace}
#preview{background:var(--field);border:1px solid var(--border);border-radius:6px;padding:8px;max-height:150px;overflow:auto;min-height:48px;user-select:text;white-space:pre-wrap;word-break:break-all;font:12.5px/1.45 ui-monospace,Consolas,Menlo,monospace}
#log{flex:1;min-height:0;overflow:auto;background:var(--field);border:1px solid var(--border);border-radius:6px;padding:8px;user-select:text}
footer{display:flex;gap:12px;align-items:center;padding:5px 14px;background:var(--panel);border-top:1px solid var(--border);font-size:13px}
footer code{color:var(--muted)}
#ctx{position:fixed;display:none;z-index:50;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:4px;min-width:230px;box-shadow:0 6px 24px #0008}
#ctx div{padding:6px 12px;border-radius:5px;cursor:pointer}
#ctx div:hover{background:var(--sel)}
#ctx hr{border:0;border-top:1px solid var(--border);margin:4px 0}
.overlay{position:fixed;inset:0;background:#000a;display:flex;align-items:center;justify-content:center;z-index:100}
.dlg{background:var(--panel);border:1px solid var(--border);border-radius:10px;width:min(640px,92vw);max-height:86vh;display:flex;flex-direction:column;box-shadow:0 10px 40px #000a}
.dlg.wide{width:min(760px,94vw)}
.dlg h3{margin:0;padding:12px 16px;border-bottom:1px solid var(--border);font-size:16px}
.dlg .body{padding:14px 16px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.dlg .btns{padding:10px 16px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end}
.dlg.error h3{color:#ff9aa5}.dlg.warn h3{color:#ffd27a}
#toasts{position:fixed;right:14px;top:60px;display:flex;flex-direction:column;gap:8px;z-index:200}
.toast{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:6px;padding:9px 14px;max-width:420px;box-shadow:0 6px 24px #0008;white-space:pre-wrap}
.toast.error{border-left-color:#ff6b7d}.toast.ok{border-left-color:#4cc38a}
.fsbar{display:flex;gap:6px;margin-bottom:8px;align-items:center}.fsbar input{flex:1}
.fslist{border:1px solid var(--border);border-radius:6px;background:var(--field);height:300px;overflow:auto}
.fslist div{padding:5px 10px;cursor:pointer;display:flex;justify-content:space-between;gap:10px}
.fslist div:hover{background:var(--sel)}.fslist div.picked{background:var(--sel)}
.fslist small{color:var(--muted)}
.logbtns{display:flex;gap:6px;margin-left:auto}
</style></head>
<body>
<header>
  <div class="brand">🛡️ Scan Backdoors</div>
  <nav>
    <button class="tabbtn" data-tab="settings">Settings</button>
    <button class="tabbtn" data-tab="run">Run and results</button>
  </nav>
  <div class="spacer"></div>
  <span id="conn" class="pill off">connecting…</span>
  <button id="quitBtn" class="ghost" title="Stop the local server">Quit server</button>
</header>
<main>
  <section id="tab-settings" class="tab">
    <div id="pathGrid" class="grid"></div>
    <fieldset><legend>Scan options</legend>
      <div id="optGrid" class="opts"></div>
      <div id="flagRow" class="flags"></div>
    </fieldset>
    <fieldset><legend>Mass cleanup (clean_malware.py)</legend>
      <div id="cleanRow" class="flags" style="margin-top:0"></div>
    </fieldset>
    <div class="row"><span class="hint">Settings are saved automatically and applied on the next launch.</span><span class="spacer"></span>
      <button id="goRun">Go to run →</button></div>
  </section>

  <section id="tab-run" class="tab">
    <div class="row">
      <button id="startBtn" class="primary">▶ Start scan</button>
      <button id="stopBtn" disabled>■ Stop</button>
      <div id="bar" class="bar"><div id="barFill"></div></div>
    </div>
    <div id="progText"></div>
    <div class="row"><span>Reports:</span>
      <button data-rep="csv" disabled>📂 CSV</button><button data-rep="xlsx" disabled>📂 XLSX</button><button data-rep="json" disabled>📂 JSON</button>
      <button id="repFolder">📁 Reports folder</button>
      <span class="hint">Download:</span><a class="hint" href="/download/csv">CSV</a><a class="hint" href="/download/xlsx">XLSX</a><a class="hint" href="/download/json">JSON</a>
    </div>
    <div class="panel">
      <div class="row" style="margin-bottom:6px">
        <span>Level:</span>
        <select id="fLevel"><option>All</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
        <span>Search (file / signature):</span><input id="fQuery" type="text" size="26">
        <button id="fReset">Reset filters</button>
        <span class="spacer"></span><span id="count" class="hint"></span>
      </div>
      <div class="row" style="margin-bottom:6px">
        <button data-act="reveal">📁 Show file</button>
        <button data-act="quarantine">📦 Quarantine</button>
        <button data-act="delete" class="danger">🗑 Delete from disk</button>
        <button id="cleanBtn">🧹 Mass cleanup</button>
        <span class="hint">Click, Ctrl/Shift+click or Ctrl+A to select. Right-click for more. “Mass cleanup” removes the known families (.htaccess locks, filefuns) across the whole site.</span>
      </div>
      <div id="tableWrap" class="tablewrap" tabindex="0">
        <table>
          <colgroup><col style="width:80px"><col style="width:62px"><col><col style="width:62px"><col style="width:84px"><col style="width:132px"><col style="width:72px"><col></colgroup>
          <thead><tr id="thead">
            <th data-col="level">Level</th><th data-col="score">Score</th><th data-col="file">File</th><th data-col="line">Line</th>
            <th data-col="size">Size</th><th data-col="date">Date</th><th data-col="delete">Delete</th><th data-col="signature">Signature</th>
          </tr></thead>
          <tbody id="tbody"></tbody>
        </table>
      </div>
    </div>
    <div id="preview" class="hint">Select a row to see the suspicious code snippet.</div>
    <div class="panel">
      <div class="row"><h4 style="margin:0">Log</h4><div class="logbtns"><button id="logCopy">Copy log</button><button id="logClear">Clear view</button></div></div>
      <pre id="log"></pre>
    </div>
  </section>
</main>
<footer><span id="status">Ready to run</span><span class="spacer"></span>
  <span class="hint">Bookmark this page: <code id="selfUrl"></code> · v__VERSION__</span></footer>
<div id="ctx"></div>
<div id="toasts"></div>
<script>
(() => {
'use strict';
const $ = (id) => document.getElementById(id);
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ESC[c]);
const S = {settings: {}, tab: 'run', logNext: 0, ver: -1, noticeSeq: null, boot: null, sel: new Set(), order: [], last: null,
           sort: 'score', desc: true, job: null, rows: [], saveTimer: null, online: false, fTimer: null};

async function api(path, body) {
  const opt = {headers: {'X-Requested-With': 'scan-backdoors-gui'}};
  if (body !== undefined) { opt.method = 'POST'; opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  let j = {};
  try { j = await r.json(); } catch (e) { /* not JSON */ }
  if (!r.ok) { const err = new Error(j.error || r.statusText); err.data = j; err.status = r.status; throw err; }
  return j;
}
function toast(msg, kind) {
  const d = document.createElement('div'); d.className = 'toast ' + (kind || ''); d.textContent = msg;
  $('toasts').appendChild(d); setTimeout(() => d.remove(), kind === 'error' ? 7000 : 4000);
}
function modal(o) {
  return new Promise((resolve) => {
    const ov = document.createElement('div'); ov.className = 'overlay';
    const dlg = document.createElement('div'); dlg.className = 'dlg ' + (o.cls || '') + (o.wide ? ' wide' : '');
    const h = document.createElement('h3'); h.textContent = o.title || '';
    const body = document.createElement('div'); body.className = 'body';
    if (o.node) body.appendChild(o.node); else body.textContent = o.text || '';
    const btns = document.createElement('div'); btns.className = 'btns';
    const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); close(null); } };
    const close = (v) => { document.removeEventListener('keydown', onKey, true); ov.remove(); resolve(v); };
    (o.buttons || [{text: 'OK', value: true, cls: 'primary'}]).forEach((b) => {
      const el = document.createElement('button'); el.textContent = b.text; if (b.cls) el.className = b.cls;
      el.addEventListener('click', () => close(typeof b.value === 'function' ? b.value() : b.value)); btns.appendChild(el);
    });
    document.addEventListener('keydown', onKey, true);
    dlg.append(h, body, btns); ov.appendChild(dlg); document.body.appendChild(ov);
    const first = btns.querySelector('.primary, .danger') || btns.lastChild; if (first) first.focus();
  });
}
const confirmDlg = (title, text, ok, danger) => modal({title, text, cls: danger ? 'warn' : '', buttons: [
  {text: 'Cancel', value: false}, {text: ok || 'Continue', value: true, cls: danger ? 'danger' : 'primary'}]});
const msgDlg = (title, text, kind) => modal({title, text, cls: kind === 'error' ? 'error' : kind === 'warn' ? 'warn' : ''});
const showErr = (e) => toast(e && e.message ? e.message : String(e), 'error');

// ---------------------------------------------------------------- settings form
const PATHS = [['scanner_path', 'Scanner script', 'file'], ['site_dir', 'Site folder', 'dir'], ['baseline_dir', 'Clean Joomla (optional)', 'dir'],
  ['whitelist_path', 'Whitelist (optional)', 'file'], ['csv_path', 'CSV report', 'save'], ['xlsx_path', 'XLSX report (optional)', 'save'],
  ['json_path', 'JSON report (optional)', 'save']];
const OPTS = [['max_size', 'File size, MB'], ['max_matches', 'Max findings/level'], ['min_score', 'Minimum score'],
  ['since', 'Modified after (14d or 2026-09-01)'], ['workers', 'Processes (0 = auto)'], ['exclude_ext', 'Exclude extensions (comma-separated)'],
  ['exclude_dir', 'Exclude folders (comma-separated)']];
const FLAGS = [['only_critical', 'Critical only'], ['no_warnings', 'No warnings'], ['no_csv', 'Do not create CSV'], ['auto_open', 'Open the CSV after scanning']];
const CLEAN = [['clean_permanent', 'Delete permanently (no quarantine)'], ['clean_fm', 'Include web file managers (elp.php etc.)'],
  ['clean_core', 'Replace modified core files with originals (needs a clean Joomla of the same version)']];

function buildSettings() {
  const grid = $('pathGrid'); grid.innerHTML = '';
  PATHS.forEach(([k, label, mode]) => {
    const l = document.createElement('label'); l.textContent = label + ':'; l.htmlFor = 'set_' + k;
    const i = document.createElement('input'); i.type = 'text'; i.id = 'set_' + k; i.dataset.key = k;
    const b = document.createElement('button'); b.textContent = 'Browse…';
    b.addEventListener('click', async () => { const p = await browse(mode, i.value, label); if (p != null) { i.value = p; onSettingChanged(); } });
    grid.append(l, i, b);
  });
  const og = $('optGrid'); og.innerHTML = '';
  OPTS.forEach(([k, label]) => {
    const l = document.createElement('label'); l.textContent = label;
    const i = document.createElement('input'); i.type = 'text'; i.id = 'set_' + k; i.dataset.key = k; l.appendChild(i); og.appendChild(l);
  });
  const flag = (box, list) => { box.innerHTML = ''; list.forEach(([k, label]) => {
    const l = document.createElement('label'); const c = document.createElement('input'); c.type = 'checkbox'; c.id = 'set_' + k; c.dataset.key = k;
    l.append(c, document.createTextNode(label)); box.appendChild(l); }); };
  flag($('flagRow'), FLAGS); flag($('cleanRow'), CLEAN);
  document.querySelectorAll('[data-key]').forEach((el) => { el.addEventListener('input', onSettingChanged); el.addEventListener('change', onSettingChanged); });
}
function fillSettings(s) {
  Object.keys(s).forEach((k) => { const el = $('set_' + k); if (!el) return; if (el.type === 'checkbox') el.checked = !!s[k]; else el.value = s[k]; });
}
function readSettings() {
  const out = {};
  document.querySelectorAll('[data-key]').forEach((el) => { out[el.dataset.key] = el.type === 'checkbox' ? el.checked : el.value; });
  return out;
}
function onSettingChanged() { clearTimeout(S.saveTimer); S.saveTimer = setTimeout(saveSettings, 500); }
async function saveSettings() { clearTimeout(S.saveTimer); S.saveTimer = null; try { await api('/api/settings', {settings: readSettings()}); } catch (e) { showErr(e); } }

// ---------------------------------------------------------------- server-side file browser
async function browse(mode, start, title) {
  let cur = '', picked = null, data = null;
  const node = document.createElement('div');
  const bar = document.createElement('div'); bar.className = 'fsbar';
  const up = document.createElement('button'); up.textContent = '↑ Up';
  const home = document.createElement('button'); home.textContent = 'Home';
  const pathIn = document.createElement('input'); pathIn.type = 'text';
  const go = document.createElement('button'); go.textContent = 'Go';
  bar.append(up, home, pathIn, go);
  const list = document.createElement('div'); list.className = 'fslist';
  const nameRow = document.createElement('div'); nameRow.className = 'fsbar'; nameRow.style.marginTop = '8px';
  const nameIn = document.createElement('input'); nameIn.type = 'text'; nameIn.placeholder = 'file name';
  if (mode === 'save') { const lab = document.createElement('span'); lab.textContent = 'File name:'; nameRow.append(lab, nameIn); }
  node.append(bar, list); if (mode === 'save') node.appendChild(nameRow);
  const join = (name) => (cur ? cur + (cur.endsWith(data.sep) ? '' : data.sep) : '') + name;
  const load = async (p) => {
    try { data = await api('/api/fs?mode=' + encodeURIComponent(mode) + '&path=' + encodeURIComponent(p || '')); }
    catch (e) { if (p) return load(''); showErr(e); return; }
    cur = data.path; pathIn.value = cur; picked = null; list.innerHTML = '';
    data.entries.forEach((en) => {
      const d = document.createElement('div'); const n = document.createElement('span');
      n.textContent = (en.kind === 'dir' ? '📁 ' : '📄 ') + en.name; d.appendChild(n);
      if (en.size) { const s = document.createElement('small'); s.textContent = en.size; d.appendChild(s); }
      d.addEventListener('click', () => {
        if (en.kind === 'dir') { load(join(en.name)); return; }
        picked = join(en.name); nameIn.value = en.name;
        list.querySelectorAll('.picked').forEach((x) => x.classList.remove('picked')); d.classList.add('picked');
      });
      d.addEventListener('dblclick', () => { if (en.kind === 'file' && mode === 'file') { const b = document.querySelector('.overlay .btns .primary'); if (b) b.click(); } });
      list.appendChild(d);
    });
  };
  up.addEventListener('click', () => load(data && data.parent != null ? data.parent : ''));
  home.addEventListener('click', () => load(data ? data.home : ''));
  go.addEventListener('click', () => load(pathIn.value));
  pathIn.addEventListener('keydown', (e) => { if (e.key === 'Enter') load(pathIn.value); });
  await load((start || '').trim());
  if (!data) return null;
  return modal({title: 'Choose ' + (mode === 'dir' ? 'a folder' : 'a file') + (title ? ' — ' + title : ''), node, wide: true, buttons: [
    {text: 'Cancel', value: null},
    {text: mode === 'dir' ? 'Select this folder' : 'Select', cls: 'primary', value: () => {
      if (mode === 'dir') return cur;
      if (mode === 'save') { const n = nameIn.value.trim(); return n ? join(n) : null; }
      return picked; }}]});
}

// ---------------------------------------------------------------- findings table
function rowHtml(r) {
  const cells = [r.level, r.score, r.file, r.line, r.size, r.date, r.delete, r.signature];
  return '<tr data-id="' + Number(r.id) + '" class="lv-' + esc(r.level) + (S.sel.has(r.id) ? ' sel' : '') + '">' +
    cells.map((c) => '<td title="' + esc(c) + '">' + esc(c) + '</td>').join('') + '</tr>';
}
function renderRows(data) {
  S.rows = data.rows; S.order = data.rows.map((r) => r.id);
  const keep = new Set(S.order); S.sel.forEach((id) => { if (!keep.has(id)) S.sel.delete(id); });
  $('tbody').innerHTML = data.rows.map(rowHtml).join('');
  let t = 'Showing ' + data.shown + ' of ' + data.total;
  if (data.matched > data.shown) t += ' (table limit ' + data.limit + ', narrow the filter or open the CSV)';
  if (data.hidden_done) t += ' · hidden as handled: ' + data.hidden_done;
  $('count').textContent = t;
  document.querySelectorAll('#thead th').forEach((th) => {
    const a = th.querySelector('.arr'); if (a) a.remove();
    if (th.dataset.col === S.sort) { const s = document.createElement('span'); s.className = 'arr'; s.textContent = S.desc ? ' ▼' : ' ▲'; th.appendChild(s); }
  });
  showPreview();
}
async function refreshFindings() {
  const p = new URLSearchParams({level: $('fLevel').value, q: $('fQuery').value, sort: S.sort, desc: S.desc ? '1' : '0'});
  try { const d = await api('/api/findings?' + p.toString()); S.ver = d.version; renderRows(d); } catch (e) { showErr(e); }
}
function paintSel() {
  document.querySelectorAll('#tbody tr').forEach((tr) => tr.classList.toggle('sel', S.sel.has(Number(tr.dataset.id))));
}
function selectRow(id, ev) {
  if (ev && ev.shiftKey && S.last != null && S.order.includes(S.last)) {
    const a = S.order.indexOf(S.last), b = S.order.indexOf(id); const lo = Math.min(a, b), hi = Math.max(a, b);
    if (!(ev.ctrlKey || ev.metaKey)) S.sel.clear(); for (let i = lo; i <= hi; i++) S.sel.add(S.order[i]);
  } else if (ev && (ev.ctrlKey || ev.metaKey)) { if (S.sel.has(id)) S.sel.delete(id); else S.sel.add(id); S.last = id; }
  else { S.sel.clear(); S.sel.add(id); S.last = id; }
  paintSel(); showPreview();
}
let pvTimer = null;
function showPreview() {
  clearTimeout(pvTimer);
  pvTimer = setTimeout(async () => {
    const el = $('preview'); const ids = [...S.sel];
    if (ids.length === 0) { el.className = 'hint'; el.textContent = 'Select a row to see the suspicious code snippet.'; return; }
    if (ids.length > 1) { const files = new Set(S.rows.filter((r) => S.sel.has(r.id)).map((r) => r.file)); el.className = ''; el.textContent = 'Rows selected: ' + ids.length + ', files: ' + files.size; return; }
    try {
      const d = await api('/api/finding?id=' + ids[0]); el.className = '';
      el.textContent = 'File: ' + d.file + '\nLevel: ' + d.level + ' | Score: ' + d.score + ' | Line: ' + d.line + ' | Size: ' + d.size + ' | Date: ' + d.date +
        '\nSignature: ' + d.signature + (d.sha256 ? '\nSHA-256: ' + d.sha256 : '') + '\n' + '-'.repeat(72) + '\n' + (d.snippet || '(The snippet is not stored in the CSV.)');
    } catch (e) { el.textContent = ''; }
  }, 80);
}

// ---------------------------------------------------------------- actions on files
async function saveFromServer() { const s = await api('/api/settings'); S.settings = s.settings; fillSettings(s.settings); }
async function copyText(t) {
  try { await navigator.clipboard.writeText(t); return; } catch (e) { /* fall back */ }
  const ta = document.createElement('textarea'); ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
}
async function fileAction(act) {
  const ids = [...S.sel];
  if (!ids.length) { toast('Select one or more rows in the table first.'); return; }
  try {
    if (act === 'reveal') { await api('/api/files/reveal', {id: ids[0]}); return; }
    if (act === 'copyPath') { const r = await api('/api/files/paths', {ids}); await copyText(r.paths.join('\n')); toast('Path copied to the clipboard', 'ok'); return; }
    if (act === 'copySha') { const d = await api('/api/finding?id=' + ids[0]); if (!d.sha256) { toast('No SHA-256 in the report.', 'error'); return; } await copyText(d.sha256); toast('SHA-256 copied to the clipboard', 'ok'); return; }
    if (act === 'whitelist') {
      if (!(await confirmDlg('Add to whitelist', 'The hashes of the selected files will be added to the whitelist: the scanner will stop reporting them until the file content changes.\n\nContinue?'))) return;
      const r = await api('/api/files/whitelist', {ids}); toast(r.text + '\n' + r.path, 'ok'); await saveFromServer(); return;
    }
    const pv = await api('/api/files/preview', {ids});
    if (!pv.files.length) { const r = await api('/api/files/do', {ids, action: act}); toast(r.text, 'ok'); return; }
    const verb = act === 'quarantine' ? 'move to quarantine' : 'PERMANENTLY delete';
    let text = 'Action: ' + verb + '. Files: ' + pv.files.length + '\n\n' + pv.files.slice(0, 8).map((f) => '  • ' + f.rel + '  [' + f.level + ']').join('\n');
    if (pv.files.length > 8) text += '\n  … and ' + (pv.files.length - 8) + ' more';
    if (pv.warn_levels) text += '\n\nThe files include MEDIUM/LOW levels: false positives are possible. Check the code snippet.';
    if (!(await confirmDlg('Confirmation', text, act === 'quarantine' ? 'Move to quarantine' : 'Delete', act === 'delete'))) return;
    const prot = pv.files.filter((f) => f.protected).map((f) => f.rel);
    if (prot.length && !(await confirmDlg('Important Joomla file', 'The list contains system files:\n  ' + prot.join('\n  ') +
        '\n\nDeleting them may take the site down. Such files are usually cleaned manually. Continue?', 'Continue anyway', true))) return;
    const r = await api('/api/files/do', {ids, action: act, confirm_protected: prot.length > 0});
    toast(r.text, r.failed.length ? 'error' : 'ok');
    if (r.failed.length) msgDlg('Some files were not processed', r.failed.slice(0, 8).map((f) => f[0] + ': ' + f[1]).join('\n'), 'error');
  } catch (e) { showErr(e); }
}

// ---------------------------------------------------------------- state polling
function setBusy(job) {
  S.job = job;
  $('startBtn').disabled = !!job; $('cleanBtn').disabled = !!job; $('stopBtn').disabled = !job || !!(job && job.stopping);
  const bar = $('bar');
  if (job) { bar.classList.toggle('indet', !!job.indeterminate); $('barFill').style.width = job.indeterminate ? '' : job.percent + '%'; $('progText').textContent = job.text; }
  else { bar.classList.remove('indet'); $('barFill').style.width = '0'; }
}
function appendLog(lines) {
  if (!lines.length) return; const el = $('log'); const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  el.textContent += lines.join('');
  if (el.textContent.length > 600000) el.textContent = el.textContent.slice(-400000);
  if (atBottom) el.scrollTop = el.scrollHeight;
}
async function onNotice(n) {
  try {
    if (n.kind === 'offer_csv') { if (await confirmDlg(n.title, n.text, 'Open CSV')) await api('/api/report/open', {kind: 'csv'}); }
    else if (n.kind === 'clean_plan') {
      const go = await confirmDlg(n.title, n.text, n.permanent ? 'Delete permanently' : 'Move to quarantine', true);
      if (go) await api('/api/clean/apply', {}); else await api('/api/clean/cancel', {});
    } else await msgDlg(n.title, n.text, n.kind);
  } catch (e) { showErr(e); }
}
async function poll() {
  let delay = 1500;
  try {
    const st = await api('/api/state?since=' + S.logNext);
    if (!S.online) { S.online = true; $('conn').textContent = 'connected'; $('conn').className = 'pill'; }
    if (S.boot !== null && S.boot !== st.boot) { S.logNext = 0; $('log').textContent = ''; await saveFromServer(); }
    S.boot = st.boot;
    if (st.log.from > S.logNext && S.logNext !== 0) $('log').textContent += '… (older lines were dropped)\n';
    appendLog(st.log.lines); S.logNext = st.log.next;
    setBusy(st.job);
    if (!st.job) $('progText').textContent = st.idle_text || '';
    $('status').textContent = st.status;
    ['csv', 'xlsx', 'json'].forEach((k) => { const b = document.querySelector('[data-rep="' + k + '"]'); if (b) b.disabled = !st.reports[k].exists; });
    if (st.findings_version !== S.ver) await refreshFindings();
    if (S.noticeSeq === null) S.noticeSeq = st.notice ? st.notice.seq : 0;       // do not replay old dialogs after a reload
    else if (st.notice && st.notice.seq !== S.noticeSeq) { S.noticeSeq = st.notice.seq; onNotice(st.notice); }
    delay = st.job ? 500 : 1500;
  } catch (e) {
    if (S.online) { S.online = false; $('conn').textContent = 'server not reachable'; $('conn').className = 'pill off'; }
    delay = 2000;
  }
  setTimeout(poll, document.hidden ? Math.max(delay, 2500) : delay);
}

// ---------------------------------------------------------------- tabs and wiring
function showTab(t) {
  S.tab = t; location.hash = t;
  document.querySelectorAll('.tab').forEach((el) => el.classList.toggle('active', el.id === 'tab-' + t));
  document.querySelectorAll('.tabbtn').forEach((b) => b.classList.toggle('active', b.dataset.tab === t));
}
function showCtx(x, y) {
  const m = $('ctx');
  m.innerHTML = [['reveal', '📁 Show file'], ['copyPath', '📋 Copy path'], ['copySha', '📋 Copy SHA-256'], ['whitelist', '✅ To whitelist (false positive)'], ['-'],
    ['quarantine', '📦 Move to quarantine'], ['delete', '🗑 Delete from disk']].map((a) => a[0] === '-' ? '<hr>' : '<div data-a="' + a[0] + '">' + esc(a[1]) + '</div>').join('');
  m.style.display = 'block'; m.style.left = Math.max(0, Math.min(x, innerWidth - 250)) + 'px'; m.style.top = Math.max(0, Math.min(y, innerHeight - 230)) + 'px';
}
async function init() {
  buildSettings();
  $('selfUrl').textContent = location.origin + '/';
  document.querySelectorAll('.tabbtn').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
  $('goRun').addEventListener('click', async () => { await saveSettings(); showTab('run'); });
  $('startBtn').addEventListener('click', async () => {
    try { await saveSettings(); await api('/api/scan/start', {settings: readSettings()}); $('log').textContent = ''; S.logNext = 0; S.sel.clear(); toast('Scan started', 'ok'); }
    catch (e) { msgDlg('Parameters not filled in', e.message, 'error'); }
  });
  $('stopBtn').addEventListener('click', () => api('/api/job/stop', {}).catch(showErr));
  $('cleanBtn').addEventListener('click', async () => { try { await saveSettings(); await api('/api/clean/plan', {settings: readSettings()}); } catch (e) { msgDlg('Mass cleanup', e.message, 'error'); } });
  document.querySelectorAll('[data-rep]').forEach((b) => b.addEventListener('click', () => api('/api/report/open', {kind: b.dataset.rep}).catch(showErr)));
  $('repFolder').addEventListener('click', () => api('/api/report/folder', {}).catch(showErr));
  document.querySelectorAll('[data-act]').forEach((b) => b.addEventListener('click', () => fileAction(b.dataset.act)));
  $('fLevel').addEventListener('change', refreshFindings);
  $('fQuery').addEventListener('input', () => { clearTimeout(S.fTimer); S.fTimer = setTimeout(refreshFindings, 250); });
  $('fReset').addEventListener('click', () => { $('fLevel').value = 'All'; $('fQuery').value = ''; refreshFindings(); });
  $('thead').addEventListener('click', (e) => {
    const th = e.target.closest('th'); if (!th) return; const c = th.dataset.col;
    if (S.sort === c) S.desc = !S.desc; else { S.sort = c; S.desc = (c === 'score'); } refreshFindings();
  });
  const tb = $('tbody');
  tb.addEventListener('click', (e) => { const tr = e.target.closest('tr'); if (tr) selectRow(Number(tr.dataset.id), e); });
  tb.addEventListener('dblclick', (e) => { const tr = e.target.closest('tr'); if (tr) { S.sel.clear(); S.sel.add(Number(tr.dataset.id)); paintSel(); fileAction('reveal'); } });
  tb.addEventListener('contextmenu', (e) => {
    const tr = e.target.closest('tr'); if (!tr) return; e.preventDefault(); const id = Number(tr.dataset.id);
    if (!S.sel.has(id)) selectRow(id, null); showCtx(e.clientX, e.clientY);
  });
  $('ctx').addEventListener('click', (e) => { const d = e.target.closest('[data-a]'); $('ctx').style.display = 'none'; if (d) fileAction(d.dataset.a); });
  document.addEventListener('click', (e) => { if (!e.target.closest('#ctx')) $('ctx').style.display = 'none'; });
  document.addEventListener('scroll', () => { $('ctx').style.display = 'none'; }, true);
  $('tableWrap').addEventListener('keydown', (e) => {
    if (e.key === 'Delete') { e.preventDefault(); fileAction('delete'); }
    else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a') { e.preventDefault(); S.order.forEach((id) => S.sel.add(id)); paintSel(); showPreview(); }
    else if (e.key === 'Escape') { S.sel.clear(); paintSel(); showPreview(); }
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault(); if (!S.order.length) return; let i = S.last != null ? S.order.indexOf(S.last) : -1;
      i = e.key === 'ArrowDown' ? Math.min(i + 1, S.order.length - 1) : Math.max(i - 1, 0); selectRow(S.order[i], e.shiftKey ? {shiftKey: true} : null);
      const tr = document.querySelector('#tbody tr[data-id="' + S.order[i] + '"]'); if (tr && tr.scrollIntoView) tr.scrollIntoView({block: 'nearest'});
    }
  });
  $('logCopy').addEventListener('click', async () => { await copyText($('log').textContent); toast('Log copied', 'ok'); });
  $('logClear').addEventListener('click', () => { $('log').textContent = ''; });
  $('quitBtn').addEventListener('click', async () => {
    if (!(await confirmDlg('Quit', 'Stop the local server? A running scan will be stopped. To use the GUI again start scan_backdoors_gui.py (or start.bat).', 'Quit server', true))) return;
    try { await api('/api/shutdown', {}); } catch (e) { /* the server is going away */ }
    document.body.innerHTML = '<div style="padding:40px;font:16px system-ui;color:#e6eaf2">Server stopped. You can close this tab.</div>';
  });
  try {
    const s = await api('/api/settings'); S.settings = s.settings; fillSettings(s.settings);
    const h = location.hash.replace('#', '');
    showTab(h === 'settings' || h === 'run' ? h : (s.settings.site_dir ? 'run' : 'settings'));
  } catch (e) { showTab('run'); }
  poll();
}
window.__sbg = {esc, rowHtml, renderRows, selectRow, fileAction, S, init, onNotice, browse};
document.addEventListener('DOMContentLoaded', init);
})();
</script>
</body></html>
'''


# ---------------------------------------------------------------------------
# startup
# ---------------------------------------------------------------------------

def ping(port):
    """Is one of OUR servers already listening on this port? (so that a second start just opens the browser)"""
    try:
        req = Request("http://127.0.0.1:%d/api/ping" % port)
        with urlopen(req, timeout=1.5) as r:
            return json.loads(r.read().decode("utf-8")).get("app") == APP_ID
    except Exception:
        return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="Browser front end for scan_backdoors.py, v" + VERSION)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="port on 127.0.0.1 (default %d; keep it fixed to use a bookmark)" % DEFAULT_PORT)
    ap.add_argument("--no-browser", action="store_true", help="do not open the browser")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:
            pass

    if ping(args.port):
        url = "http://127.0.0.1:%d/" % args.port
        print("Scan Backdoors GUI is already running: %s" % url)
        if not args.no_browser:
            webbrowser.open(url)
        return 0

    server, port = None, args.port
    for p in range(args.port, args.port + 20):
        try:
            server = Server(("127.0.0.1", p), Handler)
            port = p
            break
        except OSError:
            continue
    if server is None:
        print("Could not bind a port in the range %d-%d." % (args.port, args.port + 19))
        return 1
    app = App(port)
    app.shutdown_cb = server.shutdown
    server.app = app
    url = "http://127.0.0.1:%d/" % port
    print("Scan Backdoors GUI %s" % VERSION)
    print("Open in your browser: %s   (bookmark it)" % url)
    if port != args.port:
        print("NOTE: port %d was busy, using %d. The bookmark URL changes when the port does." % (args.port, port))
    print("The server listens on 127.0.0.1 only. Press Ctrl+C or use 'Quit server' in the page to stop.")
    if not args.no_browser:
        threading.Timer(0.6, webbrowser.open, [url]).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop_job()
        server.server_close()
    print("Stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
