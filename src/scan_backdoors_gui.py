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
import errno
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
try:                                       # single source of truth: version.py next to this file
    from version import VERSION, MIN_SCANNER
except ImportError:                        # the GUI is useless without the scanner, but never crash on import
    VERSION, MIN_SCANNER = "3.3.1", "2.1"    # keep in sync with src/version.py (tests/test_release.py checks it)
DEFAULT_PORT = 8765
PORT_FALLBACK_SPAN = 100    # how many consecutive ports the startup loop tries (see _pick_port)
HERE = Path(__file__).resolve().parent
CONFIG_PATH = Path.home() / ".scan_backdoors_gui.json"

# The library of AI-prepared signatures the user confirms in the GUI.
# The scanner reads it via --user-signatures on the next scan.
USER_SIG_FILENAME = ".scan_backdoors_user_signatures.json"
USER_SIGS_PATH = Path.home() / USER_SIG_FILENAME
API_HEADER = "X-Requested-With"
API_HEADER_VALUE = "scan-backdoors-gui"
MAX_TABLE_ROWS = 5000          # a bigger table is heavy for the browser; the full list is in the CSV
LOG_KEEP = 4000
LEVEL_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
# Files whose deletion may "take the site down": the server insists on an extra confirmation
PROTECTED_FILES = {"configuration.php", "index.php", ".htaccess", "administrator/index.php"}

# The signature library: bounded proposal calls per real-threat file (mirrors the review bounds)
AI_SIGNATURE_MAX_FILES = 5       # at most this many real-threat files get a proposal
AI_SIGNATURE_MAX_TOKENS = 700    # max answer size for a proposal
AI_SIGNATURE_REASON_MAX = 400
AI_SIGNATURE_LABEL_MAX = 120
USER_SIG_KINDS = ("php", "js", "html", "htaccess", "ini", "text")
USER_SIG_SEVERITIES = ("critical", "obfuscated", "warning")

DEFAULTS = {
    "scanner_path": str(HERE / "scan_backdoors.py"), "site_dir": "", "csv_path": str(Path.cwd() / "report-data.csv"),
    "xlsx_path": "", "json_path": "", "baseline_dir": "", "whitelist_path": "", "since": "", "max_size": "5",
    "max_matches": "60", "min_score": "0", "workers": "0", "exclude_ext": "", "exclude_dir": "",
    "only_critical": False, "no_warnings": False, "no_csv": False, "auto_open": False,
    "clean_permanent": False, "clean_fm": False, "clean_core": False,
    "ai_enabled": False, "ai_base_url": "http://127.0.0.1:8080/v1", "ai_model": "",
}
BOOL_KEYS = {k for k, v in DEFAULTS.items() if isinstance(v, bool)}

# ------------------------------------------------------------------------------
# Local AI - review of suspicious files against a localhost model
# ------------------------------------------------------------------------------
AI_HOSTS = {"127.0.0.1", "localhost", "::1"}
# The file contents and snippets are sent to the endpoint, so the endpoint must stay on localhost.
AI_MAX_CONTENT = 24000        # max chars of file context sent per file
AI_MAX_FINDINGS = 5           # max findings sent per file
AI_MAX_FILES = 100            # a local model is slow: the review stops after this many unique files
AI_CONTEXT_LINES = 8          # lines above/below a finding line, included in the prompt
AI_START_BYTES = 2000         # the first bytes of the file, included in the prompt
AI_PROMPT_FILE_BYTES = 65536  # max bytes read from a file to build the context
AI_TIMEOUT = 180              # per-request timeout (seconds) - a local model can be slow
AI_VALID_STATUSES = ("real_threat", "false_positive", "uncertain", "error")
AI_COMMENT_MAX = 1200


def validate_ai_endpoint(url):
    """Validate the configured AI endpoint. -> (ok, reason).

    The endpoint must stay on localhost: the file contents and snippets are sent
    to it, so nothing outside the machine may ever be contacted by this URL."""
    raw = str(url or "").strip()
    if not raw:
        return False, "the AI base URL is empty"
    try:
        parts = urlparse(raw)
    except ValueError:
        return False, "the AI base URL is not a valid URL: %s" % raw
    if parts.scheme.lower() not in ("http", "https"):
        return False, "the AI base URL must be http:// or https://"
    if parts.username or parts.password:
        return False, "credentials in the URL are not allowed"
    if parts.query or parts.fragment:
        return False, "the base URL must not carry a query or a fragment"
    host = (parts.hostname or "").lower()
    if host not in AI_HOSTS:
        return False, "the AI endpoint must be on localhost (127.0.0.1, localhost or ::1), got '%s'" % (parts.hostname or "")
    try:
        port = parts.port
    except ValueError:
        return False, "the AI base URL has an invalid port"
    if port is not None and not (1 <= port <= 65535):
        return False, "the AI base URL has an out-of-range port"
    return True, ""


def parse_ai_answer(text):
    """Extract {status, comment} from the model answer. -> dict or None.

    The model is asked to answer with strict JSON; we tolerate markdown fences and
    prose around the object, but never accept a status that is not in the alias map."""
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S | re.I)
    if fence:
        text = fence.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        obj = json.loads(text[start:end + 1])
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    status = str(obj.get("status", "")).strip().lower().replace("-", "_").replace(" ", "_")
    alias = {
        "real": "real_threat", "threat": "real_threat", "real_threat": "real_threat",
        "malicious": "real_threat", "true": "real_threat", "yes": "real_threat",
        "false": "false_positive", "fp": "false_positive", "false_positive": "false_positive",
        "benign": "false_positive", "safe": "false_positive", "no": "false_positive",
        "uncertain": "uncertain", "unknown": "uncertain", "unsure": "uncertain",
        "unclear": "uncertain", "maybe": "uncertain",
    }
    status = alias.get(status)
    if not status:
        return None
    comment = str(obj.get("comment", "")).strip()
    return {"status": status, "comment": comment[:AI_COMMENT_MAX]}


def read_file_context(root, rel, lines, context_lines=AI_CONTEXT_LINES, start_bytes=AI_START_BYTES):
    """Read a bounded context around the finding lines. -> (start, context).

    Never returns more than AI_PROMPT_FILE_BYTES; reads only what is needed."""
    path = root / rel
    try:
        raw = path.read_bytes()
    except OSError:
        return "", ""
    if len(raw) > AI_PROMPT_FILE_BYTES:
        raw = raw[:AI_PROMPT_FILE_BYTES]
    text = raw.decode("utf-8", "replace")
    lines_list = text.splitlines()
    start = text[:start_bytes]
    wanted = set()
    for ln in lines:
        try:
            n = int(ln or 0)
        except (TypeError, ValueError):
            continue
        for k in range(max(1, n - context_lines), min(len(lines_list), n + context_lines) + 1):
            wanted.add(k)
    if not wanted:
        return start, ""
    out, prev = [], None
    for k in sorted(wanted):
        if prev is not None and k - prev > 2:
            out.append("    ...")
        out.append("%6d | %s" % (k, lines_list[k - 1]))
        prev = k
    context = "\n".join(out)
    if len(context) > AI_MAX_CONTENT:
        context = context[:AI_MAX_CONTENT]
    return start, context


def build_ai_prompt(payload):
    """The prompt for one file. payload: rel, level, score, size, date, findings,
    context, start. -> str. Only snippets + metadata + a bounded context of the
    file are sent - never the whole file."""
    lines = [
        "You are a security analyst reviewing suspicious code found by a static scanner.",
        "Answer with STRICT JSON only, no markdown fences:",
        '{"status": "real_threat" | "false_positive" | "uncertain", "comment": "<reason, English, <= 400 chars>"}',
        "",
        "File: %s" % payload["rel"],
        "Scanner verdict: %s | Score: %s | Size: %s | Modified: %s" % (
            payload["level"], payload["score"], payload["size"], payload["date"]),
        "",
        "Findings (most important first):",
    ]
    for f in payload["findings"]:
        lines.append("  - line %s: %s (severity %s, score %s)" % (
            f.get("line", ""), f.get("signature", ""), f.get("severity", ""), f.get("score", "")))
        snip = (f.get("snippet") or "").strip()
        if snip:
            lines.append("    snippet: %s" % snip[:600].replace("\n", " ").replace("\r", " "))
    if payload.get("context"):
        lines += ["", "Context around the findings (line numbers):", payload["context"]]
    if payload.get("start"):
        lines += ["", "The start of the file:", payload["start"][:AI_START_BYTES]]
    lines += [
        "",
        "Decide: is this file a real malicious threat, or a false positive (known-safe content that looks risky, e.g. a plugin header or a comment) — or uncertain?",
        "Base your answer ONLY on the evidence above. If the evidence is insufficient, answer 'uncertain'.",
    ]
    return "\n".join(lines)


def build_ai_signature_prompt(payload):
    """The prompt for one real-threat file: ask for ONE scanner-signature proposal.

    Same discipline as the review prompt: metadata + bounded findings/context only -
    never the whole file. The pattern is validated again before it may be written."""
    lines = [
        "You are a security analyst hardening a static scanner.",
        "Answer with STRICT JSON only, no markdown fences:",
        '{"propose": true | false, "label": "<short label>", "pattern": "<regex>", "severity": "critical" | "obfuscated" | "warning", "kinds": "<space separated kinds>", "weight": <int 1-30, optional>, "reason": "<<= 400 chars, evidence based>"}',
        "",
        "File: %s" % payload["rel"],
        "Scanner verdict: %s | Score: %s | Size: %s | Modified: %s" % (
            payload["level"], payload["score"], payload["size"], payload["date"]),
        "",
        "Findings (most important first):",
    ]
    for f in payload["findings"]:
        lines.append("  - line %s: %s (severity %s, score %s)" % (
            f.get("line", ""), f.get("signature", ""), f.get("severity", ""), f.get("score", "")))
        snip = (f.get("snippet") or "").strip()
        if snip:
            lines.append("    snippet: %s" % snip[:600].replace("\n", " ").replace("\r", " "))
    if payload.get("context"):
        lines += ["", "Context around the findings (line numbers):", payload["context"]]
    if payload.get("start"):
        lines += ["", "The start of the file:", payload["start"][:AI_START_BYTES]]
    lines += [
        "",
        "Propose ONE additional scanner signature that would flag the malicious code in THIS file.",
        "The pattern must be a valid regular expression (Python-style, matched against the raw file text)",
        "that matches the malicious code and NOT the benign content of this file.",
        "If the evidence is insufficient, or the pattern cannot be made safe, answer propose=false with a reason.",
        "kinds: one or more of: php, js, html, htaccess, ini, text (space separated).",
    ]
    return "\n".join(lines)


def _validate_signature_fields(label, pattern, severity, kinds, weight):
    """Validate a signature proposal. Shared by the AI answer parser and the apply endpoint.

    -> normalized dict (kinds as a space-separated string, weight as int or None).
    Raises ValueError with a short reason on failure."""
    label = str(label or "").strip()
    if len(label) < 2 or len(label) > AI_SIGNATURE_LABEL_MAX:
        raise ValueError("label must be 2-%d chars" % AI_SIGNATURE_LABEL_MAX)
    pattern = str(pattern or "").strip()
    if len(pattern) < 2 or len(pattern) > 400:
        raise ValueError("pattern must be 2-400 chars")
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        raise ValueError("pattern is not a valid regex: %s" % exc)
    for probe in ("", " "):
        if rx.search(probe):
            raise ValueError("pattern matches an empty or whitespace-only string - it would fire on every file")
    severity = str(severity or "").strip().lower().strip("[]")
    if severity == "obs":
        severity = "obfuscated"
    if severity not in USER_SIG_SEVERITIES:
        raise ValueError("severity must be one of critical/obfuscated/warning")
    if isinstance(kinds, (list, tuple)):
        kinds = [str(k).strip().lower() for k in kinds]
    else:
        kinds = [k.strip().lower() for k in str(kinds or "").split()]
    kinds = [k for k in kinds if k]
    if not kinds:
        raise ValueError("kinds are missing")
    bad = [k for k in kinds if k not in USER_SIG_KINDS]
    if bad:
        raise ValueError("unknown kinds: %s (allowed: %s)" % (", ".join(bad), ", ".join(USER_SIG_KINDS)))
    if weight is None or str(weight).strip() == "":
        weight = None
    else:
        try:
            weight = int(weight)
        except (TypeError, ValueError):
            raise ValueError("weight must be an integer")
        if not 1 <= weight <= 30:
            raise ValueError("weight %d is out of the 1-30 range" % weight)
    return {"label": label, "pattern": pattern, "severity": severity,
            "kinds": " ".join(dict.fromkeys(kinds)), "weight": weight}


def parse_ai_signature_answer(text):
    """Extract one signature proposal from the model answer.

    -> {"propose": True, "label": ..., "pattern": ..., "severity": ..., "kinds": [...],
        "weight": int|None, "reason": ...}
       {"propose": False, "reason": ...}   (the model declined or the proposal is invalid)
       None                                 (unreadable answer)"""
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S | re.I)
    if fence:
        text = fence.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        obj = json.loads(text[start:end + 1])
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    reason = str(obj.get("reason", "")).strip()[:AI_SIGNATURE_REASON_MAX]
    propose_raw = obj.get("propose", True)
    if isinstance(propose_raw, str):
        propose = propose_raw.strip().lower() not in ("false", "no", "0", "n")
    else:
        propose = bool(propose_raw)
    if not propose:
        return {"propose": False, "reason": reason}
    try:
        v = _validate_signature_fields(obj.get("label"), obj.get("pattern"), obj.get("severity"),
                                        obj.get("kinds"), obj.get("weight"))
    except ValueError as exc:
        return {"propose": False, "reason": "invalid proposal: %s" % exc}
    kinds = v["kinds"].split(" ")
    return {"propose": True, "label": v["label"], "pattern": v["pattern"], "severity": v["severity"],
            "kinds": kinds, "weight": v["weight"], "reason": reason}


def validate_signature(entry, reason_max=AI_SIGNATURE_REASON_MAX):
    """Validate one signature coming from the frontend / the library. -> normalized dict
    (label, pattern, severity, kinds [space-separated], weight, reason, created, flags).
    Raises ValueError with a short reason on failure."""
    if not isinstance(entry, dict):
        raise ValueError("entry is not an object")
    v = _validate_signature_fields(entry.get("label"), entry.get("pattern"), entry.get("severity"),
                                   entry.get("kinds"), entry.get("weight"))
    reason = str(entry.get("reason", "")).strip()[:reason_max]
    v["reason"] = reason
    v["created"] = datetime.now().strftime("%Y-%m-%d")
    v["flags"] = "i"     # case-insensitive by default (the scanner's own default)
    return v


def ai_http_post(url, body, timeout=AI_TIMEOUT):
    req = Request(url, data=json.dumps(body).encode("utf-8"),
                  headers={"Content-Type": "application/json", "Accept": "application/json"},
                  method="POST")
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def ai_http_get(url, timeout=AI_TIMEOUT):
    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


# The GUI path fields and their kind: "file" must exist, "dir" must be a folder,
# "save" is a report destination (its folder must exist and be writable).
# The third element marks required fields (an empty required field is an error,
# an empty optional one is fine).
PATH_FIELDS = (
    ("scanner_path", "file", True),    # required
    ("site_dir", "dir", False),
    ("baseline_dir", "dir", False),
    ("whitelist_path", "file", False),
    ("csv_path", "save", True),
    ("xlsx_path", "save", False),
    ("json_path", "save", False),
)


def load_config():
    """Read CONFIG_PATH. -> (data dict or None, error message or None).
    A missing file is not an error: the defaults are used."""
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except OSError:
        return None, None
    except ValueError as exc:
        return None, "the settings file is not valid JSON: %s" % exc
    if not isinstance(data, dict):
        return None, "the settings file is not a JSON object"
    return data, None


def validate_paths(settings):
    """Check the configured path fields against their declared kind.
    -> [(field, value, error)], empty when all is well. An empty optional field
    is not an error; a relative path is resolved like the GUI resolves it
    (against the scanner's folder)."""
    bad = []
    scanner_raw = str(settings.get("scanner_path") or "").strip()
    base = Path(scanner_raw).expanduser().parent if scanner_raw else Path.cwd()
    for key, kind, required in PATH_FIELDS:
        raw = str(settings.get(key) or "").strip()
        if not raw:
            if key == "scanner_path":
                bad.append((key, raw, "not set"))
            continue
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = base / p
        if kind == "file" and not p.is_file():
            bad.append((key, raw, "is not a file"))
        elif kind == "dir" and not p.is_dir():
            bad.append((key, raw, "is not a folder"))
        elif kind == "save":
            parent = p.parent
            if not parent.exists():
                bad.append((key, raw, "the folder does not exist: %s" % parent))
            elif not os.access(str(parent), os.W_OK):
                bad.append((key, raw, "the folder is not writable: %s" % parent))
    return bad


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
        self.log, self.log_first = [], 0          # before _load_config: boot errors must be loggable
        self._load_config()
        self.migrate_data_locations()      # old next-to-the-scanner data -> the data folder
        self.job = None
        self.status = "Ready to run"
        self.idle_text = ""
        self.findings, self.next_id, self.findings_version, self.hidden_done = [], 1, 0, 0
        self.report_files, self.scanned_site, self.last_stats = {}, None, None
        self.notice, self.notice_seq = None, 0
        self.cleaned, self.stripped, self.replaced, self.clean_summary = [], [], [], None
        self.engines = []          # downloadable engines detected on the site: [{"name","version"}]
        self.baseline_view = {"dir": "", "version": None, "joomla": None, "match": False}
        threading.Thread(target=self._refresh_engines, daemon=True).start()
        self.shutdown_cb = None
        self.ai_results = {}                    # rel -> {status, comment}, loaded from the CSV below
        self._active_ai_model = ''                # resolved once per review job, then used for every file
        self._ai_loaded_model_cache = None           # the loaded model, resolved once per process
        self.load_findings()                  # show the previous report right away, if there is one

    # ------------------------------------------------------------ settings
    def s(self, key):
        return self.settings.get(key, DEFAULTS.get(key))

    def _load_config(self):
        """A settings problem is logged by field name; nothing is silently reset.
        The server still starts - bad settings refuse jobs, not the GUI."""
        data, err = load_config()
        if err:
            self.log_add("ERROR: %s (the defaults are used)" % err)
            print("ERROR: %s (the defaults are used)" % err)
        else:
            self.update_settings(data, save=False)
        for key, value, reason in validate_paths(self.settings):
            self.log_add("ERROR: settings: %s = '%s' - %s" % (key, value, reason))
            print("ERROR: settings: %s = '%s' - %s" % (key, value, reason))

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
            self.ai_results = {}
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
                    # marked false-positive in the AI review and removed from the list: still in the CSV
                    handle = (row.get("AI Handled") or "").strip().lower()
                    if handle == "false_positive":
                        self.hidden_done += 1
                        continue
                    level = (row.get("Verdict") or "").upper().strip()
                    row["_level"] = level if level in LEVEL_ORDER else "LOW"
                    row["_id"] = self.next_id
                    self.next_id += 1
                    verdict = clean_cell(row.get("AI Verdict", "")).strip().lower()
                    if verdict in ("real_threat", "false_positive", "uncertain", "error"):
                        self.ai_results[rel] = {"status": verdict, "comment": str(row.get("AI Comment", ""))[:AI_COMMENT_MAX]}
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
        ai_filter = params.get("ai", "all").casefold().strip()
        sort, desc = params.get("sort", ""), params.get("desc", "0") == "1"
        try:
            limit = max(1, min(int(params.get("limit", MAX_TABLE_ROWS)), MAX_TABLE_ROWS))
        except ValueError:
            limit = MAX_TABLE_ROWS
        with self.lock:
            def keep(r):
                if query and query not in (r.get("File", "") + " " + r.get("Signature", "")).casefold():
                    return False
                ai = self.ai_results.get(clean_cell(r.get("File", "")))
                status = ai.get("status") if ai else None
                if ai_filter == "hide_fp" and status == "false_positive":
                    return False
                if ai_filter in ("real", "malicious") and status != "real_threat":
                    return False
                if ai_filter == "clean" and status != "false_positive":
                    return False
                if ai_filter == "not_reviewed" and status:
                    return False
                return True
            base = [r for r in self.findings if keep(r)]
            counts = {"ALL": len(base), "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for r in base:
                if r["_level"] in counts:
                    counts[r["_level"]] += 1
            if sort in ("level", "score", "file", "line", "size", "date", "delete", "signature"):
                base = sorted(base, key=lambda r: self._sort_key(r, sort), reverse=desc)
            out, matched = [], 0
            for r in base:
                if level != "All" and r["_level"] != level:
                    continue
                matched += 1
                if len(out) < limit:
                    ai = self.ai_results.get(clean_cell(r.get("File", "")))
                    out.append({"id": r["_id"], "level": r["_level"], "score": r.get("Score", ""),
                                "file": r.get("File", ""), "line": r.get("Line", ""),
                                "size": fmt_size(r.get("Size", "")), "date": r.get("Modified", ""),
                                "delete": r.get("Delete", ""), "signature": r.get("Signature", ""),
                                "ai": ai})
            return {"total": len(self.findings), "matched": matched, "shown": len(out), "limit": limit,
                    "hidden_done": self.hidden_done, "version": self.findings_version,
                    "counts": counts, "rows": out}

    def finding_detail(self, fid):
        with self.lock:
            for r in self.findings:
                if r["_id"] == fid:
                    return {"id": fid, "file": r.get("File", ""), "level": r["_level"], "score": r.get("Score", ""),
                            "line": r.get("Line", ""), "size": fmt_size(r.get("Size", "")),
                            "date": r.get("Modified", ""), "signature": r.get("Signature", ""),
                            "severity": r.get("Severity", ""), "sha256": r.get("SHA-256", ""),
                            "snippet": r.get("Snippet", ""),
                            "ai": self.ai_results.get(clean_cell(r.get("File", "")))}
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
        if not wl:                                   # a browser has no 'save as' dialog: the data folder
            wl = self._whitelist_default()
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

    def build_scan_command(self, allow_baseline=True):
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
            scanner_text = scanner.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            scanner_text = ""
        markers = "--progress-lines" in scanner_text
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
        if allow_baseline:
            add("--baseline-dir", self.s("baseline_dir"))
        add("--whitelist", self.s("whitelist_path"))
        # the AI-confirmed signature library: the scanner refuses to run with a missing file,
        # so the flag is only passed when the file exists and is not empty
        try:
            user_sigs_raw = USER_SIGS_PATH.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            user_sigs_raw = ""
        if user_sigs_raw:
            cmd.extend(["--user-signatures", str(USER_SIGS_PATH)])
        # the installed signature package (updater.py): the ACTIVE release's rules,
        # a server-side path the browser can never influence; off when nothing is
        # installed or the scanner build does not know the flag
        yara_rules = self._active_rules_dir()
        if yara_rules and "--yara-rules" in scanner_text:
            cmd.extend(["--yara-rules", yara_rules])
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

    def _refuse_bad_settings(self):
        """Check the path settings before a job starts. -> the problem list (empty
        when the job may run). A refused job starts nothing and leaves self.job
        untouched; the problems are named in the log and in a notice."""
        problems = validate_paths(self.settings)
        if not str(self.s("site_dir")).strip():
            problems.append(("site_dir", "", "not set - choose a site folder on the Settings tab"))
        if problems:
            for key, value, reason in problems:
                self.log_add("ERROR: %s = '%s' - %s" % (key, value, reason))
            self.notify("error", "Job not started",
                        "Fix the settings first: " + "; ".join("%s (%s)" % (k, r) for k, _v, r in problems))
        return problems

    def _start_job(self, kind, cmd, markers=True):
        with self.lock:
            if self.job is not None:
                raise ApiError("Another job is already running.", 409)
            self.job = {"kind": kind, "proc": None, "t0": time.time(), "text": "Starting…", "indeterminate": True,
                        "done": 0, "total": 0, "stopped": False, "got_done": False, "markers": markers,
                        "report_error": False}
            self.idle_text = ""
            self.log_add("\n" + "=" * 76 + "\nCommand: " + subprocess.list2cmdline(cmd) + "\n\n")
            if not markers and kind == "scan":
                self.log_add("WARNING: old scanner version (no --progress-lines), exact progress is unavailable. "
                             "Update scan_backdoors.py to %s or newer.\n\n" % MIN_SCANNER)
        threading.Thread(target=self._run_job, args=(cmd,), daemon=True).start()

    def start_scan(self, no_baseline=False):
        if self._refuse_bad_settings():
            return
        cmd, markers = self.build_scan_command(allow_baseline=not no_baseline)
        with self.lock:
            if self.job is not None:
                raise ApiError("Another job is already running.", 409)
            self.report_files, self.last_stats = {}, None
            self.ai_results = {}
            self.scanned_site = str(Path(self.s("site_dir")).expanduser())
            self.findings, self.hidden_done = [], 0
            self.findings_version += 1
            self.status = "Scan in progress…"
            if no_baseline:
                self.log_add("Note: the scan runs WITHOUT the clean Joomla baseline - core files are judged "
                             "by heuristics only (the baseline did not match the site version, or was skipped).\n")
            self._start_job("scan", cmd, markers)

    def start_clean_plan(self):
        if self._refuse_bad_settings():
            return
        cmd = self.build_clean_command(False)
        with self.lock:
            self.cleaned, self.stripped, self.replaced, self.clean_summary = [], [], [], None
            self.status = "Mass cleanup: searching for malicious files…"
            self._start_job("clean-plan", cmd)

    def start_clean_apply(self):
        if self._refuse_bad_settings():
            return
        cmd = self.build_clean_command(True)
        with self.lock:
            self.cleaned, self.stripped, self.replaced, self.clean_summary = [], [], [], None
            self.status = "Mass cleanup: working…"
            self._start_job("clean-apply", cmd)

    def clean_cancel(self):
        self.status = "Mass cleanup cancelled."

    # ---------------------------------------------------------------- baseline
    @staticmethod
    def _joomla_version(root):
        """The site's exact Joomla version from its own files (same sources the cleaner
        uses: J4/5 libraries/src/Version.php, J3 libraries/cms/version/version.php)."""
        root = Path(str(root or ""))
        try:
            t = (root / "libraries" / "src" / "Version.php").read_text(encoding="utf-8", errors="ignore")
            parts = [re.search(r"%s_VERSION\s*=\s*(\d+)" % k, t) for k in ("MAJOR", "MINOR", "PATCH")]
            if all(parts):
                return ".".join(m.group(1) for m in parts)
        except OSError:
            pass
        try:
            t = (root / "libraries" / "cms" / "version" / "version.php").read_text(encoding="utf-8", errors="ignore")
            rel = re.search(r"(?:const\s+)?\$?RELEASE\s*=\s*'([\d.]+)'", t)
            dev = re.search(r"(?:const\s+)?\$?DEV_LEVEL\s*=\s*'(\d+)'", t)
            if rel and dev:
                return "%s.%s" % (rel.group(1), dev.group(1))
        except OSError:
            pass
        return None

    def baseline_detect(self):
        """Report the exact Joomla version of the configured site (for the Fetch baseline button)."""
        site_s = self.s("site_dir").strip()
        if not site_s or not Path(site_s).expanduser().is_dir():
            raise ApiError("Select an existing site folder on the Settings tab first.")
        v = self._joomla_version(site_s)
        if not v or not re.match(r"^\d+\.\d+\.\d+$", v):
            raise ApiError("Could not detect the exact Joomla version (x.y.z) from the site's version files. "
                           "Set the 'Clean Joomla folder' by hand, or run joomla_baseline.py <version> from the command line.")
        return {"version": v}

    def baseline_fetch(self, version=""):
        """Start a job that downloads the official clean Joomla Full_Package (joomla_baseline.py,
        GitHub releases, HTTPS). On success the baseline_dir setting is filled in automatically."""
        v = str(version or "").strip()
        if not v:
            v = self.baseline_detect()["version"]
        if not re.match(r"^\d+\.\d+\.\d+$", v):
            raise ApiError("Bad Joomla version: %s" % v)
        scanner = Path(self.s("scanner_path")).expanduser()
        if not scanner.is_file():
            raise ApiError("The scanner file scan_backdoors.py was not found.")
        tool = scanner.resolve().parent / "joomla_baseline.py"
        if not tool.is_file():
            raise ApiError("joomla_baseline.py was not found next to the scanner.")
        out = Path(self._baselines_dir())          # the data folder, not the folder of the code
        folder = out / ("Joomla_" + v)
        cmd = [python_exe(), "-u", str(tool), v, "--out", str(out)]
        self._start_job("baseline", cmd)
        with self.lock:
            if self.job is not None:
                self.job["text"] = "Fetching the clean Joomla %s baseline…" % v
                self.job["baseline_folder"] = str(folder)
                self.job["baseline_version"] = v
        return {"ok": True, "version": v, "folder": str(folder)}

    # ------------------------------------------------------------- data folder
    # What the tools keep between runs - the whitelist they may append to, the Joomla
    # baseline cache, the YARA rule cache, the installed signature releases - lives in
    # ONE folder: $SBD_DATA_DIR or ~/.scan_backdoors. Never next to the code, never
    # inside a scanned site. Older versions wrote some of it next to the scanner; that
    # is moved once on startup (migrate_data_locations).
    def _data_root(self):
        d = os.environ.get("SBD_DATA_DIR") or os.path.join(os.path.expanduser("~"), ".scan_backdoors")
        return os.path.abspath(os.path.expanduser(d))

    def _whitelist_default(self):
        """Where 'Add to whitelist' writes when the user did not pick a file."""
        return os.path.join(self._data_root(), "whitelist.txt")

    def _baselines_dir(self):
        return os.path.join(self._data_root(), "joomla-baselines")

    def migrate_data_locations(self):
        """Move what used to live next to the scanner into the data folder and point
        the settings at the new place. -> list of (old, new) that were moved."""
        try:
            tools = Path(self.s("scanner_path")).expanduser().resolve().parent
        except (OSError, RuntimeError):
            return []
        moved = []
        pairs = [(tools / "whitelist.txt", Path(self._whitelist_default())),
                 (tools / "joomla-baselines", Path(self._baselines_dir()))]
        for old, new in pairs:
            if not old.exists() or new.exists() or old.parent == new.parent:
                continue
            try:
                if not new.parent.is_dir():
                    new.parent.mkdir(parents=True)
                shutil.move(str(old), str(new))
                moved.append((str(old), str(new)))
            except OSError:
                pass                        # a locked folder: the job that needs it will say so
        if not moved:
            return []
        changed = False
        for key in ("whitelist_path", "baseline_dir"):
            value = str(self.s(key) or "").strip()
            if not value:
                continue
            try:
                value_abs = os.path.abspath(os.path.expanduser(value))
            except (OSError, ValueError):
                continue
            for old, new in moved:
                if os.path.normcase(value_abs) == os.path.normcase(old):
                    self.settings[key] = new
                elif value_abs.startswith(old + os.sep):
                    self.settings[key] = new + value_abs[len(old):]
                else:
                    continue
                changed = True
                break
        if changed:
            self.update_settings({}, save=True)
            for old, new in moved:
                self.log_add("Data moved: %s -> %s\n" % (old, new))
        return moved

    # ------------------------------------------------------------- signatures
    # The signature package is managed by src/updater.py. The browser never sends a
    # URL or a path here: the sources are updater's own constants/config, the work
    # runs as a background subprocess job, and the status is read from the manifest.
    def _signatures_root(self):
        return self._data_root()

    def _active_rules_dir(self):
        """The rules folder of the ACTIVE release, or None (validated exactly like
        updater.Store.active() does)."""
        name_s = ""
        try:
            with open(os.path.join(self._signatures_root(), "signatures", "ACTIVE"), encoding="utf-8") as f:
                name_s = f.read().strip()
        except OSError:
            return None
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$", name_s):
            return None
        d = os.path.join(self._signatures_root(), "signatures", "releases", name_s, "rules")
        return d if os.path.isdir(d) else None

    def signatures_status(self):
        root = self._signatures_root()
        sig_dir = os.path.join(root, "signatures")
        manifest = None
        try:
            with open(os.path.join(sig_dir, "manifest.json"), encoding="utf-8") as f:
                manifest = json.load(f)
        except (OSError, ValueError):
            manifest = None
        active = self._active_rules_dir()
        active_name = os.path.basename(os.path.dirname(active)) if active else None
        pkg = (manifest or {}).get("package") or {}
        rel_doc = None
        if active:
            try:
                with open(os.path.join(os.path.dirname(active), "RELEASE.json"), encoding="utf-8") as f:
                    rel_doc = json.load(f)
            except (OSError, ValueError):
                rel_doc = None
        src = ((manifest or {}).get("sources") or {}).get((rel_doc or {}).get("source") or "", {})
        verified = (rel_doc or {}).get("verified")
        if verified is None:
            verified = pkg.get("verified")
        return {"present": bool(active), "active": active_name,
                "rules": (rel_doc or {}).get("count") if rel_doc else (0 if not active else None),
                "verified": verified,
                "verification": (rel_doc or {}).get("verification") or pkg.get("verification"),
                "updated": src.get("updated"), "manifest_generated": (manifest or {}).get("generated"),
                "failed": (manifest or {}).get("failed") or [],
                "releases": [r.get("name") for r in ((manifest or {}).get("releases") or [])],
                "data_dir": sig_dir,
                "tool": os.path.isfile(str(HERE / "updater.py"))}

    def _updater_cmd(self, action_flags):
        tool = str(HERE / "updater.py")
        if not os.path.isfile(tool):
            raise ApiError("updater.py was not found next to the scanner.")
        return [python_exe(), "-u", tool] + action_flags + ["--data-dir", self._signatures_root()]

    def signatures_update(self):
        self._start_job("signatures", self._updater_cmd(["--update-signatures"]), markers=False)
        with self.lock:
            if self.job is not None:
                self.job["text"] = "Updating the signature package…"
        return {"ok": True}

    def signatures_rollback(self):
        self._start_job("signatures-rollback", self._updater_cmd(["--rollback-signatures"]), markers=False)
        with self.lock:
            if self.job is not None:
                self.job["text"] = "Rolling the signatures back…"
        return {"ok": True}

    # ---------------------------------------------------------------- engines
    ENGINE_SKIP_DIRS = {"files", "tmp", "cache", "logs", "media", "assets", "language", "languages",
                        "models", "views", "controllers", "helpers", "tables", "scripts", "sql", "config"}
    ENGINE_NAME_MAP = {"com_virtuemart": "VirtueMart", "com_akeeba": "Akeeba Backup",
                       "com_admintools": "Admin Tools", "com_joomshop": "JoomShopping",
                       "com_hikashop": "HikaShop", "com_phocadownload": "Phoca Download",
                       "com_sppagebuilder": "SP Page Builder", "com_yootheme": "YOOtheme"}

    @staticmethod
    def _manifest_name_version(xf):
        """(<name>, <version>) from a Joomla install manifest XML; version None when absent."""
        try:
            t = xf.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None, None
        if "<install" not in t and "<extension" not in t:
            return None, None
        m = re.search(r"<name>\s*([^<]{1,40}?)\s*</name>", t, re.I)
        v = re.search(r"<version>\s*([0-9][^<\s]{0,24})\s*</version>", t, re.I)
        return (m.group(1).strip() if m else None), (v.group(1) if v else None)

    def _detect_engines(self):
        """What the site is made of: the Joomla core version plus third-party extensions
        that publish their version (install manifest <version>, or a VERSION define in
        version.php - like VirtueMart). These are the originals one can download freely."""
        out = []
        site_s = self.s("site_dir").strip()
        site = Path(site_s).expanduser() if site_s else None
        if not site or not site.is_dir():
            return out
        jv = self._joomla_version(site)
        if jv:
            out.append({"name": "Joomla", "version": jv})
        seen = set((e["name"].lower(), e["version"]) for e in out)
        for sub in ("administrator/components", "components", "modules"):
            base = site / sub
            if not base.is_dir():
                continue
            try:
                kids = sorted(base.iterdir())
            except OSError:
                continue
            for d in kids:
                if not d.is_dir() or d.name.lower() in self.ENGINE_SKIP_DIRS:
                    continue
                name = ver = None
                try:
                    manifests = sorted(d.glob("*.xml"))
                except OSError:
                    manifests = []
                for xf in manifests[:4]:
                    nm, vv = self._manifest_name_version(xf)
                    if vv:
                        name, ver = nm or d.name, vv
                        break
                if ver is None and d.name.lower().startswith("com_"):
                    try:
                        t = (d / "version.php").read_text(encoding="utf-8", errors="ignore")
                        m = re.search(r"define\s*\(\s*['\"][A-Z0-9_]*VERSION['\"]\s*,\s*['\"]([0-9][^'\"]*)['\"]", t)
                        if m:
                            name, ver = d.name, m.group(1)
                    except OSError:
                        pass
                if not ver:
                    continue
                if jv and ver == jv:
                    continue          # a bundled core extension, not a separate downloadable engine
                nm = self.ENGINE_NAME_MAP.get((name or d.name).lower(), name or d.name)
                key = (nm.lower(), ver)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"name": nm, "version": ver})
                if len(out) >= 12:
                    return out
        return out

    def _refresh_engines(self):
        try:
            eng = self._detect_engines()
        except Exception:
            eng = []
        with self.lock:
            self.engines = eng
        self._refresh_baseline_view(eng)

    def _refresh_baseline_view(self, eng=None):
        """What the Engines tab shows for the 'original loaded' mark: the Clean Joomla
        folder, the Joomla version it holds, and whether it matches the site's core."""
        bdir = self.s("baseline_dir").strip()
        bv = self.baseline_version()
        if eng is None:
            with self.lock:
                eng = self.engines
        jv = next((e["version"] for e in eng if e["name"] == "Joomla"), None)
        with self.lock:
            self.baseline_view = {"dir": bdir, "version": bv, "joomla": jv,
                                  "match": bool(jv and bv and bv == jv)}

    def baseline_version(self):
        b = self.s("baseline_dir").strip()
        if not b:
            return None
        p = Path(b).expanduser()
        return self._joomla_version(p) if p.is_dir() else None

    def preflight(self):
        """Before a scan: does the loaded clean-Joomla baseline match the detected core version?"""
        eng = self._detect_engines()
        with self.lock:
            self.engines = eng
        self._refresh_baseline_view(eng)
        jv = next((e["version"] for e in eng if e["name"] == "Joomla"), None)
        bdir = self.s("baseline_dir").strip()
        bv = self.baseline_version()
        if not jv:
            mode = "no_engine"
        elif not bdir:
            mode = "no_baseline"
        elif bv == jv:
            mode = "ok"
        else:
            mode = "mismatch"
        return {"mode": mode, "joomla": jv, "baseline": {"dir": bdir, "version": bv}, "engines": eng}

    def stop_job(self):
        with self.lock:
            job = self.job
            if job is None:
                return
            job["stopped"] = True
            self.status = "Stopping…"
            proc = job["proc"]
        kill_tree(proc)

    # ---------------------------------------------------------------- AI review
    # The AI review is an in-process job (no subprocess): it reviews the suspicious
    # files one at a time against a localhost model and stores the verdicts in the
    # report CSV (columns "AI Verdict" / "AI Comment") and in self.ai_results.
    def ai_unique_files(self):
        """Unique files from the current findings, highest priority first.
        -> [(rel, best_row, rows_sorted), ...]"""
        def score_of(r):
            try:
                return float(r.get("Score") or -1)
            except ValueError:
                return -1.0
        with self.lock:
            by_file = {}
            for r in self.findings:
                rel = clean_cell(r.get("File", ""))
                if rel:
                    by_file.setdefault(rel, []).append(r)
            out = []
            for rel, rows in by_file.items():
                rows = sorted(rows, key=lambda r: (LEVEL_ORDER.get(r.get("_level"), 3), -score_of(r)))
                out.append((rel, rows[0], rows))
            out.sort(key=lambda t: (LEVEL_ORDER.get(t[1].get("_level"), 3), -score_of(t[1])))
            return out

    def start_ai_review(self, dry_run=False, files=None):
        """Prepare (and, unless dry_run, start) the AI review. -> {"ok": True,
        "files": n, "endpoint": url, "model": model}. When `files` (a list of
        relative paths from the table selection) is given, only those files are
        reviewed - all of them, without the AI_MAX_FILES cap."""
        if not self.s("ai_enabled"):
            raise ApiError("AI review is disabled in the settings. Enable it on the Settings tab first.")
        ok, reason = validate_ai_endpoint(self.s("ai_base_url"))
        if not ok:
            raise ApiError("The AI endpoint is not valid: %s" % reason)
        if not str(self.site_root() or "").strip():
            raise ApiError("The site folder is not set - choose it on the Settings tab first.")
        plan = self.ai_unique_files()
        wanted = [clean_cell(f) for f in files if clean_cell(f)] if isinstance(files, (list, tuple)) else None
        if wanted:
            want = set(w.replace("\\", "/") for w in wanted)
            plan = [t for t in plan if t[0].replace("\\", "/") in want]
            if not plan:
                raise ApiError("The selected files are not in the current report any more - run a new scan and try again.")
            self.log_add("\nNote: reviewing the %d file(s) selected in the table (selected files are not capped).\n" % len(plan))
        elif not plan:
            raise ApiError("The current report has no suspicious files to review.")
        elif len(plan) > AI_MAX_FILES:
            self.log_add("\nNote: %d files are in the report; only the first %d (most critical) will be reviewed.\n" % (len(plan), AI_MAX_FILES))
            plan = plan[:AI_MAX_FILES]
        endpoint = self.ai_endpoint()
        if dry_run:
            return {"ok": True, "files": len(plan), "endpoint": endpoint, "model": str(self.s("ai_model") or "")}
        model = str(self.s("ai_model") or "").strip()
        if not model:
            model = self.ai_loaded_model()
        if not model:
            self.log_add("\nNote: no AI model configured and the gateway did not report a loaded model - requests will be sent without one.\n")
        self._active_ai_model = model
        with self.lock:
            if self.job is not None:
                raise ApiError("Another job is already running.", 409)
            self.ai_results = {}
            self.findings_version += 1
            self.job = {"kind": "ai-review", "proc": None, "t0": time.time(), "text": "Starting…",
                        "indeterminate": False, "done": 0, "total": len(plan), "stopped": False,
                        "got_done": False, "markers": False, "report_error": False,
                        "current": None, "times": []}
            self.idle_text = ""
            self.status = "AI review in progress…"
        self.log_add("\n" + "=" * 76 + "\nAI review: %d unique file(s), endpoint %s, model %s\n\n" % (len(plan), endpoint, model))
        threading.Thread(target=self._run_ai_review, args=(plan,), daemon=True).start()
        return {"ok": True, "files": len(plan), "endpoint": endpoint, "model": model}

    def ai_endpoint(self):
        base = str(self.s("ai_base_url") or "").strip().rstrip("/")
        if base.lower().endswith("/chat/completions"):
            return base
        return base + "/chat/completions"

    def ai_loaded_model(self):
        """The model the gateway has loaded, used when ai_model is not configured.

        Queries the gateway's /v1/models endpoint (localhost, validated already).
        One cached request; -> '' on any failure. Never sends file contents."""
        cached = getattr(self, "_ai_loaded_model_cache", None)
        if cached is not None:
            return cached
        base = str(self.s("ai_base_url") or "").strip().rstrip("/")
        if base.lower().endswith("/chat/completions"):
            base = base[:-len("/chat/completions")]
        model = ""
        try:
            data = ai_http_get(base + "/models")
            models = data.get("data") if isinstance(data, dict) else None
            if isinstance(models, list):
                for m in models:
                    if isinstance(m, dict) and (m.get("status") or {}).get("value") == "loaded" and m.get("id"):
                        model = str(m.get("id"))
                        break
                if not model and models and isinstance(models[0], dict):
                    model = str(models[0].get("id") or "")
        except Exception:
            model = ""
        self._ai_loaded_model_cache = model
        return model

    def _file_ai_payload(self, rel, best, rows):
        """The bounded payload sent to the model for one file (review or signature proposal)."""
        root = Path(self.site_root()).expanduser()
        findings = []
        for r in rows[:AI_MAX_FINDINGS]:
            findings.append({"line": r.get("Line", ""), "signature": r.get("Signature", ""),
                             "severity": r.get("Severity", ""), "score": r.get("Score", ""),
                             "snippet": r.get("Snippet", "")})
        lines = [f["line"] for f in findings]
        try:
            start, context = read_file_context(root, rel, lines)
        except Exception:
            start, context = "", ""
        return {"rel": rel, "level": best.get("_level", "LOW"), "score": best.get("Score", ""),
                "size": fmt_size(best.get("Size", "")), "date": best.get("Modified", ""),
                "findings": findings, "context": context, "start": start}

    def _ask_ai_file(self, rel, best, rows):
        payload = self._file_ai_payload(rel, best, rows)
        prompt = build_ai_prompt(payload)
        model = (self._active_ai_model or str(self.s("ai_model") or "")).strip()
        body = {"messages": [{"role": "user", "content": prompt}], "temperature": 0.1, "max_tokens": 800}
        if model:
            body["model"] = model
        data = ai_http_post(self.ai_endpoint(), body)
        content = ""
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            content = ""
        verdict = parse_ai_answer(content)
        if verdict is None:
            return {"status": "error", "comment": "The model returned an unreadable answer: %s" % (content or "(empty)")[:AI_COMMENT_MAX]}
        return verdict

    def _run_ai_review(self, plan):
        processed, stopped = 0, False
        for i, (rel, best, rows) in enumerate(plan):
            with self.lock:
                job = self.job
                if job is None:
                    return
                if job["stopped"]:
                    stopped = True
                    break
                job["current"] = rel
            self.log_add("\n[%d/%d] %s\n" % (i + 1, len(plan), rel))
            t_start = time.time()
            try:
                verdict = self._ask_ai_file(rel, best, rows)
            except Exception as exc:
                verdict = {"status": "error", "comment": str(exc)[:AI_COMMENT_MAX]}
            elapsed_file = time.time() - t_start
            with self.lock:
                self.ai_results[rel] = verdict
                job = self.job
                if job is not None:
                    job["done"] = i + 1
                    job["current"] = ""
                    times = job.setdefault("times", [])
                    times.append(elapsed_file)
                    del times[:-5]  # keep the last few durations for the ETA estimate
                self.findings_version += 1
            processed = i + 1
            try:
                self.mark_ai_in_csv({rel: verdict})
            except Exception as exc:
                self.log_add("\n[WARNING] Could not write the AI verdict to the CSV: %s\n" % exc)
        self._finish_ai_review(stopped, processed, len(plan))

    def _finish_ai_review(self, stopped, processed, total):
        with self.lock:
            self.job = None
            ai = dict(self.ai_results)
        counts = {}
        for v in ai.values():
            st = v.get("status", "error")
            counts[st] = counts.get(st, 0) + 1
        parts = ["%d of %d file(s) reviewed" % (processed, total)]
        for st, label in (("real_threat", "real threats"), ("false_positive", "false positives"),
                          ("uncertain", "uncertain"), ("error", "errors")):
            if counts.get(st):
                parts.append("%s: %d" % (label, counts[st]))
        msg = "AI review: " + ", ".join(parts)
        if stopped:
            msg += " - stopped by the user"
        self.status = msg
        self.log_add("\n" + msg + "\n")
        self.findings_version += 1
        self.notify("info", "AI review", msg, ai_real=counts.get("real_threat", 0),
                    ai_fp=counts.get("false_positive", 0), ai_stopped=bool(stopped))

    def mark_ai_in_csv(self, results):
        """Write the AI verdicts into the CSV (columns "AI Verdict" / "AI Comment").
        Mirrors mark_deleted_in_csv: read, append missing columns, write atomically."""
        path = Path(self.report_files["csv"]) if self.report_files.get("csv") else self.report_path("csv")
        if not path or not path.is_file():
            return None
        tmp = path.with_name(path.name + ".tmp")
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                fields = list(reader.fieldnames or [])
                if "File" not in fields:
                    return None
                rows = list(reader)
            for col in ("AI Verdict", "AI Comment", "AI Handled"):
                if col not in fields:
                    fields.append(col)
            for row in rows:
                rel = clean_cell(row.get("File", ""))
                v = results.get(rel)
                if v is None:
                    continue
                status = str(v.get("status", ""))[:64]
                row["AI Verdict"] = status
                row["AI Comment"] = str(v.get("comment", ""))[:AI_COMMENT_MAX]
                # the "handled" flag survives a re-review only while the verdict stays false_positive
                if status != "false_positive":
                    row["AI Handled"] = ""
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

    def _candidate_groups(self, ai, rows):
        """One group per signature over the real-threat verdicts, with the evidence."""
        real = [rel for rel, v in ai.items() if v.get("status") == "real_threat"]
        by_rel = {}
        for r in rows:
            rel = clean_cell(r.get("File", ""))
            if rel:
                by_rel.setdefault(rel, []).append(r)
        groups = {}
        for rel in real:
            comment = ai.get(rel, {}).get("comment", "")
            for r in by_rel.get(rel, []):
                sig = r.get("Signature", "") or "(unknown signature)"
                g = groups.get(sig)
                if g is None:
                    g = {"signature": sig, "severity": r.get("Severity", ""), "score": r.get("Score", ""),
                         "files": [], "examples": [], "count": 0}
                    groups[sig] = g
                g["count"] += 1
                if len(g["files"]) < 8 and rel not in g["files"]:
                    g["files"].append(rel)
                if len(g["examples"]) < 3:
                    g["examples"].append({"file": rel, "line": r.get("Line", ""),
                                          "snippet": r.get("Snippet", ""), "ai_comment": comment})
        return real, groups

    def _ai_stats(self, ai, rows):
        """The AI-review counters for the run bar (after the review completes)."""
        counts = {}
        for v in ai.values():
            st = v.get("status", "error")
            counts[st] = counts.get(st, 0) + 1
        _, groups = self._candidate_groups(ai, rows)
        return {"reviewed": len(ai),
                "real_threat": counts.get("real_threat", 0),
                "false_positive": counts.get("false_positive", 0),
                "uncertain": counts.get("uncertain", 0),
                "error": counts.get("error", 0),
                "candidates": len(groups)}

    def ai_candidates(self):
        """Compose a list of candidates for the signature library from the
        real-threat verdicts: one group per signature, with the evidence."""
        with self.lock:
            ai = dict(self.ai_results)
            rows = list(self.findings)
        real, groups = self._candidate_groups(ai, rows)
        if not real:
            raise ApiError("The AI review found no real threats.")
        candidates = sorted(groups.values(), key=lambda g: (-g["count"], g["signature"]))
        return {"candidates": candidates, "files": len(real)}

    def ai_prepare_signatures(self):
        """Ask the AI to propose one scanner signature per real-threat file.

        Evidence-only and bounded (the same discipline as the review): no whole files,
        no non-localhost hosts, and nothing is applied automatically.
        -> {"ok": True, "proposals": [...], "files": n, "problems": [...]}"""
        if not self.s("ai_enabled"):
            raise ApiError("AI review is disabled in the settings. Enable it on the Settings tab first.")
        ok, reason = validate_ai_endpoint(self.s("ai_base_url"))
        if not ok:
            raise ApiError("The AI endpoint is not valid: %s" % reason)
        with self.lock:
            real = [rel for rel, v in self.ai_results.items() if v.get("status") == "real_threat"]
            rows_by_file = {}
            for r in self.findings:
                rel = clean_cell(r.get("File", ""))
                if rel:
                    rows_by_file.setdefault(rel, []).append(r)
        if not real:
            raise ApiError("The AI review found no real threats - there is nothing to build signatures from.")

        def score_of(r):
            try:
                return float(r.get("Score") or -1)
            except ValueError:
                return -1.0

        plan = []
        for rel in real:
            rows = rows_by_file.get(rel)
            if not rows:
                continue
            rows = sorted(rows, key=lambda r: (LEVEL_ORDER.get(r.get("_level"), 3), -score_of(r)))
            plan.append((rel, rows[0], rows))
        plan.sort(key=lambda t: (LEVEL_ORDER.get(t[1].get("_level"), 3), -score_of(t[1])))
        if len(plan) > AI_SIGNATURE_MAX_FILES:
            self.log_add("\nNote: %d real-threat file(s); only the first %d (most critical) will be proposed.\n"
                         % (len(plan), AI_SIGNATURE_MAX_FILES))
            plan = plan[:AI_SIGNATURE_MAX_FILES]
        proposals, problems = [], []
        for rel, best, rows in plan:
            try:
                payload = self._file_ai_payload(rel, best, rows)
                prompt = build_ai_signature_prompt(payload)
                model = (self._active_ai_model or str(self.s("ai_model") or "")).strip()
                body = {"messages": [{"role": "user", "content": prompt}], "temperature": 0.1,
                        "max_tokens": AI_SIGNATURE_MAX_TOKENS}
                if model:
                    body["model"] = model
                data = ai_http_post(self.ai_endpoint(), body)
                content = ""
                try:
                    content = data["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError):
                    content = ""
                parsed = parse_ai_signature_answer(content)
            except Exception as exc:
                problems.append({"file": rel, "reason": str(exc)[:200]})
                continue
            if parsed is None:
                problems.append({"file": rel, "reason": "the model returned an unreadable answer"})
                continue
            if not parsed.get("propose"):
                problems.append({"file": rel, "reason": parsed.get("reason") or "the model declined the proposal"})
                continue
            proposals.append({"label": parsed["label"], "pattern": parsed["pattern"],
                              "severity": parsed["severity"], "kinds": " ".join(parsed["kinds"]),
                              "weight": parsed.get("weight"), "reason": parsed.get("reason", ""),
                              "file": rel, "line": rows[0].get("Line", "")})
        return {"ok": True, "proposals": proposals, "files": len(plan), "problems": problems}

    def apply_signatures(self, entries):
        """Validate the signatures, merge them with the library, write it atomically.

        Never writes a malformed entry. -> {"ok": True, "added": n, "replaced": n,
        "problems": [...], "count": n, "path": path, "text": text}."""
        if not isinstance(entries, list) or not entries:
            raise ApiError("No signatures to add.")
        existing = []
        try:
            data = json.loads(USER_SIGS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, list):
                existing = data
            elif isinstance(data, dict):
                existing = data.get("signatures") or []
        except Exception:
            existing = []
        valid = []
        problems = []
        for entry in entries:
            try:
                v = validate_signature(entry)
            except (ValueError, TypeError) as exc:
                problems.append({"label": str((entry or {}).get("label", ""))[:AI_SIGNATURE_LABEL_MAX]
                                  if isinstance(entry, dict) else "",
                                  "reason": str(exc)[:200]})
                continue
            valid.append(v)
        # dedupe by label+pattern: a new version replaces the old one
        merged = list(existing)
        added = replaced = 0
        for v in valid:
            key = (v["label"].strip().lower(), v["pattern"].strip())
            idx = None
            for i, s in enumerate(merged):
                if isinstance(s, dict) and (str(s.get("label", "")).strip().lower(),
                                            str(s.get("pattern", "")).strip()) == key:
                    idx = i
                    break
            if idx is not None:
                old_created = merged[idx].get("created")
                v["created"] = str(old_created or v["created"])
                merged[idx] = v
                replaced += 1
            else:
                merged.append(v)
                added += 1
        try:
            tmp = USER_SIGS_PATH.with_name(USER_SIGS_PATH.name + ".tmp")
            tmp.write_text(json.dumps(merged, ensure_ascii=False, indent=1), encoding="utf-8")
            os.replace(str(tmp), str(USER_SIGS_PATH))
        except OSError as exc:
            raise ApiError("Could not write the signature library %s: %s" % (USER_SIGS_PATH, exc))
        parts = []
        if added:
            parts.append("added %d" % added)
        if replaced:
            parts.append("updated %d" % replaced)
        text = "Signature library updated (%s): %s" % (", ".join(parts) if parts else "nothing new", USER_SIGS_PATH)
        if problems:
            text += " - %d invalid entr%s skipped" % (len(problems), "y" if len(problems) == 1 else "ies")
        self.log_add("\n" + text + "\n")
        return {"ok": True, "added": added, "replaced": replaced, "problems": problems,
                "count": len(merged), "path": str(USER_SIGS_PATH), "text": text}

    def mark_false_positives_in_csv(self, rels):
        """Write 'AI Handled'=false_positive for the given files (invisible to the scanner).
        Mirrors mark_ai_in_csv: read, append missing column, write atomically."""
        path = Path(self.report_files["csv"]) if self.report_files.get("csv") else self.report_path("csv")
        if not path or not path.is_file():
            return None
        tmp = path.with_name(path.name + ".tmp")
        want = set(rels)
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                fields = list(reader.fieldnames or [])
                if "File" not in fields:
                    return None
                rows = list(reader)
            for col in ("AI Handled",):
                if col not in fields:
                    fields.append(col)
            for row in rows:
                if clean_cell(row.get("File", "")) in want:
                    row["AI Handled"] = "false_positive"
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

    def remove_false_positives(self):
        """Hide every row whose AI verdict is false_positive (persisted in the CSV as
        'AI Handled'=false_positive - the rows stay in the file). -> {"ok", "count", "text"}."""
        with self.lock:
            false_positives = {rel for rel, v in self.ai_results.items() if v.get("status") == "false_positive"}
            count = sum(1 for r in self.findings
                        if clean_cell(r.get("File", "")) in false_positives)
        if not false_positives:
            raise ApiError("The AI review found no false positives to remove.")
        err = self.mark_false_positives_in_csv(false_positives)
        with self.lock:
            self.status = "False positives removed from the list"
            self.log_add("\n%d false-positive row(s) removed from the list (they stay in the CSV).\n" % count)
        self.load_findings()
        text = "Removed %d false-positive row(s) from the list. The rows stay in the CSV." % count
        if err:
            text += " (CSV could not be updated: %s)" % err
        return {"ok": True, "count": count, "text": text}

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
            elif kind == "baseline":
                self._finish_baseline(code, stopped, job)
            elif kind in ("signatures", "signatures-rollback"):
                self._finish_signatures(code, stopped, kind)
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

    def _finish_baseline(self, code, stopped, job):
        if stopped:
            self.status = "Baseline download stopped by the user."
            return
        folder_raw = job.get("baseline_folder") or ""
        ver = job.get("baseline_version") or ""
        if code != 0 or not folder_raw or not Path(folder_raw).is_dir():
            self.status = "The baseline download finished with an error (code %s), see the log." % code
            self.notify("error", "Baseline",
                        "The clean Joomla baseline was not fetched. See the log for details.")
            return
        self.update_settings({"baseline_dir": folder_raw})
        threading.Thread(target=self._refresh_engines, daemon=True).start()
        msg = "Baseline ready: the clean Joomla %s folder was set automatically: %s" % (ver, folder_raw)
        self.status = msg
        self.log_add("\n" + msg + "\n")

    def _finish_signatures(self, code, stopped, kind):
        label = "Signature update" if kind == "signatures" else "Signature rollback"
        if stopped:
            self.status = "%s stopped by the user." % label
            return
        st = self.signatures_status()
        if code == 0:
            self.status = ("%s done: active package %s (%s rule(s), %s)." % (
                label, st.get("active") or "?", st.get("rules") if st.get("rules") is not None else "?",
                "verified" if st.get("verified") else "UNVERIFIED"))
        elif code == 3:
            self.status = "%s finished PARTIALLY - at least one source failed, see the log." % label
            self.notify("warn", label, self.status)
        else:
            self.status = "%s failed (code %s) - the previously active package stays in place." % (label, code)
            self.notify("error", label, self.status + " See the log for details.")
        self.log_add("\n" + self.status + "\n")

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
                        "Reviewed" if job["kind"] == "ai-review" else ("Processed" if job["kind"].startswith("clean") else "Scanned"),
                        "{:,}".format(done).replace(",", " "), "{:,}".format(total).replace(",", " "), pct,
                        fmt_duration(elapsed)))
                    cur = job.get("current")
                    if cur:
                        text += " · now: %s" % (cur if len(cur) <= 70 else "…" + cur[-69:])
                    if 0 < done < total:
                        if job["kind"] == "ai-review":
                            recent = job.get("times") or []
                            if recent:
                                per_file = sum(recent) / len(recent)
                            elif elapsed > 1:
                                per_file = elapsed / done
                            else:
                                per_file = None
                            if per_file:
                                text += " · ~%s left" % fmt_duration(per_file * (total - done))
                        elif elapsed > 1:
                            text += " · ~%s left" % fmt_duration((total - done) / (done / elapsed))
                job_view = {"kind": job["kind"], "indeterminate": job["indeterminate"], "percent": round(pct, 1),
                            "text": text, "stopping": job["stopped"]}
            ai = self.ai_results
            ai_stats = self._ai_stats(ai, self.findings) if ai else None
            start = max(since, self.log_first)
            lines = self.log[start - self.log_first:]
            return {"app": APP_ID, "version": VERSION, "boot": self.boot, "job": job_view, "status": self.status,
                    "idle_text": self.idle_text, "log": {"from": start, "lines": lines, "next": start + len(lines)},
                    "reports": self.reports_info(), "findings_version": self.findings_version,
                    "findings_total": len(self.findings), "notice": self.notice, "ai_stats": ai_stats,
                    "engines": list(self.engines), "baseline": dict(self.baseline_view),
                    "signatures": self.signatures_status()}

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
                page = PAGE.replace("__VERSION__", VERSION).replace("__LOGO__", LOGO_DATA_URI)
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
        if path == "/api/signatures/status":
            return app.signatures_status()
        raise ApiError("Not found", 404)

    def _route_post(self, app, path, body):
        ids = body.get("ids") or []
        if path == "/api/settings":
            before = (app.s("site_dir"), app.s("baseline_dir"))
            app.update_settings(body.get("settings") or {})
            if (app.s("site_dir"), app.s("baseline_dir")) != before:
                threading.Thread(target=app._refresh_engines, daemon=True).start()
            return {"ok": True}
        if path == "/api/preflight":
            return app.preflight()
        if path == "/api/scan/start":
            if "settings" in body:
                app.update_settings(body["settings"])
            app.start_scan(bool(body.get("no_baseline")))
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
        if path == "/api/baseline/detect":
            return app.baseline_detect()
        if path == "/api/baseline/fetch":
            return app.baseline_fetch(str(body.get("version") or ""))
        if path == "/api/signatures/update":
            return app.signatures_update()
        if path == "/api/signatures/rollback":
            return app.signatures_rollback()
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
        if path == "/api/ai/review":
            sel_files = body.get("files")
            if sel_files is not None:
                if not isinstance(sel_files, list):
                    raise ApiError("Bad request.")
                sel_files = [str(f) for f in sel_files[:20000]]
            return app.start_ai_review(bool(body.get("dry_run")), sel_files)
        if path == "/api/ai/candidates":
            return app.ai_candidates()
        if path == "/api/ai/signatures/prepare":
            return app.ai_prepare_signatures()
        if path == "/api/ai/signatures/apply":
            return app.apply_signatures(body.get("signatures") or [])
        if path == "/api/ai/review/remove_false_positives":
            return app.remove_false_positives()
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
# logo (96x96 PNG of emblem_ScanBackDoors_512.png), embedded so that the GUI stays a single file
# ---------------------------------------------------------------------------

LOGO_PNG_B64 = (
    "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"
    "Z1Ywnv9H/6cX7l25AfsjVJhBpghHA5xKicT3yfrDnGK/tYVIcr2b1YfvY3mqzj/7O/+AG9eucff2HfzBiMb0BEfPnWWmVmOq0eCx"
    "p5/iO9/7EdVCkS9/5nEqpomlFMvTs9wd9Pn4nXf4r//SX2AYJ7z7+qt4xSLt/Q6GYzM9M0EWJ7z+s9fo7u7xi7/051laWuKH3/s+"
    "//pf/Rt++7d/h3feeptv/sEf8u0/+RY3r1xndXWVxz/zBHdu3ubdt96hWCowikKSRLFzbwPPsbh08SOK5QL/5H/5x+zsdnn940v8"
    "2q/9YxZdD1DUPJdkOOD/809/nZ/7+a/zS3/x5xn5Ppkp8cMxa3fu8fJPXuPjK9d59+XXMaKQs88+ztVLNzEFpIaBs7JIsLVF3O9Q"
    "mJ4ArQja3cMGnSQrmxz9uYcxM4E0tWTyxCKqaCIsI2+rpilhr4dT8hCGQEcxWX8AKkFYkpPnTvIn/+a3KbVqfOUXv85TzzzNQbfH"
    "z37wErev3MCqVLGF4OzSPH////x3+N5PXuLipUsUDIt+nLDV3uNLn/8ia50O77/zNp/93POUmxPs7+ziByG261AqlVnf3ODe7dt8"
    "4ctfAiH4tX/ya/zO7/wumxubjAcDnv/i56iWKuzv7vGn3/kO/8Pf/ju8/erL/Mrf+Kt4XoE3X38nJ/eZFtJxuHv7Hu29bT73la9g"
    "uRV+4zd+i1/8K7/E8UaLfX9EJnKyxf/2736T+x4+z//hl/8yOogolcskwz5X3nmfb/3Hb7EwP8/nPvsUn/vq53n1Oz9kuLXNxPIc"
    "wWBI65lHOfrf/DnSJERaJm6lSnAwBJUdqspLRLPAzNFF1i7fwZj/0jMvTB5b5N7H1zGHCVmU5krgSYw31UJIg9QPDoWcNOVGi9m5"
    "ST586VW++tf/Kk0FjUadU2dPsb25ydVLVyjXqzzy2GOUvQKLczOsdfb54fd/xBNPPMr+cMhg0KdZKDBWmu/+wR9x4swp1je3uHXl"
    "GsK0aExPUnYd3n7zHe574DyNZp0//uZ/5ODgANd1aU1M8Mhjj/DQY4/SrDVRCqIwxLIsNtbXKZaK3PfA/bz92lsIYVBs1Dlod+hs"
    "b+IUbD7zued564136Pd7/Hf/7d/AHw0I0pRyucqPfvITXvzZq/zdv/23mamUqXgeN27d5Tt/+J/59n/+Ho8/9jhPP/ckpmWzcPwE"
    "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"
)
LOGO_DATA_URI = "data:image/png;base64," + LOGO_PNG_B64


# ---------------------------------------------------------------------------
# the page (one self-contained HTML document, no external resources)
# ---------------------------------------------------------------------------

PAGE = r'''<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>Scan Backdoors</title>
<link rel="icon" type="image/png" href="__LOGO__">
<style>
/* ── tokens ──────────────────────────────────────────────── */
:root{
  --bg:#0a0e17; --panel:#0f141f; --panel2:#151b28; --card:#151b28; --field:#151b28;
  --line:#1c2434; --line2:#2e3a52;
  --text:#e2e8f0; --mute:#94a3b8; --mute2:#64748b;
  --acc:#3b82f6; --acc2:#2563eb; --sel:rgba(37,99,235,.25);
  --btn:#1c2434; --btn2:#1c2434; --btn-hover:#242e42; --btn-border:#2e3a52;
  --grid-bg:#0a0e17; --track:#1c2434; --pill:#1c2434; --pill-border:#2e3a52;
  --pop-bg:#151b28; --row-hover:#0f141f; --input-text:#f1f5f9;
  --hi:#fb7185; --hi-bg:rgba(251,113,133,.13); --hi-border:rgba(251,113,133,.32);
  --med:#fbbf24; --med-bg:rgba(251,191,36,.13); --med-border:rgba(251,191,36,.32);
  --low:#38bdf8; --low-bg:rgba(56,189,248,.13); --low-border:rgba(56,189,248,.32);
  --ok:#34d399; --ok-bg:rgba(16,185,129,.2);
  --gold:#fbbf24; --lavender:#818cf8; --sig:#fbbf24;
  --danger:#fb7185; --danger-bg:rgba(244,63,94,.15); --danger-border:rgba(244,63,94,.3);
  --code-bg:#080b12; --code-text:#cbd5e1; --code-head:#151b28;
  --shadow:0 10px 28px rgba(0,0,0,.45);
  --radius:10px;
  --font-sans:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --font-mono:"JetBrains Mono",ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;
  color-scheme:dark
}
@media (prefers-color-scheme:light){:root:not([data-theme="dark"]){
  --bg:#eef1f6; --panel:#ffffff; --panel2:#f1f4f9; --card:#ffffff; --field:#f8fafc;
  --line:#dde3ec; --line2:#c9d2e0;
  --text:#1e293b; --mute:#64748b; --mute2:#94a3b8;
  --acc:#2563eb; --acc2:#1d4ed8; --sel:rgba(37,99,235,.15);
  --btn:#ffffff; --btn2:#f1f5f9; --btn-hover:#e2e8f0; --btn-border:#cbd5e1;
  --grid-bg:#ffffff; --track:#e2e8f0; --pill:#f1f5f9; --pill-border:#e2e8f0;
  --pop-bg:#ffffff; --row-hover:#f8fafc; --input-text:#0f172a;
  --hi:#be123c; --hi-bg:rgba(225,29,72,.09); --hi-border:rgba(225,29,72,.26);
  --med:#b45309; --med-bg:rgba(217,119,6,.11); --med-border:rgba(217,119,6,.3);
  --low:#0369a1; --low-bg:rgba(2,132,199,.09); --low-border:rgba(2,132,199,.28);
  --ok:#059669; --ok-bg:rgba(16,185,129,.15);
  --gold:#d97706; --lavender:#6366f1; --sig:#d97706;
  --danger:#e11d48; --danger-bg:rgba(244,63,94,.1); --danger-border:rgba(244,63,94,.35);
  --code-bg:#0f172a; --code-text:#cbd5e1; --code-head:#1e293b;
  --shadow:0 10px 30px rgba(15,23,42,.12);
  color-scheme:light
}}
:root[data-theme="light"]{
  --bg:#eef1f6; --panel:#ffffff; --panel2:#f1f4f9; --card:#ffffff; --field:#f8fafc;
  --line:#dde3ec; --line2:#c9d2e0;
  --text:#1e293b; --mute:#64748b; --mute2:#94a3b8;
  --acc:#2563eb; --acc2:#1d4ed8; --sel:rgba(37,99,235,.15);
  --btn:#ffffff; --btn2:#f1f5f9; --btn-hover:#e2e8f0; --btn-border:#cbd5e1;
  --grid-bg:#ffffff; --track:#e2e8f0; --pill:#f1f5f9; --pill-border:#e2e8f0;
  --pop-bg:#ffffff; --row-hover:#f8fafc; --input-text:#0f172a;
  --hi:#be123c; --hi-bg:rgba(225,29,72,.09); --hi-border:rgba(225,29,72,.26);
  --med:#b45309; --med-bg:rgba(217,119,6,.11); --med-border:rgba(217,119,6,.3);
  --low:#0369a1; --low-bg:rgba(2,132,199,.09); --low-border:rgba(2,132,199,.28);
  --ok:#059669; --ok-bg:rgba(16,185,129,.15);
  --gold:#d97706; --lavender:#6366f1; --sig:#d97706;
  --danger:#e11d48; --danger-bg:rgba(244,63,94,.1); --danger-border:rgba(244,63,94,.35);
  --code-bg:#0f172a; --code-text:#cbd5e1; --code-head:#1e293b;
  --shadow:0 10px 30px rgba(15,23,42,.12);
  color-scheme:light
}

/* ── base ────────────────────────────────────────────────── */
*{box-sizing:border-box}
*{scrollbar-width:thin;scrollbar-color:var(--line2) transparent}
html,body{height:100%;margin:0}
body{
  background:var(--bg);color:var(--text);
  font:13px/1.45 var(--font-sans);
  display:flex;flex-direction:column;overflow:hidden;
  -webkit-font-smoothing:antialiased;
}
::selection{background:#2563eb;color:#fff}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--line2);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background-color:var(--mute2)}
button,select,input,textarea{font:inherit;color:inherit}
button{background:var(--btn);border:1px solid var(--btn-border);border-radius:6px;padding:6px 10px;cursor:pointer;white-space:nowrap;line-height:1.4;color:var(--text);font-size:12px;transition:background .15s,border-color .15s,color .15s}
button:hover:not(:disabled){background:var(--btn-hover);border-color:var(--btn-border)}
button:disabled{opacity:.45;cursor:default}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
button.primary{background:#2563eb;border-color:#2563eb;color:#fff;font-weight:600;box-shadow:0 1px 2px rgba(37,99,235,.25)}
button.primary:hover:not(:disabled){background:#3b82f6;border-color:#3b82f6}
button.primary:active:not(:disabled){background:#1d4ed8;border-color:#1d4ed8}
button.danger{background:var(--danger);border-color:var(--danger);color:#fff}
button.danger:hover:not(:disabled){filter:brightness(1.1)}
button.ghost{background:transparent;border-color:transparent;color:var(--mute)}
button.ghost:hover:not(:disabled){color:var(--text);border-color:var(--line2)}
input[type=text],input[type=search],input[type=number],select,textarea{background:var(--field);border:1px solid var(--btn-border);border-radius:6px;padding:5px 8px;min-width:0;color:var(--input-text)}
input[type=text]:focus,input[type=search]:focus,input[type=number]:focus,select:focus,textarea:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 1px var(--acc)}
[hidden]{display:none!important}

/* ── header ──────────────────────────────────────────────── */
.top{display:flex;align-items:center;gap:10px;height:44px;padding:0 12px;border-bottom:1px solid var(--line);background:var(--panel);flex:none;z-index:30}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:14px;letter-spacing:-.01em;white-space:nowrap;color:var(--text)}
.brand img{width:28px;height:28px;border-radius:8px;object-fit:cover;box-shadow:0 1px 3px rgba(0,0,0,.3)}
nav{display:flex;align-items:stretch;height:44px;gap:4px;margin-left:14px}
.toptab{background:none;border:0;border-bottom:2px solid transparent;border-radius:0;padding:0 12px;color:var(--mute);cursor:pointer;font-size:12px;font-weight:500;display:flex;align-items:center;gap:6px;transition:color .15s}
.toptab svg{width:14px;height:14px;flex:none}
.toptab:hover{color:var(--text)}
.toptab[aria-selected="true"]{color:var(--text);border-bottom-color:var(--acc);font-weight:600}
.toptab[aria-selected="true"] svg{color:var(--acc)}
[data-theme="light"] .toptab[aria-selected="true"]{color:#2563eb}
.sp{flex:1}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;padding:2px 10px;border-radius:99px;background:var(--ok-bg);color:var(--ok);white-space:nowrap;font-weight:600;border:1px solid rgba(16,185,129,.3)}
.badge::before{content:"";width:6px;height:6px;border-radius:50%;background:#10b981;animation:pulse 1.6s ease-in-out infinite}
.badge.off{background:var(--danger-bg);color:var(--danger);border-color:var(--danger-border)}
.badge.off::before{background:#f43f5e;animation:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.theme{display:flex;align-items:center;gap:2px;padding:4px;background:var(--pill);border:1px solid var(--pill-border);border-radius:99px}
.theme button{display:flex;align-items:center;justify-content:center;width:20px;height:20px;padding:0;border:0;background:transparent;border-radius:99px;cursor:pointer;transition:background .15s,color .15s}
.theme #themeLight svg{width:14px;height:14px}
.theme #themeDark svg{width:12px;height:12px}
.theme #themeLight{color:#64748b}
.theme #themeDark{color:#94a3b8}
.theme button:hover{color:var(--text);border-color:transparent;background:transparent}
.theme #themeLight.on{background:#ffffff;color:#f59e0b;box-shadow:0 1px 2px rgba(15,23,42,.25)}
.theme #themeDark.on{background:#2563eb;color:#ffffff}
.top .ghost{font-size:12px;font-weight:500;padding:4px 10px;border-color:transparent;background:transparent;color:var(--mute)}
.top .ghost:hover:not(:disabled){color:var(--danger);background:rgba(244,63,94,.1);border-color:transparent}
#quitBtn{display:inline-flex;align-items:center;gap:6px}
#quitBtn svg{width:14px;height:14px;flex:none}

/* ── tabs ────────────────────────────────────────────────── */
main{flex:1;min-height:0;position:relative;overflow:hidden;display:flex;flex-direction:column}
.tab{display:none;height:100%;min-height:0}
.tab.active{display:flex;flex-direction:column;overflow:hidden}
#tab-settings.active{overflow:auto;padding:0;gap:0}
#tab-run.active{gap:0;padding:0}

/* ── run bar ─────────────────────────────────────────────── */
.run{display:flex;align-items:center;gap:10px;padding:8px 12px;flex:none;flex-wrap:wrap;border-bottom:1px solid var(--line);background:var(--panel)}
.run button{font-size:12.5px}
.prog{position:relative;flex:1 1 160px;min-width:160px;height:8px;background:var(--track);border:1px solid var(--btn-border);border-radius:99px;overflow:hidden}
.prog i{position:absolute;left:0;top:0;bottom:0;width:0;background:linear-gradient(90deg,#3b82f6,#6366f1,#22d3ee);border-radius:99px;transition:width .2s}
.prog.indet i{width:30%;animation:slide 1.2s infinite ease-in-out}
@keyframes slide{0%{left:-30%}100%{left:100%}}
.progText{color:var(--mute);font-size:11px;font-family:var(--font-mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:38%}
.menu{position:relative}
.menu .pop{display:none;position:absolute;right:0;top:100%;margin-top:6px;background:var(--pop-bg);border:1px solid var(--btn-border);border-radius:8px;padding:4px 0;min-width:220px;z-index:40;box-shadow:0 20px 25px -5px rgba(2,6,23,.45),0 8px 10px -6px rgba(2,6,23,.45)}
.menu.open .pop{display:block}
.pop button,.pop a{display:flex;align-items:center;gap:7px;width:100%;text-align:left;border:0;background:none;padding:6px 12px;border-radius:0;cursor:pointer;color:var(--text);text-decoration:none;font-size:12px;white-space:normal}
.pop button:hover,.pop a:hover{background:var(--btn-hover);border-color:transparent}
.pop button:disabled,.pop a[aria-disabled="true"]{opacity:.4;cursor:default;pointer-events:none}
.pop hr{border:0;border-top:1px solid var(--btn-border);margin:4px 0}
.pop .lbl{display:block;padding:4px 12px;color:var(--mute);font-size:10px;letter-spacing:.05em;text-transform:uppercase;font-weight:600}
.ai-stats{display:inline-flex;align-items:center;white-space:nowrap;padding:2px 10px;background:var(--btn);border:1px solid var(--btn-border);border-radius:99px;color:var(--mute);font-size:11px;font-family:var(--font-mono)}
.ai-stats b{color:var(--text);font-weight:600}
#startBtn,#stopBtn{display:inline-flex;align-items:center;gap:6px}
#startBtn svg{width:14px;height:14px;flex:none}
#stopBtn{font-size:12px;font-weight:500}
#stopBtn .sq{width:10px;height:10px;border-radius:2px;background:currentColor;flex:none}
#stopBtn:not(:disabled){background:rgba(225,29,72,.15);border-color:rgba(244,63,94,.4);color:var(--danger)}
#stopBtn:not(:disabled):hover{background:rgba(225,29,72,.25)}
#stopBtn:disabled{opacity:1;background:var(--btn2);border-color:var(--btn-border);color:var(--mute2)}
.ai-btn-ico{color:#818cf8}
[data-theme="light"] .ai-btn-ico{color:#6366f1}
#aiBtn,#candBtn,#fpBtn,#repBtn{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:500}
#aiBtn{gap:5px}
#repBtn svg{width:12px;height:12px;color:var(--mute);flex:none}
.cbtn-ico{width:14px;height:14px;color:#10b981;flex:none}
.cbadge{padding:1px 6px;border-radius:4px;background:rgba(244,63,94,.2);color:var(--danger);font-size:10px;font-family:var(--font-mono)}
[data-theme="light"] .cbadge{color:#be123c}
.hint{color:var(--mute2);font-size:11.5px;white-space:nowrap}
#aiHint{overflow:hidden;text-overflow:ellipsis}

/* ── toolbar (filters + actions) ─────────────────────────── */
.toolbar{background:var(--panel);border-bottom:1px solid var(--line);padding:8px 12px;display:flex;flex-direction:column;gap:8px;flex:none}
.filtersRow{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.chip{border-radius:99px;padding:4px 10px;cursor:pointer;font-size:12px;font-weight:500;background:var(--btn2);border:1px solid var(--btn-border);color:var(--text);transition:background .15s,border-color .15s}
.chip b{font-weight:600;margin-left:2px;font-family:var(--font-mono);color:var(--mute)}
#c-HIGH{color:#f43f5e}#c-MEDIUM{color:#f59e0b}#c-LOW{color:#94a3b8}
#c-ALL{color:var(--mute)}.chip[aria-pressed="true"] #c-ALL{color:#fff}
.chip[aria-pressed="true"]{background:#2563eb;border-color:#3b82f6;color:#fff;font-weight:600}
.chip[data-l="HIGH"]:not([aria-pressed="true"]):hover{border-color:rgba(244,63,94,.5)}
.chip[data-l="MEDIUM"]:not([aria-pressed="true"]):hover{border-color:rgba(245,158,11,.5)}
.chip[data-l="LOW"]:not([aria-pressed="true"]):hover{border-color:rgba(14,165,233,.5)}
.chip:not([data-l]):not([aria-pressed="true"]):hover,.chip[data-l="ALL"]:not([aria-pressed="true"]):hover{border-color:var(--btn-border);background:var(--btn-hover)}
.searchWrap{position:relative;width:256px;flex:0 1 256px;min-width:160px}
.searchWrap svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);width:14px;height:14px;color:var(--mute);pointer-events:none}
.searchWrap input{width:100%;padding:4px 10px 4px 32px;font-size:12px;border-radius:6px}
.filtersRow select{font-size:12px;cursor:pointer;padding:4px 10px;border-radius:6px}
#fReset{font-size:12px;font-weight:500;padding:4px 10px;background:var(--btn2)}
#goRun{font-size:12px;font-weight:600;padding:6px 14px}
.count{color:var(--mute);margin-left:auto;font-size:12px;white-space:nowrap;font-family:var(--font-mono)}
.actionsRow{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.actionsRow button{font-size:12px;font-weight:500;padding:4px 10px;display:inline-flex;align-items:center;gap:6px}
.actionsRow button svg{width:14px;height:14px;flex:none}
.actionsRow button.danger{background:rgba(244,63,94,.1);border-color:rgba(244,63,94,.3);color:var(--danger)}
.actionsRow button.danger:hover:not(:disabled){background:rgba(244,63,94,.2);border-color:rgba(244,63,94,.3)}
.actionsRow .hint{margin-left:auto;white-space:nowrap}
@media(max-width:1279px){.actionsRow .hint{display:none}}
.ico-amber{color:#f59e0b}.ico-orange{color:#fb923c}.ico-purple{color:#c084fc}.ico-blue{color:#3b82f6}.ico-rose{color:#f43f5e}

/* ── main split: table + bottom panel ────────────────────── */
.main{flex:1;min-height:0;display:flex;flex-direction:column;padding:0}
.tablewrap{flex:1;min-height:120px;overflow:auto;border:0;border-radius:0;background:var(--grid-bg);outline:none;user-select:none;-webkit-user-select:none}
.tablewrap:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
table{border-collapse:separate;border-spacing:0;width:100%;table-layout:fixed}
thead th{position:sticky;top:0;background:var(--panel);text-align:left;font-weight:600;font-size:11px;letter-spacing:0;padding:8px;border-bottom:1px solid var(--line);cursor:pointer;user-select:none;z-index:2;white-space:nowrap;color:var(--mute);transition:color .15s}
thead th:hover{color:var(--text)}
th[data-col="file"],th[data-col="date"],th[data-col="signature"],#aiCol{padding-left:12px;padding-right:12px}
th.chk{width:34px;text-align:center;cursor:default;padding:8px 4px}
th.chk:hover{color:var(--mute)}
#rowSelAll,#tbody input[data-chk]{accent-color:#2563eb;width:14px;height:14px;cursor:pointer;margin:0;vertical-align:middle}
thead th .arr{color:var(--acc);margin-left:3px;font-size:10px}
thead th.num{text-align:right}
thead th.num .arr{margin-left:3px}
td{padding:6px 8px;border-bottom:1px solid rgba(28,36,52,.8);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-variant-numeric:tabular-nums;font-size:12px;color:var(--text)}
[data-theme="light"] td{border-bottom-color:rgba(226,232,240,.7)}
td.chk{text-align:center;padding:6px 4px}
#tbody td:nth-child(4),#tbody td:nth-child(7),#tbody td:nth-child(9),#tbody td:nth-child(10){padding-left:12px;padding-right:12px}
tbody tr{cursor:default;transition:background .1s}
tbody tr:hover{background:var(--row-hover)}
tbody tr.sel{background:var(--sel)}
tbody tr.sel:hover{background:var(--sel)}
.num{text-align:right;font-family:var(--font-mono);font-size:12px;color:var(--mute)}
#tbody td:nth-child(3).num{color:var(--text)}
td:nth-child(4){color:var(--text)}
td:nth-child(7){font-family:var(--font-mono);font-size:11px;color:var(--mute)}
td:nth-child(8){color:var(--mute)}
td:nth-child(9){color:var(--text)}
.lv{display:inline-block;min-width:0;text-align:center;border-radius:4px;font-size:10px;font-weight:700;padding:2px 8px;letter-spacing:.025em;border:0}
.lv.HIGH{background:#e11d48;color:#fff}
.lv.MEDIUM{background:#f59e0b;color:#0f172a}
.lv.LOW{background:#242e42;color:#cbd5e1}
[data-theme="light"] .lv.HIGH{background:#e11d48;color:#fff}
[data-theme="light"] .lv.MEDIUM{background:#f59e0b;color:#0f172a}
[data-theme="light"] .lv.LOW{background:#e2e8f0;color:#334155}
tr.empty-row td{padding:60px 12px;text-align:center;color:var(--mute);cursor:default;font-size:13px;font-weight:500}
.gutter{height:6px;flex:none;cursor:row-resize;display:flex;align-items:center;justify-content:center;background:transparent;transition:background .15s}
.gutter::after{content:"";width:40px;height:4px;border-radius:99px;background:var(--line2);transition:background .15s}
.gutter:hover,.gutter.drag{background:rgba(59,130,246,.15)}
.gutter:hover::after,.gutter.drag::after{background:#3b82f6}

/* ── bottom panel: Details / Log ─────────────────────────── */
.bottom{flex:none;height:230px;min-height:60px;border:0;border-top:1px solid var(--line);border-radius:0;background:var(--panel);display:flex;flex-direction:column;overflow:hidden}
.bottom.collapsed{height:34px!important;min-height:0;overflow:hidden}
.btabs{display:flex;align-items:center;gap:4px;padding:4px 12px;border-bottom:1px solid var(--line);flex:none;min-height:37px}
.btab{background:none;border:1px solid transparent;border-radius:4px;padding:4px 10px;color:var(--mute);cursor:pointer;font-size:12px;font-weight:500;transition:color .15s,background .15s}
.btab:hover{color:var(--text)}
.btab[aria-selected="true"]{color:var(--text);background:var(--btn);border-color:var(--btn-border);font-weight:600;box-shadow:0 1px 2px rgba(2,6,23,.15)}
[data-theme="light"] .btab[aria-selected="true"]{color:#0f172a}
.btabs .sp{flex:1}
.btabs button.btn{font-size:11px;padding:3px 9px}
.engBar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;color:var(--mute);font-size:11.5px;padding:2px 0 10px}
.engBar .btn{font-size:11px;padding:3px 10px}
#eng{overflow:auto}
.engTbl{width:100%;border-collapse:collapse;font-size:12px}
.engTbl th{text-align:left;color:var(--mute2);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.05em;padding:4px 12px 4px 0;border-bottom:1px solid var(--line)}
.engTbl td{padding:7px 12px 7px 0;border-bottom:1px solid var(--line);vertical-align:top}
.engName{font-weight:600;color:var(--text);white-space:nowrap}
.engVer{font-family:var(--font-mono);color:var(--mute);white-space:nowrap}
.engYes{color:var(--ok);font-weight:600}
.engBad{color:var(--danger);font-weight:600}
.engNo{color:var(--mute2)}
.engDir{font-family:var(--font-mono);font-size:10.5px;color:var(--mute2);white-space:normal;overflow-wrap:anywhere;max-width:46ch}
#foldBtn{color:var(--mute);background:var(--btn);border:1px solid var(--btn-border);border-radius:4px;padding:4px;display:inline-flex;align-items:center;justify-content:center}
.bottom.collapsed #foldBtn svg{transform:rotate(180deg)}
#foldBtn svg{width:14px;height:14px;transition:transform .2s}
.detQuickPath{display:none;flex:0 1 auto;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono);font-size:11px;color:var(--mute2)}
@media(min-width:1100px){.detQuickPath{display:inline-block}}
.pane{flex:1;overflow:auto;padding:12px;font:12.5px/1.5 var(--font-sans)}
.pane.log{font:11px/1.6 var(--font-mono);white-space:pre-wrap;word-break:break-word;margin:0;background:var(--code-bg);color:var(--code-text);padding:12px}
.empty{color:var(--mute2)}
.multi{color:var(--mute);font-size:12px;margin-bottom:8px;font-weight:600}

/* details pane (mockup-style) */
.detWrap{display:flex;flex-direction:column;gap:10px}
.detMeta{display:flex;flex-direction:column;gap:8px;min-width:0}
.detPath{display:flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px}
.detPathTop{min-width:0;flex:1}
.detLabel{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--mute);font-weight:600}
.detPathVal{font-family:var(--font-mono);font-size:12px;color:var(--text);white-space:normal;overflow-wrap:anywhere;line-height:1.4;margin-top:2px}
.detCopyBtn{flex:none;font-size:11px;font-weight:500;padding:4px 8px;border-radius:4px;background:var(--btn2);border:0;color:var(--mute)}
.detCopyBtn:hover:not(:disabled){background:var(--btn-hover)}
.detGrid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.detCard{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px;min-width:0}
.detVal{font-family:var(--font-mono);font-size:11px;color:var(--mute);white-space:normal;overflow-wrap:anywhere;line-height:1.4;margin-top:2px}
.detSig{font-family:var(--font-sans);font-size:11px;font-weight:500;color:var(--sig)}
.detAiBox{background:rgba(16,185,129,.05);border:1px solid rgba(16,185,129,.25);border-radius:6px;padding:10px}
.detAiBox.v-real{background:rgba(244,63,94,.1);border-color:rgba(244,63,94,.35)}
.detAiBox.v-real .detLabel{color:var(--danger)}
.detAiBox.v-fp .detLabel{color:var(--ok)}
.detAiBox.v-uncertain{background:rgba(245,158,11,.08);border-color:rgba(245,158,11,.3)}
.detAiBox.v-uncertain .detLabel{color:#f59e0b}
.detAiBox.v-error{background:rgba(249,115,22,.08);border-color:rgba(249,115,22,.3)}
.detAiBox.v-error .detLabel{color:#fb923c}
.detAiHead{display:flex;align-items:center;justify-content:space-between;gap:8px}
.detAiHead .detLabel{color:var(--ok)}
.detAiReason{margin:4px 0 0;font-size:12px;line-height:1.625;color:var(--mute);white-space:pre-wrap;word-break:break-word}
.detCode{display:flex;flex-direction:column;flex:none;min-height:0;max-height:170px;background:var(--code-bg);border:1px solid var(--line);border-radius:6px;overflow:hidden}
.detCodeHead{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:4px 10px;background:var(--code-head);border-bottom:1px solid var(--line);font-family:var(--font-mono);font-size:11px;color:#94a3b8;flex:none}
.detCodeFile{font-family:var(--font-mono);font-size:10.5px;color:var(--mute);text-transform:none;letter-spacing:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:55%}
.detCodeBody{flex:1;margin:0;padding:10px;overflow:auto;font:11px/1.25 var(--font-mono);color:var(--code-text);white-space:pre-wrap;word-break:break-word}
@media(max-width:1099px){.detWrap{flex-direction:row;height:100%}.detMeta{flex:0 0 46%;min-width:0;overflow:auto}.detCode{flex:1;min-width:0;max-height:none;height:100%}}
@media(min-width:1500px){.detWrap{flex-direction:row;height:100%}.detMeta{flex:0 0 46%;min-width:0;overflow:auto}.detCode{flex:1;min-width:0;max-height:none;height:100%}}

/* AI badge + chip */
.ai-badge{display:inline-flex;align-items:center;gap:4px;padding:0;border-radius:0;background:transparent;font-size:12px;white-space:nowrap;font-weight:500;font-family:var(--font-sans)}
td.ai-real,td.ai-fp,td.ai-uncertain,td.ai-error,td.ai-none{background:transparent}
.ai-badge.ai-real{color:#fb7185;font-weight:600}.ai-badge.ai-fp{color:#34d399}.ai-badge.ai-uncertain{color:#f59e0b}.ai-badge.ai-error{color:#fb923c}.ai-badge.ai-none{color:#475569}
[data-theme="light"] .ai-badge.ai-real{color:#e11d48}
[data-theme="light"] .ai-badge.ai-fp{color:#059669}
[data-theme="light"] .ai-badge.ai-uncertain{color:#b45309}
[data-theme="light"] .ai-badge.ai-error{color:#c2410c}
[data-theme="light"] .ai-badge.ai-none{color:#94a3b8}

/* ── footer ──────────────────────────────────────────────── */
.footer{flex:0 0 auto;display:flex;gap:8px;align-items:center;padding:0 12px;background:var(--panel);border-top:1px solid var(--line);font-size:11px;color:var(--mute);height:28px;z-index:30}
.footer #status{color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.footer code{color:#60a5fa;font-family:var(--font-mono);font-size:11px;cursor:pointer}
.footer code:hover{text-decoration:underline}
[data-theme="light"] .footer code{color:#2563eb}
.footer .ver{font-family:var(--font-mono);font-weight:600;color:var(--text)}
.footer .dot{color:var(--mute2)}
.footer .engines{color:var(--mute2);font-family:var(--font-mono);font-size:10.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:46vw}

/* ── settings tab ────────────────────────────────────────── */
.setWrap{max-width:896px;width:100%;margin:0 auto;padding:24px 24px 28px;display:flex;flex-direction:column;gap:20px}
.setHead{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px;border-bottom:1px solid var(--line);padding-bottom:12px}
.setHead h1{font-size:16px;font-weight:700;margin:0;letter-spacing:-.01em}
.setHead p{color:var(--mute);font-size:12px;margin:2px 0 0;max-width:640px}
.setGrid{display:grid;grid-template-columns:1fr;gap:16px}
@media(min-width:768px){.setGrid{grid-template-columns:1fr 1fr;align-items:start}}
fieldset.card{border:1px solid var(--line);border-radius:12px;margin:0;padding:16px;background:var(--panel);display:flex;flex-direction:column;gap:12px;min-width:0}
fieldset.card legend{padding:0;font-size:12px;text-transform:uppercase;letter-spacing:.05em;font-weight:700;color:var(--mute)}
fieldset.card.card-blue legend{color:#3b82f6}
fieldset.card.card-amber legend{color:#f59e0b}
fieldset.card.card-indigo legend{color:#6366f1}
fieldset.card.card-emerald legend{color:#10b981}
.grid{display:grid;grid-template-columns:1fr auto;gap:12px 8px;align-items:center}
.grid label{grid-column:1/-1;font-size:12px;font-weight:500;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:-8px}
.grid input[type=text]{grid-column:1;min-width:0;font-family:var(--font-mono);font-size:12px;padding:6px 12px;border-radius:6px}
.opts{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px}
.opts label{display:flex;flex-direction:column;gap:4px;color:var(--text);font-size:12px;font-weight:500}
.opts label input{width:100%;font-family:var(--font-mono);font-size:12px;padding:6px 12px;border-radius:6px}
.grid button{font-size:12px;font-weight:500;padding:6px 12px;border-radius:6px}
.flags{display:flex;flex-wrap:wrap;gap:7px 16px}
.flags label{display:flex;align-items:center;gap:8px;cursor:pointer;font-size:12px;color:var(--text)}
.flags input[type=checkbox]{accent-color:#2563eb;width:14px;height:14px;cursor:pointer}
.card .hint{white-space:normal;line-height:1.5;color:var(--mute);font-size:12px}
.setNote{color:var(--mute2);font-size:12px;text-align:center}

/* ── dialogs / toasts / context menu ─────────────────────── */
#ctx{position:fixed;display:none;z-index:60;background:var(--pop-bg);border:1px solid var(--btn-border);border-radius:8px;padding:4px 0;width:208px;box-shadow:0 25px 50px -12px rgba(2,6,23,.5);font-size:12px}
#ctx div{padding:6px 12px;display:flex;align-items:center;gap:8px;cursor:pointer;color:var(--text)}
#ctx div:hover{background:var(--btn-hover)}
#ctx hr{border:0;border-top:1px solid var(--btn-border);margin:4px 0}
.overlay{position:fixed;inset:0;background:rgba(2,6,23,.7);display:flex;align-items:center;justify-content:center;z-index:100;backdrop-filter:blur(4px);padding:16px}
.dlg{background:var(--panel);border:1px solid var(--btn-border);border-radius:12px;width:min(768px,92vw);max-height:88vh;display:flex;flex-direction:column;box-shadow:0 25px 50px -12px rgba(2,6,23,.6)}
.dlg.wide{width:min(760px,94vw)}
.dlg h3{margin:0;padding:12px 16px;border-bottom:1px solid var(--line);font-size:14px;font-weight:700;color:var(--text);letter-spacing:.01em}
.dlg .body{padding:16px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:12px;line-height:1.6;color:var(--text)}
.dlg .btns{padding:10px 16px;border-top:1px solid var(--line);background:var(--panel2);display:flex;gap:8px;justify-content:flex-end}
.dlg.error h3{color:var(--danger)}
.dlg.warn h3{color:var(--gold)}
#toasts{position:fixed;right:16px;bottom:40px;display:flex;flex-direction:column;gap:8px;z-index:220}
.toast{background:var(--panel);border:1px solid var(--line2);border-left:4px solid var(--acc);border-radius:8px;padding:9px 14px;max-width:440px;box-shadow:var(--shadow);white-space:pre-wrap;font-size:12.5px}
.toast.error{border-left-color:var(--danger)}
.toast.ok{border-left-color:var(--ok)}
.fsbar{display:flex;gap:6px;margin-bottom:8px;align-items:center}
.fsbar input{flex:1}
.fslist{border:1px solid var(--line);border-radius:8px;background:var(--field);height:280px;overflow:auto}
.fslist div{padding:5px 11px;cursor:pointer;display:flex;justify-content:space-between;gap:12px;font-size:12.5px;color:var(--text)}
.fslist div:hover{background:var(--panel2)}
.fslist div.picked{background:var(--sel)}
.fslist small{color:var(--mute2);font-family:var(--font-mono);font-size:11px}

/* ── wide screens: table 2/3 + Detail/Log panel 1/3 (right column) ── */
@media(min-width:1100px){
  .main{flex-direction:row}
  .tablewrap{flex:0 0 auto;width:calc((100% - 6px) * 0.6667);min-width:0;min-height:0}
  .gutter{flex:0 0 auto;width:6px;height:auto;cursor:col-resize}
  .gutter::after{width:4px;height:40px}
  .bottom{flex:1 1 0;width:auto;height:auto;min-height:0;min-width:0;overflow:hidden;border-top:0;border-left:1px solid var(--line)}
  .bottom.collapsed{height:auto!important;min-height:0;overflow:hidden}
  #foldBtn{display:none}
}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><img src="__LOGO__" alt="" width="26" height="26"><span>Scan Backdoors</span></div>
  <nav role="tablist">
    <button class="toptab" role="tab" data-tab="settings" aria-selected="false"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3" stroke-width="2"/></svg>Settings</button>
    <button class="toptab" role="tab" data-tab="run" aria-selected="true"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>Run and results</button>
  </nav>
  <span class="sp"></span>
  <span id="conn" class="badge off">connecting…</span>
  <div class="theme" role="group" aria-label="Theme">
    <button id="themeLight" type="button" title="Light theme" aria-pressed="false"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></button>
    <button id="themeDark" type="button" title="Dark theme" aria-pressed="true"><svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg></button>
  </div>
  <button id="quitBtn" class="ghost" title="Stop the local server"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>Quit server</button>
</header>
<main>
  <section id="tab-settings" class="tab">
    <div class="setWrap">
      <header class="setHead">
        <div>
          <h1>Scanner &amp; Engine Configuration</h1>
          <p>Configure target filesystem paths, heuristic thresholds, exclusions, and the local AI review endpoint.</p>
        </div>
        <button id="goRun" class="primary">Go to run →</button>
      </header>
      <div class="setGrid">
        <fieldset class="card card-blue"><legend>1. Scan scope &amp; targets</legend>
          <div id="pathGrid" class="grid"></div>
        </fieldset>
        <fieldset class="card card-amber"><legend>2. Heuristic scoring &amp; flags</legend>
          <div id="optGrid" class="opts"></div>
          <div id="flagRow" class="flags"></div>
        </fieldset>
        <fieldset class="card card-emerald"><legend>3. Mass cleanup</legend>
          <div id="cleanRow" class="flags"></div>
          <div class="hint">Mass cleanup (clean_malware.py) acts on files from the current report. Nothing is deleted permanently without the flag — everything is quarantined first.</div>
        </fieldset>
        <fieldset class="card card-indigo"><legend>4. AI review (local model)</legend>
          <div class="flags" id="aiFlagRow"></div>
          <div class="opts" id="aiGrid"></div>
          <div class="hint">The AI reviews the suspicious files from the current report and stores the verdicts in the CSV (columns “AI Verdict” / “AI Comment”). The scanner's own Verdict column is never overwritten. Only localhost endpoints are allowed, and the endpoint is validated before any request is sent. File contents and snippets are sent to that endpoint.</div>
        </fieldset>
      </div>
      <div class="setNote">Settings are saved automatically and applied on the next launch.</div>
    </div>
  </section>

  <section id="tab-run" class="tab">
    <section class="run">
      <button id="startBtn" class="primary"><svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M6.3 2.841A1.5 1.5 0 004 4.11V15.89a1.5 1.5 0 002.3 1.269l9.344-5.89a1.5 1.5 0 000-2.538L6.3 2.84z"/></svg><span>Start scan</span></button>
      <button id="stopBtn" disabled><span class="sq"></span><span>Stop</span></button>
      <div class="prog" id="prog" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><i id="progFill"></i></div>
      <span class="progText" id="progText"></span>
      <button id="aiBtn" disabled title="Enable AI review in the Settings tab first"><span class="ai-btn-ico">🤖</span><span>AI review</span></button>
      <span class="ai-stats" id="aiStats" hidden></span>
      <button id="fpBtn" disabled><span>🧹</span><span>Remove false positives</span></button>
      <button id="candBtn" disabled title="Enable AI review in the Settings tab first"><svg class="cbtn-ico" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg><span>Candidates</span></button>
      <span class="hint" id="aiHint"></span>
      <div class="menu" id="repMenu">
        <button id="repBtn" aria-haspopup="true" aria-expanded="false" aria-controls="repPop"><span>Reports</span><svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/></svg></button>
        <div class="pop" id="repPop" role="menu">
          <button class="popbtn" id="repFolder">📁 Open reports folder</button><hr>
          <span class="lbl">Open</span>
          <button class="popbtn" data-rep="csv" disabled>📂 CSV</button>
          <button class="popbtn" data-rep="xlsx" disabled>📂 XLSX</button>
          <button class="popbtn" data-rep="json" disabled>📂 JSON</button><hr>
          <span class="lbl">Download</span>
          <a class="popbtn" href="/download/csv" data-dl="csv" aria-disabled="true">⬇ Download CSV</a>
          <a class="popbtn" href="/download/xlsx" data-dl="xlsx" aria-disabled="true">⬇ Download XLSX</a>
          <a class="popbtn" href="/download/json" data-dl="json" aria-disabled="true">⬇ Download JSON</a>
        </div>
      </div>
    </section>

    <div class="toolbar">
      <div class="filtersRow">
        <button class="chip" data-l="ALL" aria-pressed="true">All<b id="c-ALL"></b></button>
        <button class="chip" data-l="HIGH" aria-pressed="false">High<b id="c-HIGH"></b></button>
        <button class="chip" data-l="MEDIUM" aria-pressed="false">Medium<b id="c-MEDIUM"></b></button>
        <button class="chip" data-l="LOW" aria-pressed="false">Low<b id="c-LOW"></b></button>
        <div class="searchWrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
          <input id="fQuery" type="search" placeholder="Search file / signature  (press /)" aria-label="Search file or signature">
        </div>
        <select id="fAi" title="Filter by the AI verdict">
          <option value="all">AI: all</option>
          <option value="malicious">AI: malicious</option>
          <option value="clean">AI: clean</option>
          <option value="not_reviewed">AI: not reviewed</option>
          <option value="hide_fp">AI: hide false positives</option>
        </select>
        <button id="fReset">Reset</button>
        <span class="count" id="count"></span>
      </div>
      <div class="actionsRow">
        <button data-act="reveal"><svg class="ico-amber" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z"/></svg><span>Show file</span></button>
        <button data-act="quarantine"><svg class="ico-orange" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg><span>Quarantine</span></button>
        <button data-act="delete" class="danger"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg><span>Delete from disk</span></button>
        <button id="cleanBtn"><svg class="ico-purple" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z"/></svg><span>Mass cleanup</span></button>
        <button id="selectAllBtn"><svg class="ico-blue" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><span>Select all</span></button>
        <span class="hint">Click · Ctrl/Shift+click · Ctrl+A · ↑↓ to move · right-click for more</span>
      </div>
    </div>

    <div class="main">
      <div class="tablewrap" id="tableWrap" tabindex="0">
        <table>
          <colgroup><col style="width:34px"><col style="width:84px"><col style="width:56px"><col style="width:220px"><col style="width:56px"><col style="width:72px"><col style="width:128px"><col style="width:60px"><col><col style="width:132px"></colgroup>
          <thead><tr id="thead">
            <th class="chk"><input type="checkbox" id="rowSelAll" title="Select all rows" aria-label="Select all rows"></th>
            <th data-col="level">Level</th><th class="num" data-col="score">Score</th><th data-col="file">File</th><th class="num" data-col="line">Line</th>
            <th class="num" data-col="size">Size</th><th data-col="date">Date</th><th data-col="delete">Del</th><th data-col="signature">Signature</th><th id="aiCol">AI</th>
          </tr></thead>
          <tbody id="tbody"></tbody>
        </table>
      </div>
      <div class="gutter" id="gut" title="Drag to resize · double-click to collapse"></div>
      <div class="bottom" id="bottom">
        <div class="btabs">
          <button class="btab" data-p="det" aria-selected="true">Details</button>
          <button class="btab" data-p="log" aria-selected="false">Log</button>
          <button class="btab" data-p="eng" aria-selected="false">Engines</button>
          <span class="sp"></span>
          <span class="detQuickPath" id="detQuickPath"></span>
          <button id="logClear" class="btn" hidden>Clear view</button>
          <button id="logCopy" class="btn" hidden>Copy log</button>
          <button id="foldBtn" class="btn" title="Collapse / expand" aria-label="Collapse or expand the bottom panel"><svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/></svg></button>
        </div>
        <div class="pane" id="det"><span class="empty">Select a row to see details.</span></div>
        <pre class="pane log" id="log" hidden></pre>
        <div class="pane" id="eng" hidden></div>
      </div>
    </div>
  </section>
</main>
<footer class="footer"><span id="status">Ready to run</span><span id="engines" class="engines" title="Engines detected on the site"></span><span class="sp"></span>
  <span>Bookmark this page:</span><code id="selfUrl"></code><span class="dot">·</span><span class="ver">v__VERSION__</span></footer>
<div id="ctx"></div>
<div id="toasts"></div>
<script>
(() => {
'use strict';
const $ = (id) => document.getElementById(id);
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ESC[c]);
const S = {settings: {}, tab: 'run', logNext: 0, ver: -1, noticeSeq: null, boot: null, sel: new Set(), order: [], last: null,
           sort: 'score', desc: true, level: 'ALL', job: null, rows: [], saveTimer: null, online: false, fTimer: null, pvTimer: null, aiStats: null};

async function api(path, body, opts) {
  const opt = {headers: {'X-Requested-With': 'scan-backdoors-gui'}};
  if (body !== undefined) { opt.method = 'POST'; opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  if (opts && opts.signal) opt.signal = opts.signal;
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

// ────────────────────────────────────────────── theme
function effectiveTheme() {
  try {
    const saved = localStorage.getItem('sb_theme');
    if (saved === 'light' || saved === 'dark') return saved;
  } catch (e) { /* no storage */ }
  return matchMedia('(prefers-color-scheme:light)').matches ? 'light' : 'dark';
}
function paintTheme(t) {
  document.documentElement.dataset.theme = t;
  document.getElementById('themeLight').classList.toggle('on', t === 'light');
  document.getElementById('themeLight').setAttribute('aria-pressed', t === 'light' ? 'true' : 'false');
  document.getElementById('themeDark').classList.toggle('on', t === 'dark');
  document.getElementById('themeDark').setAttribute('aria-pressed', t === 'dark' ? 'true' : 'false');
}
function setTheme(t) {
  try { localStorage.setItem('sb_theme', t); } catch (e) { /* no storage */ }
  paintTheme(t);
}
function toggleTheme() { setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark'); }

// ────────────────────────────────────────────── settings form
const PATHS = [['scanner_path', 'Scanner script', 'file'], ['site_dir', 'Site folder', 'dir'], ['baseline_dir', 'Clean Joomla (optional)', 'dir'],
  ['whitelist_path', 'Whitelist (optional)', 'file'], ['csv_path', 'CSV report', 'save'], ['xlsx_path', 'XLSX report (optional)', 'save'],
  ['json_path', 'JSON report (optional)', 'save']];
const OPTS = [['max_size', 'File size, MB'], ['max_matches', 'Max findings/level'], ['min_score', 'Minimum score'],
  ['since', 'Modified after (14d or 2026-09-01)'], ['workers', 'Processes (0 = auto)'], ['exclude_ext', 'Exclude extensions (comma-separated)'],
  ['exclude_dir', 'Exclude folders (comma-separated)']];
const FLAGS = [['only_critical', 'Critical only'], ['no_warnings', 'No warnings'], ['no_csv', 'Do not create CSV'], ['auto_open', 'Open the CSV after scanning']];
const CLEAN = [['clean_permanent', 'Delete permanently (no quarantine)'], ['clean_fm', 'Include web file managers (elp.php etc.)'],
  ['clean_core', 'Replace modified core files with originals (needs a clean Joomla of the same version)']];
const AI_FLAGS = [['ai_enabled', 'Enable AI review (after the scan)']];
const AI_TEXT = [['ai_base_url', 'Endpoint (e.g. http://127.0.0.1:8080/v1)'],
  ['ai_model', 'Model (optional - the gateway-loaded model is used when empty)']];

function buildSettings() {
  const grid = $('pathGrid'); grid.innerHTML = '';
  PATHS.forEach(([k, label, mode]) => {
    const l = document.createElement('label'); l.textContent = label + ':'; l.htmlFor = 'set_' + k;
    const i = document.createElement('input'); i.type = 'text'; i.id = 'set_' + k; i.dataset.key = k;
    const b = document.createElement('button'); b.textContent = 'Browse…';
    b.addEventListener('click', async () => { const p = await browse(mode, i.value, label); if (p != null) { i.value = p; onSettingChanged(); } });
    grid.append(l, i, b);
    if (k === 'baseline_dir') {
      const fb = document.createElement('button'); fb.textContent = 'Fetch baseline';
      fb.title = 'Detect the Joomla version of the site and download the official clean Full_Package from the joomla/joomla-cms GitHub releases';
      fb.addEventListener('click', () => fetchBaseline(false));
      grid.append(fb);
    }
  });
  const og = $('optGrid'); og.innerHTML = '';
  OPTS.forEach(([k, label]) => {
    const l = document.createElement('label'); l.textContent = label;
    const i = document.createElement('input'); i.type = 'text'; i.id = 'set_' + k; i.dataset.key = k; l.appendChild(i); og.appendChild(l);
  });
  const flag = (box, list) => { box.innerHTML = ''; list.forEach(([k, label]) => {
    const l = document.createElement('label'); const c = document.createElement('input'); c.type = 'checkbox'; c.id = 'set_' + k; c.dataset.key = k;
    l.append(c, document.createTextNode(label)); box.appendChild(l); }); };
  flag($('flagRow'), FLAGS); flag($('cleanRow'), CLEAN); flag($('aiFlagRow'), AI_FLAGS);
  const aog = $('aiGrid'); aog.innerHTML = '';
  AI_TEXT.forEach(([k, label]) => {
    const l = document.createElement('label'); l.textContent = label;
    const i = document.createElement('input'); i.type = 'text'; i.id = 'set_' + k; i.dataset.key = k; l.appendChild(i); aog.appendChild(l);
  });
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
async function saveSettings() { clearTimeout(S.saveTimer); S.saveTimer = null; try { await api('/api/settings', {settings: readSettings()}); S.settings = readSettings(); setBusy(S.job); } catch (e) { showErr(e); } }
async function fetchBaseline(autoScan) {
  try {
    await saveSettings();
    const d = await api('/api/baseline/detect', {});
    const yes = await confirmDlg('Download the clean Joomla ' + d.version + ' baseline?',
      'The site looks like Joomla ' + d.version + '.\n\n' +
      'The tool will download the official Full_Package from the joomla/joomla-cms GitHub releases over HTTPS, verify it, and unpack it into the joomla-baselines folder of your Scan Backdoors data folder (~/.scan_backdoors, or $SBD_DATA_DIR). When it finishes, the Clean Joomla folder setting is filled in automatically.\n\n' +
      'This is the only part of the app that reaches the internet, and only after this confirmation.',
      'Download');
    if (!yes) return;
    const r = await api('/api/baseline/fetch', {version: d.version});
    if (autoScan) S.autoScanBaseline = true;
    toast('Downloading the Joomla ' + r.version + ' baseline - progress in the Log tab.', 'ok');
  } catch (e) { msgDlg('Baseline', e.message, 'error'); }
}

// ────────────────────────────────────────────── server-side file browser
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
    cur = data.path; pathIn.value = cur; picked = null; nameIn.value = ''; list.innerHTML = '';
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

// ────────────────────────────────────────────── findings table
function aiBadge(r) {
  const ai = r.ai;
  if (!ai) return {text: '—', cls: 'ai-none', tip: 'Not reviewed by the AI yet'};
  const m = {real_threat: ['⚠ threat', 'ai-real'], false_positive: ['✓ false positive', 'ai-fp'],
             uncertain: ['? uncertain', 'ai-uncertain'], error: ['⚠ error', 'ai-error']};
  const t = m[ai.status] || ['🤖 ?', 'ai-uncertain'];
  return {text: t[0], cls: t[1], tip: ai.comment || ''};
}
function rowHtml(r) {
  const bd = aiBadge(r);
  return '<tr data-id="' + Number(r.id) + '"' + (S.sel.has(r.id) ? ' class="sel"' : '') + '>' +
    '<td class="chk"><input type="checkbox" data-chk="' + Number(r.id) + '" tabindex="-1" aria-label="Select row"' + (S.sel.has(r.id) ? ' checked' : '') + '></td>' +
    '<td><span class="lv ' + esc(r.level) + '">' + esc(r.level) + '</span></td>' +
    '<td class="num">' + esc(r.score) + '</td>' +
    '<td title="' + esc(r.file) + '">' + esc(r.file) + '</td>' +
    '<td class="num">' + esc(r.line) + '</td>' +
    '<td class="num">' + esc(r.size) + '</td>' +
    '<td>' + esc(r.date) + '</td>' +
    '<td>' + esc(r.delete) + '</td>' +
    '<td title="' + esc(r.signature) + '">' + esc(r.signature) + '</td>' +
    '<td class="' + bd.cls + '" title="' + esc(bd.tip) + '"><span class="ai-badge">' + esc(bd.text) + '</span></td></tr>';
}
function fillChips(counts) {
  const set = (id, v) => { const el = $(id); if (el) el.textContent = v == null ? '' : v; };
  set('c-ALL', counts.ALL); set('c-HIGH', counts.HIGH); set('c-MEDIUM', counts.MEDIUM); set('c-LOW', counts.LOW);
}
function renderRows(data) {
  S.rows = data.rows; S.order = data.rows.map((r) => r.id);
  const keep = new Set(S.order); S.sel.forEach((id) => { if (!keep.has(id)) S.sel.delete(id); });
  const tb = $('tbody');
  if (!data.rows.length) {
    tb.innerHTML = '<tr class="empty-row"><td colspan="10">No findings match the current filter.</td></tr>';
  } else {
    tb.innerHTML = data.rows.map(rowHtml).join('');
  }
  let t = 'Showing ' + data.shown + ' of ' + data.total;
  if (data.matched > data.shown) t += ' (table limit ' + data.limit + ', narrow the filter or open the CSV)';
  if (data.hidden_done) t += ' · hidden as handled: ' + data.hidden_done;
  if (S.sel.size) t += ' · ' + S.sel.size + ' selected';
  $('count').textContent = t;
  fillChips(data.counts || {});
  document.querySelectorAll('#thead th').forEach((th) => {
    const a = th.querySelector('.arr'); if (a) a.remove();
    if (th.dataset.col === S.sort) { const s = document.createElement('span'); s.className = 'arr'; s.textContent = S.desc ? ' ▼' : ' ▲'; th.appendChild(s); }
  });
  showDetails();
}
async function refreshFindings() {
  const lvl = S.level === 'ALL' ? 'All' : S.level;
  const p = new URLSearchParams({level: lvl, q: $('fQuery').value, ai: $('fAi').value, sort: S.sort, desc: S.desc ? '1' : '0'});
  try { const d = await api('/api/findings?' + p.toString()); S.ver = d.version; renderRows(d); renderAiCluster(); } catch (e) { showErr(e); }
}
function selectAll() {
  S.order.forEach((id) => S.sel.add(id));
  paintSel(); showDetails();
}
function paintSel() {
  document.querySelectorAll('#tbody tr').forEach((tr) => tr.classList.toggle('sel', S.sel.has(Number(tr.dataset.id))));
  document.querySelectorAll('#tbody input[data-chk]').forEach((cb) => { cb.checked = S.sel.has(Number(cb.dataset.chk)); });
  const ra = $('rowSelAll');
  if (ra) { const nn = S.order.length; const kk = S.order.filter((id) => S.sel.has(id)).length; ra.checked = nn > 0 && kk === nn; ra.indeterminate = kk > 0 && kk < nn; }
  const btn = $('selectAllBtn');
  if (btn) btn.innerHTML = '<svg class="ico-blue" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><span>' + ((S.order.length && S.sel.size >= S.order.length) ? 'Clear selection' : 'Select all') + '</span>';
}
function selectRow(id, ev) {
  if (ev && ev.shiftKey && S.last != null && S.order.includes(S.last)) {
    const a = S.order.indexOf(S.last), b = S.order.indexOf(id); const lo = Math.min(a, b), hi = Math.max(a, b);
    if (!(ev.ctrlKey || ev.metaKey)) S.sel.clear(); for (let i = lo; i <= hi; i++) S.sel.add(S.order[i]);
  } else if (ev && (ev.ctrlKey || ev.metaKey)) { if (S.sel.has(id)) S.sel.delete(id); else S.sel.add(id); S.last = id; }
  else { S.sel.clear(); S.sel.add(id); S.last = id; }
  paintSel(); showDetails();
}
const AI_BOX_CLS = {'ai-real': ' v-real', 'ai-fp': ' v-fp', 'ai-uncertain': ' v-uncertain', 'ai-error': ' v-error', 'ai-none': ''};
function showDetails() {
  clearTimeout(S.pvTimer);
  S.pvTimer = setTimeout(async () => {
    const el = $('det'); const ids = [...S.sel];
    const qp = document.getElementById('detQuickPath');
    if (!ids.length) {
      el.innerHTML = '<span class="empty">Select a row to see details.</span>';
      if (qp) qp.textContent = '';
      return;
    }
    const files = new Set(S.rows.filter((r) => S.sel.has(r.id)).map((r) => r.file));
    let note = '';
    if (ids.length > 1) note = '<div class="multi">Rows selected: ' + ids.length + ' · files: ' + files.size + '</div>';
    try {
      const d = await api('/api/finding?id=' + ids[ids.length - 1]);
      const bd = aiBadge({ai: d.ai});
      const snippet = d.snippet || '';
      const aiText = d.ai ? (d.ai.comment || 'No comment.') : 'Not reviewed by the AI yet.';
      el.innerHTML = note +
        '<div class="detWrap">' +
          '<div class="detMeta">' +
            '<div class="detPath"><div class="detPathTop"><span class="detLabel">Full file path</span><div class="detPathVal">' + esc(d.file).replace(/[\\/]/g, function (m) { return m + '<wbr>'; }) + '</div></div><button type="button" class="detCopyBtn" data-det="copyPath" title="Copy full path">Copy</button></div>' +
            '<div class="detGrid">' +
              '<div class="detCard"><span class="detLabel">SHA-256 digest</span><div class="detVal">' + esc(d.sha256 || '—') + '</div></div>' +
              '<div class="detCard"><span class="detLabel">Signature rule</span><div class="detVal detSig">' + esc(d.signature || '—') + '</div></div>' +
            '</div>' +
            '<div class="detAiBox' + (AI_BOX_CLS[bd.cls] || '') + '"><div class="detAiHead"><span class="detLabel">AI heuristic verdict</span><span class="ai-badge ' + bd.cls + '">' + esc(bd.text) + '</span></div><p class="detAiReason">' + esc(aiText) + '</p></div>' +
          '</div>' +
          '<div class="detCode"><div class="detCodeHead"><span>Source snippet</span><span class="detCodeFile">' + esc(d.file || '') + '</span></div><pre class="detCodeBody">' + (snippet ? esc(snippet) : 'No snippet stored.') + '</pre></div>' +
        '</div>';
      if (qp) qp.textContent = d.file || '';
    } catch (e) { /* row may have left the report */ }
  }, 80);
}

// ────────────────────────────────────────────── actions on files
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

// ────────────────────────────────────────────── state polling
function renderAiCluster() {
  // The run-bar AI cluster: threats/errors counter, candidates count, FP button.
  // The counter is shown only after a review completes (and not while a job runs).
  const stats = S.aiStats;
  const job = S.job;
  const aiOn = !!S.settings.ai_enabled;
  const chip = $('aiStats');
  const real = stats ? stats.real_threat : 0;
  const errors = stats ? stats.error : 0;
  const fp = stats ? stats.false_positive : 0;
  const cands = stats ? stats.candidates : 0;
  const showChip = !!(stats && stats.reviewed > 0 && !job && aiOn);
  chip.hidden = !showChip;
  if (showChip) chip.innerHTML = '🤖 threats: <b>' + real + '</b> &middot; &#9888; errors: <b>' + errors + '</b>';
  const showCount = aiOn && stats && stats.reviewed > 0;
  $('candBtn').innerHTML = '<svg class="cbtn-ico" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg><span>Candidates</span>' + (showCount && cands > 0 ? '<span class="cbadge">' + cands + '</span>' : '');
  $('candBtn').disabled = !!job || !aiOn;
  $('fpBtn').innerHTML = '<span>🧹</span><span>Remove false positives</span>' + (showCount && fp > 0 ? '<span class="cbadge">' + fp + '</span>' : '');
  $('fpBtn').disabled = !!job || !aiOn || fp === 0;
  $('fpBtn').title = fp > 0 && !job && aiOn
    ? 'Remove the ' + fp + ' false positive(s) the AI flagged - they are hidden from the list (they stay in the CSV)'
    : 'No false positives to remove';
}
function setBusy(job) {
  S.job = job;
  $('startBtn').disabled = !!job;
  $('stopBtn').disabled = !job || !!(job && job.stopping);
  $('cleanBtn').disabled = !!job;
  const aiOn = !!S.settings.ai_enabled;
  $('aiBtn').disabled = !!job || !aiOn;
  $('aiHint').textContent = aiOn ? '' : 'Enable AI review in the Settings tab first.';
  const prog = $('prog');
  if (job) {
    prog.classList.toggle('indet', !!job.indeterminate);
    $('progFill').style.width = job.indeterminate ? '' : job.percent + '%';
    if (!job.indeterminate) prog.setAttribute('aria-valuenow', job.percent);
    $('progText').textContent = job.text;
  } else {
    prog.classList.remove('indet');
    $('progFill').style.width = '0';
  }
}
function appendLog(lines) {
  if (!lines.length) return; const el = $('log'); const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  el.textContent += lines.join('');
  if (el.textContent.length > 600000) el.textContent = el.textContent.slice(-400000);
  if (atBottom) el.scrollTop = el.scrollHeight;
}
function showBusy(text) {
  const ov = document.createElement('div'); ov.className = 'overlay';
  const dlg = document.createElement('div'); dlg.className = 'dlg';
  const h = document.createElement('h3'); h.textContent = 'Signature library';
  const body = document.createElement('div'); body.className = 'body'; body.textContent = text;
  const btns = document.createElement('div'); btns.className = 'btns';
  const b = document.createElement('button'); b.textContent = 'Cancel';
  btns.appendChild(b); dlg.append(h, body, btns); ov.appendChild(dlg); document.body.appendChild(ov);
  return {close: () => ov.remove(), onCancel: (fn) => b.addEventListener('click', () => { fn(); })};
}

async function onNotice(n) {
  try {
    if (n.kind === 'info' && n.title === 'AI review') {
      await aiReviewFlow(n);
      return;
    }
    if (n.kind === 'offer_csv') { if (await confirmDlg(n.title, n.text, 'Open CSV')) await api('/api/report/open', {kind: 'csv'}); }
    else if (n.kind === 'clean_plan') {
      const go = await confirmDlg(n.title, n.text, n.permanent ? 'Delete permanently' : 'Move to quarantine', true);
      if (go) await api('/api/clean/apply', {}); else await api('/api/clean/cancel', {});
    } else await msgDlg(n.title, n.text, n.kind);
  } catch (e) { showErr(e); }
}

// ────────────────────────────────────────────── AI review post-flow
async function aiReviewFlow(n) {
  await msgDlg(n.title, n.text, n.kind);          // the review summary (existing behaviour)
  // (a) false positives -> offer to remove them from the threat list (they stay in the CSV)
  if (n.ai_fp > 0) {
    const yes = await confirmDlg('Remove false positives from the threat list?',
      'The AI review marked ' + n.ai_fp + ' file(s) as false positive.\n\n' +
      'Remove them from the threat list?\nThe rows stay in the CSV - they are only hidden from the list.',
      'Remove from list', false);
    if (yes) {
      try {
        const r = await api('/api/ai/review/remove_false_positives', {});
        toast(r.text, 'ok');
        await refreshFindings();
      } catch (e) { showErr(e); }
    }
  }
  // (b) real threats -> offer an AI-prepared signature per file (never applied without confirmation)
  if (n.ai_real > 0 && !n.ai_stopped) {
    await aiSignaturesFlow();
  }
}

async function aiSignaturesFlow() {
  const ctrl = new AbortController();
  const busy = showBusy('The AI is preparing signatures from the real threats...\nThis can take a moment.');
  let cancelled = false;
  busy.onCancel(() => { cancelled = true; ctrl.abort(); });
  let d = null;
  try {
    d = await api('/api/ai/signatures/prepare', {}, {signal: ctrl.signal});
  } catch (e) {
    busy.close();
    if (!cancelled && !(e && e.name === 'AbortError')) showErr(e);
    return;
  }
  busy.close();
  if (cancelled) return;
  if (!d.proposals || !d.proposals.length) {
    const problems = (d.problems || []).slice(0, 6);
    if (problems.length) {
      const lines = ['The AI did not prepare any signatures:', ''];
      problems.forEach((p) => lines.push('  • ' + (p.file || '') + ': ' + (p.reason || '')));
      await msgDlg('Signature library', lines.join('\n'), 'warn');
    }
    return;
  }
  const lines = ['The AI prepared ' + d.proposals.length + ' signature(s) from the real threats:', ''];
  d.proposals.forEach((p, i) => {
    lines.push('#' + (i + 1) + '  ' + p.label + '  [' + p.severity + ']  kinds: ' + p.kinds);
    lines.push('   pattern: ' + p.pattern);
    if (p.weight) lines.push('   weight: ' + p.weight);
    lines.push('   file: ' + p.file + (p.line ? '  (line ' + p.line + ')' : ''));
    if (p.reason) lines.push('   reason: ' + p.reason);
    lines.push('');
  });
  lines.push('Nothing is written automatically: the library is a separate JSON file that the');
  lines.push('scanner reads on the next scan (--user-signatures). Review the proposals.');
  const ok = await modal({title: 'Add AI-prepared signatures to the library?', text: lines.join('\n'), wide: true, buttons: [
    {text: 'Cancel', value: false},
    {text: 'Add to library', value: true, cls: 'primary'}]});
  if (!ok) return;
  try {
    const r = await api('/api/ai/signatures/apply', {signatures: d.proposals});
    let text = r.text;
    if (r.problems && r.problems.length) {
      text += '\nSkipped: ' + r.problems.map((p) => (p.label || '(no label)') + ' - ' + p.reason).join('; ');
    }
    toast(text, 'ok');
  } catch (e) { showErr(e); }
}
function paintEngines(st) {
  const list = st.engines || [], base = st.baseline || {}, sg = st.signatures || {};
  const sig = JSON.stringify([list, base, sg, !!S.job]);
  if (sig === S.engSig) return; S.engSig = sig;
  let html;
  if (!list.length) {
    html = '<span class="empty">No engines detected on the site. Choose the Site folder on the Settings tab.</span>';
  } else {
    let rows = '';
    list.forEach((e) => {
      let org;
      if (e.name !== 'Joomla') org = '<span class="engNo" title="third-party originals are not downloaded by the app">not downloaded</span>';
      else if (base.dir && base.match) org = '<span class="engYes">\u2713 loaded</span><div class="engDir">' + esc(base.dir) + '</div>';
      else if (base.dir) org = '<span class="engBad">\u2717 folder holds ' + esc(base.version || 'an unrecognized Joomla version') + '</span><div class="engDir">' + esc(base.dir) + '</div>';
      else org = '<span class="engNo">not downloaded</span>';
      rows += '<tr><td class="engName">' + esc(e.name) + '</td><td class="engVer">' + esc(e.version) + '</td><td>' + org + '</td></tr>';
    });
    const bar = '<div class="engBar"><span>The originals below are downloaded freely from the publishers; the app can fetch the Joomla core.</span>'
      + (base.joomla ? '<button class="btn" id="engFetch">Fetch Joomla ' + esc(base.joomla) + ' baseline</button>' : '') + '</div>';
    html = bar + '<table class="engTbl"><tr><th>Engine</th><th>Version</th><th>Original</th></tr>' + rows + '</table>';
  }
  html += signaturesCard(sg);
  $('eng').innerHTML = html;
  const fb = $('engFetch');
  if (fb) fb.addEventListener('click', () => fetchBaseline(false));
  const ub = $('sigUpdate');
  if (ub) ub.addEventListener('click', updateSignatures);
  const rb = $('sigRollback');
  if (rb) rb.addEventListener('click', rollbackSignatures);
}
function signaturesCard(sg) {
  if (!sg.tool) return '<div class="engBar" style="margin-top:16px"><b>Signature updates</b></div>'
    + '<span class="empty">updater.py was not found next to the scanner: signature updates are unavailable.</span>';
  let state;
  if (!sg.present) state = '<span class="engNo">No rule package is installed.</span>';
  else {
    state = 'Active package: <b>' + esc(sg.active || '?') + '</b> \u00b7 rules: ' + (sg.rules == null ? '?' : sg.rules)
      + (sg.updated ? ' \u00b7 updated ' + esc(String(sg.updated).replace('T', ' ').replace('Z', '')) : '')
      + ' ' + (sg.verified ? '<span class="engYes">\u2713 verified</span>' : '<span class="engBad">\u26a0 not verified</span>');
  }
  let failed = '';
  if (sg.failed && sg.failed.length) {
    failed = '<div class="engBad">The last update failed for: ' + esc(sg.failed.map((f) => f.source).join(', ')) + '</div>';
  }
  const busy = !!S.job;
  return '<div class="engBar" style="margin-top:16px"><b>Signature updates (YARA rules)</b>'
    + '<span class="engDir">' + esc(sg.data_dir || '') + '</span></div>'
    + '<div>' + state + '</div>' + failed
    + '<div class="engBar"><button class="btn" id="sigUpdate"' + (busy ? ' disabled' : '') + '>Update signatures</button>'
    + '<button class="btn" id="sigRollback"' + ((busy || (sg.releases || []).length < 2) ? ' disabled' : '')
    + '>Roll back to the previous package</button></div>';
}
async function updateSignatures() {
  const yes = await confirmDlg('Download the signature update?',
    'The updater connects only to the hosts pinned in its own sources.json (https only). It downloads one archive, '
    + 'checks its hashes, unpacks it safely and compiles every rule file BEFORE the new package becomes active. '
    + 'If anything fails, the previously active package stays in place. Nothing is ever executed.',
    'Download');
  if (!yes) return;
  try {
    await api('/api/signatures/update', {});
    toast('The signature update started - progress in the Log tab.', 'ok');
  } catch (e) { showErr(e); }
}
async function rollbackSignatures() {
  const yes = await confirmDlg('Roll the signatures back?',
    'The previously installed rule package becomes the active one again. Nothing is deleted.', 'Roll back');
  if (!yes) return;
  try {
    await api('/api/signatures/rollback', {});
    toast('Rolling the signatures back - progress in the Log tab.', 'ok');
  } catch (e) { showErr(e); }
}
async function startScan(noBaseline) {
  await api('/api/scan/start', noBaseline ? {settings: readSettings(), no_baseline: true} : {settings: readSettings()});
  $('log').textContent = ''; S.logNext = 0; S.sel.clear(); toast('Scan started' + (noBaseline ? ' (no baseline)' : ''), 'ok');
}
async function poll() {
  let delay = 1500;
  try {
    const st = await api('/api/state?since=' + S.logNext);
    if (!S.online) { S.online = true; $('conn').textContent = 'connected'; $('conn').className = 'badge'; }
    if (S.boot !== null && S.boot !== st.boot) { S.logNext = 0; $('log').textContent = ''; await saveFromServer(); }
    S.boot = st.boot;
    if (st.log.from > S.logNext && S.logNext !== 0) $('log').textContent += '… (older lines were dropped)\n';
    appendLog(st.log.lines); S.logNext = st.log.next;
    const prevJob = S.job;
    setBusy(st.job);
    if (prevJob && prevJob.kind === 'baseline' && !st.job) await saveFromServer();
    S.aiStats = st.ai_stats || null;
    renderAiCluster();
    if (!st.job) $('progText').textContent = st.idle_text || '';
    $('status').textContent = st.status;
    $('engines').textContent = (st.engines || []).map((e) => e.name + ' ' + e.version).join('  \u00b7  ');
    paintEngines(st);
    if (S.autoScanBaseline && !st.job && (st.status || '').indexOf('Baseline ready') === 0 && st.status !== S.lastStatus) {
      S.autoScanBaseline = false;               // the fetch may be over before a poll ever saw the job: key off the status
      await saveFromServer();
      try { await startScan(false); } catch (e) { showErr(e); }
    }
    S.lastStatus = st.status;
    ['csv', 'xlsx', 'json'].forEach((k) => {
      const exists = st.reports[k].exists;
      const b = document.querySelector('[data-rep="' + k + '"]'); if (b) b.disabled = !exists;
      const l = document.querySelector('[data-dl="' + k + '"]'); if (l) l.setAttribute('aria-disabled', exists ? 'false' : 'true');
    });
    if (st.findings_version !== S.ver) await refreshFindings();
    if (S.noticeSeq === null) S.noticeSeq = st.notice ? st.notice.seq : 0;       // do not replay old dialogs after a reload
    else if (st.notice && st.notice.seq !== S.noticeSeq) { S.noticeSeq = st.notice.seq; onNotice(st.notice); }
    delay = st.job ? 500 : 1500;
  } catch (e) {
    if (S.online) { S.online = false; $('conn').textContent = 'server not reachable'; $('conn').className = 'badge off'; }
    delay = 2000;
  }
  setTimeout(poll, document.hidden ? Math.max(delay, 2500) : delay);
}

// ────────────────────────────────────────────── AI review
async function showCandidates() {
  try {
    const d = await api('/api/ai/candidates', {});
    const lines = ['Files with real threats: ' + d.files, ''];
    d.candidates.forEach((c, i) => {
      lines.push('#' + (i + 1) + '  ' + c.signature + '  (score ' + c.score + ', ' + c.count + ' finding(s), ' + c.files.length + ' file(s))');
      if (c.severity) lines.push('   severity: ' + c.severity);
      c.files.slice(0, 5).forEach((f) => lines.push('   - ' + f));
      if (c.examples.length) {
        lines.push('   examples:');
        c.examples.slice(0, 2).forEach((ex) => lines.push('     ' + ex.file + ':' + ex.line + '  ' + String(ex.snippet || '').slice(0, 160)));
      }
      lines.push('');
    });
    lines.push('These are candidates for the signature library - review them and add only the confirmed ones to the scanner (the scanner is not modified automatically).');
    const text = lines.join('\n');
    await modal({title: 'Candidates for the signature library', text, wide: true, buttons: [
      {text: 'Copy', value: () => { try { navigator.clipboard.writeText(text); } catch (e) {} return true; }},
      {text: 'Close', value: false}]});
  } catch (e) { showErr(e); }
}

// ────────────────────────────────────────────── tabs / panel / menu
function showTab(t) {
  S.tab = t; location.hash = t;
  document.querySelectorAll('.tab').forEach((el) => el.classList.toggle('active', el.id === 'tab-' + t));
  document.querySelectorAll('.toptab').forEach((b) => b.setAttribute('aria-selected', b.dataset.tab === t ? 'true' : 'false'));
}
function showPanel(p) {
  document.querySelectorAll('[data-p]').forEach((x) => x.setAttribute('aria-selected', x.dataset.p === p ? 'true' : 'false'));
  $('det').hidden = p !== 'det';
  $('log').hidden = p !== 'log';
  $('eng').hidden = p !== 'eng';
  $('logCopy').hidden = p !== 'log';
  $('logClear').hidden = p !== 'log';
  $('bottom').classList.remove('collapsed');
}
function closeReports() { const m = $('repMenu'); m.classList.remove('open'); $('repBtn').setAttribute('aria-expanded', 'false'); }
function showCtx(x, y) {
  const m = $('ctx');
  m.innerHTML = [['reveal', '📁 Show file'], ['copyPath', '📋 Copy path'], ['copySha', '📋 Copy SHA-256'], ['whitelist', '✅ To whitelist (false positive)'], ['-'],
    ['quarantine', '📦 Move to quarantine'], ['delete', '🗑 Delete from disk']].map((a) => a[0] === '-' ? '<hr>' : '<div data-a="' + a[0] + '">' + esc(a[1]) + '</div>').join('');
  m.style.display = 'block'; m.style.left = Math.max(0, Math.min(x, innerWidth - 250)) + 'px'; m.style.top = Math.max(0, Math.min(y, innerHeight - 230)) + 'px';
}
function onKey(e) {
  const t = document.activeElement && document.activeElement.tagName;
  const typing = t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT';
  if (e.key === '/' && !typing) { e.preventDefault(); $('fQuery').focus(); $('fQuery').select(); return; }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a' && !typing) { e.preventDefault(); selectAll(); return; }
  if (e.key === 'Escape') {
    closeReports(); $('ctx').style.display = 'none';
    if (!typing) { S.sel.clear(); paintSel(); showDetails(); }
    return;
  }
  if (e.key === 'Delete' && !typing) { e.preventDefault(); fileAction('delete'); return; }
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    if (typing) return;
    e.preventDefault(); if (!S.order.length) return;
    let i = S.last != null ? S.order.indexOf(S.last) : -1;
    i = e.key === 'ArrowDown' ? Math.min(i + 1, S.order.length - 1) : Math.max(i - 1, 0);
    if (i < 0 || i >= S.order.length) i = 0;
    selectRow(S.order[i], e.shiftKey ? {shiftKey: true} : null);
    const tr = document.querySelector('#tbody tr[data-id="' + S.order[i] + '"]'); if (tr && tr.scrollIntoView) tr.scrollIntoView({block: 'nearest'});
  }
}
async function init() {
  buildSettings();
  $('det').addEventListener('click', (e) => { const b = e.target.closest('[data-det]'); if (b && b.dataset.det === 'copyPath') fileAction('copyPath'); });
  paintTheme(effectiveTheme());
  document.getElementById('themeLight').addEventListener('click', () => setTheme('light'));
  document.getElementById('themeDark').addEventListener('click', () => setTheme('dark'));
  $('selfUrl').textContent = location.origin + '/';
  document.querySelectorAll('.toptab').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
  $('goRun').addEventListener('click', async () => { await saveSettings(); showTab('run'); });
  $('startBtn').addEventListener('click', async () => {
    try {
      await saveSettings();
      let pf = null;
      try { pf = await api('/api/preflight', {}); } catch (e) { pf = null; }
      if (pf && (pf.mode === 'mismatch' || pf.mode === 'no_baseline')) {
        const jv = pf.joomla || '?';
        const bv = pf.baseline && pf.baseline.version;
        const head = pf.mode === 'mismatch'
          ? 'The site runs Joomla ' + jv + ', but the Clean Joomla folder holds ' + (bv ? 'Joomla ' + bv : 'an unrecognized Joomla version') + '.\n\nScanning with a baseline of the wrong version hides real findings and invents false ones.'
          : 'No Clean Joomla folder is set, so core files cannot be compared with originals - heuristics alone will report more noise.';
        const m = await modal({ title: pf.mode === 'mismatch' ? 'Baseline version mismatch' : 'Scan without originals?', text: head, buttons: [
          { text: 'Cancel', value: 'cancel' },
          { text: 'Scan without baseline', value: 'nobase' },
          { text: 'Fetch Joomla ' + jv + ' first', value: 'fetch', cls: 'primary' }
        ] });
        if (!m || m === 'cancel') return;
        if (m === 'fetch') { await fetchBaseline(true); return; }
        await startScan(true);
      } else {
        await startScan(false);
      }
    }
    catch (e) { msgDlg('Parameters not filled in', e.message, 'error'); }
  });
  $('stopBtn').addEventListener('click', () => api('/api/job/stop', {}).catch(showErr));
  $('cleanBtn').addEventListener('click', async () => { try { await saveSettings(); await api('/api/clean/plan', {settings: readSettings()}); } catch (e) { msgDlg('Mass cleanup', e.message, 'error'); } });
  $('selectAllBtn').addEventListener('click', () => {
    if (S.order.length && S.sel.size >= S.order.length) { S.sel.clear(); paintSel(); showDetails(); }
    else selectAll();
  });
  document.querySelectorAll('[data-rep]').forEach((b) => b.addEventListener('click', () => { closeReports(); api('/api/report/open', {kind: b.dataset.rep}).catch(showErr); }));
  $('repFolder').addEventListener('click', () => { closeReports(); api('/api/report/folder', {}).catch(showErr); });
  $('repBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    const m = $('repMenu'); const open = m.classList.toggle('open');
    $('repBtn').setAttribute('aria-expanded', open ? 'true' : 'false');
  });
  document.querySelectorAll('[data-dl]').forEach((a) => a.addEventListener('click', (e) => {
    if (a.getAttribute('aria-disabled') === 'true') { e.preventDefault(); return; } closeReports();
  }));
  document.querySelectorAll('[data-act]').forEach((b) => b.addEventListener('click', () => fileAction(b.dataset.act)));
  document.querySelectorAll('.chip').forEach((c) => c.addEventListener('click', () => {
    S.level = c.dataset.l;
    document.querySelectorAll('.chip').forEach((x) => x.setAttribute('aria-pressed', x === c ? 'true' : 'false'));
    refreshFindings();
  }));
  $('fQuery').addEventListener('input', () => { clearTimeout(S.fTimer); S.fTimer = setTimeout(refreshFindings, 250); });
  $('fAi').addEventListener('change', refreshFindings);
  $('fReset').addEventListener('click', () => {
    $('fQuery').value = ''; S.level = 'ALL'; $('fAi').value = 'all';
    document.querySelectorAll('.chip').forEach((x) => x.setAttribute('aria-pressed', x.dataset.l === 'ALL' ? 'true' : 'false'));
    refreshFindings();
  });
  $('aiBtn').addEventListener('click', async () => {
    try { await saveSettings(); const files = [...new Set(S.rows.filter((x) => S.sel.has(x.id)).map((x) => x.file))];
      const r = await api('/api/ai/review', files.length ? {files: files} : {});
      toast('AI review started: ' + r.files + ' file(s)' + (files.length ? ' from the selection' : ''), 'ok'); }
    catch (e) { msgDlg('AI review', e.message, 'error'); }
  });
  $('candBtn').addEventListener('click', () => showCandidates());
  $('fpBtn').addEventListener('click', async () => {
    const fp = S.aiStats ? S.aiStats.false_positive : 0;
    if (!fp) return;
    const yes = await confirmDlg('Remove false positives from the threat list?',
      'The AI review marked ' + fp + ' file(s) as false positive.\n\n' +
      'Remove them from the threat list?\nThe rows stay in the CSV - they are only hidden from the list.',
      'Remove from list', false);
    if (!yes) return;
    try {
      const r = await api('/api/ai/review/remove_false_positives', {});
      toast(r.text, 'ok');
      if (S.aiStats) {
        S.aiStats = Object.assign({}, S.aiStats, {false_positive: 0, reviewed: Math.max(0, S.aiStats.reviewed - fp)});
      }
      renderAiCluster();
      await refreshFindings();
    } catch (e) { showErr(e); }
  });
  $('thead').addEventListener('click', (e) => {
    const th = e.target.closest('th'); if (!th) return; const c = th.dataset.col; if (!c) return;
    if (S.sort === c) S.desc = !S.desc; else { S.sort = c; S.desc = (c === 'score'); } refreshFindings();
  });
  const tb = $('tbody');
  tb.addEventListener('click', (e) => { if (e.target.matches('input[data-chk]')) return; const tr = e.target.closest('tr'); if (tr) selectRow(Number(tr.dataset.id), e); });
  tb.addEventListener('change', (e) => { const cb = e.target.closest('input[data-chk]'); if (!cb) return; const id = Number(cb.dataset.chk); if (cb.checked) S.sel.add(id); else S.sel.delete(id); S.last = id; paintSel(); showDetails(); });
  const _ra = $('rowSelAll');
  if (_ra) _ra.addEventListener('change', () => { if (_ra.checked) selectAll(); else { S.sel.clear(); paintSel(); showDetails(); } });
  tb.addEventListener('dblclick', (e) => { const tr = e.target.closest('tr'); if (tr) { S.sel.clear(); S.sel.add(Number(tr.dataset.id)); paintSel(); showDetails(); fileAction('reveal'); } });
  tb.addEventListener('contextmenu', (e) => {
    const tr = e.target.closest('tr'); if (!tr) return; e.preventDefault(); const id = Number(tr.dataset.id);
    if (!S.sel.has(id)) selectRow(id, null); showCtx(e.clientX, e.clientY);
  });
  $('ctx').addEventListener('click', (e) => { const d = e.target.closest('[data-a]'); $('ctx').style.display = 'none'; if (d) fileAction(d.dataset.a); });
  document.addEventListener('click', (e) => { if (!e.target.closest('#ctx')) $('ctx').style.display = 'none'; if (!e.target.closest('#repMenu')) closeReports(); });
  document.addEventListener('scroll', () => { $('ctx').style.display = 'none'; }, true);
  document.addEventListener('keydown', onKey);
  // bottom panel
  document.querySelectorAll('[data-p]').forEach((t) => t.addEventListener('click', () => showPanel(t.dataset.p)));
  $('logCopy').addEventListener('click', async () => { await copyText($('log').textContent); toast('Log copied', 'ok'); });
  $('logClear').addEventListener('click', () => { $('log').textContent = ''; });
  $('foldBtn').addEventListener('click', () => $('bottom').classList.toggle('collapsed'));
  const gut = $('gut'), bottom = $('bottom');
  const wideMQ = matchMedia('(min-width: 1100px)');
  const clearInline= () => { if (wideMQ.matches) { bottom.style.height = ''; bottom.style.width = ''; } };
  if (wideMQ.addEventListener) wideMQ.addEventListener('change', clearInline);
  gut.addEventListener('pointerdown', (e) => {
    e.preventDefault(); gut.classList.add('drag');
    const x0 = e.clientX, y0 = e.clientY, w0 = bottom.offsetWidth, h0 = bottom.offsetHeight;
    const wide = wideMQ.matches;
    gut.setPointerCapture(e.pointerId);
    const move = (m) => {
      if (wide) {
        bottom.style.width = Math.max(220, Math.min(Math.round(innerWidth * 0.55), w0 - (m.clientX - x0))) + 'px';
        bottom.style.height = '';
      } else {
        bottom.style.height = Math.max(60, Math.min(Math.round(innerHeight * 0.7), h0 + (y0 - m.clientY))) + 'px';
      }
      bottom.classList.remove('collapsed');
    };
    const up = () => { gut.classList.remove('drag'); gut.removeEventListener('pointermove', move); gut.removeEventListener('pointerup', up); gut.removeEventListener('pointercancel', up); };
    gut.addEventListener('pointermove', move);
    gut.addEventListener('pointerup', up);
    gut.addEventListener('pointercancel', up);
  });
  gut.addEventListener('dblclick', () => { if (!wideMQ.matches) bottom.classList.toggle('collapsed'); });
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
window.__sbg = {esc, rowHtml, renderRows, selectRow, fileAction, S, init, onNotice, browse, showDetails};
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


def _pick_port(start, span=PORT_FALLBACK_SPAN):
    """Try to bind the GUI server to ports `start` .. `start + span - 1`, in order.

    Returns (server, port, error). `server` is the bound Server object (the
    caller owns it). `error` is the OSError from the most recent attempt, kept
    so the caller can tell "excluded by the operating system" (EACCES) apart
    from "busy port" (EADDRINUSE). When every port in the range refuses to
    bind, server is None.
    """
    last_error = None
    for p in range(start, min(start + span, 65536)):
        try:
            return Server(("127.0.0.1", p), Handler), p, None
        except OSError as e:
            last_error = e
    return None, None, last_error


def _bind_failure_lines(start, span, error):
    """The printed lines used when every port in the range refused to bind."""
    lines = ["Could not bind a port in the range %d-%d." % (start, min(start + span, 65536) - 1)]
    if getattr(error, "errno", None) == errno.EACCES:
        if os.name == "nt":
            lines.append("The system refuses to use those ports (access denied). On Windows this is the")
            lines.append("excluded port range. List it with:")
            lines.append("  netsh int ipv4 show excludedportrange protocol=tcp")
            lines.append("Pick a range outside it, e.g.:  --port 8800")
        else:
            lines.append("The system refuses to use those ports (access denied).")
            lines.append("If they are below 1024 they need elevated privileges - pick a port at or above")
            lines.append("1024, e.g.:  --port 9000")
    else:
        lines.append("The ports in that range refused to bind: %s" % (error if error is not None else "unknown"))
        lines.append("Pick another port, e.g.:  --port 9000")
    return lines


def _ver_tuple(v):
    t = tuple(int(x) for x in str(v).split(".")[:3])
    return t + (0,) * (3 - len(t))


def self_test():
    """Doctor: does the settings file parse, is the scanner there and new enough,
    is the cleaner next to it, do the path settings check out? No server, no browser.
    Exit 0 iff all checks pass."""
    print("scan_backdoors_gui %s | self-test (doctor)" % VERSION)
    settings = dict(DEFAULTS)
    data, err = load_config()
    if err:
        print("  [FAIL] settings file: %s" % err)
        ok = 0
    else:
        if data:
            for k, v in data.items():
                if k in DEFAULTS and k not in BOOL_KEYS and isinstance(v, (str, int, float)):
                    settings[k] = str(v)
                elif k in DEFAULTS and k in BOOL_KEYS:
                    settings[k] = bool(v)
            print("  [PASS] settings file: %d entries read" % len(data))
        else:
            print("  [PASS] settings file: not found, the defaults are used")
        ok = 1
    scanner = Path(str(settings.get("scanner_path") or "")).expanduser()
    if scanner.is_file():
        ok += 1
        print("  [PASS] scanner_path: %s" % scanner)
        try:
            proc = subprocess.run([python_exe(), str(scanner), "--version"],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = (proc.stdout or b"").decode("utf-8", "replace").strip()
            ver = out.rsplit(" ", 1)[-1] if proc.returncode == 0 else ""
            if proc.returncode == 0 and _ver_tuple(ver) >= _ver_tuple(MIN_SCANNER):
                ok += 1
                print("  [PASS] scanner version: %s (minimum %s)" % (ver, MIN_SCANNER))
            else:
                print("  [FAIL] scanner version: %r (minimum %s)" % (ver, MIN_SCANNER))
        except Exception as exc:
            print("  [FAIL] scanner version: could not run --version: %s" % exc)
    else:
        print("  [FAIL] scanner_path: '%s' is not a file" % settings.get("scanner_path"))
    cleaner = scanner.parent / "clean_malware.py"
    if cleaner.is_file():
        ok += 1
        print("  [PASS] clean_malware.py: next to the scanner")
    else:
        print("  [FAIL] clean_malware.py: not found next to the scanner (mass cleanup will not work)")
    for key, _kind, _req in PATH_FIELDS:
        raw = str(settings.get(key) or "").strip()
        if not raw:
            print("  [PASS] %s: not set%s" % (key, "" if key == "scanner_path" else " (optional)"))
            ok += 1
            continue
        errs = [e for f, _v, e in validate_paths(settings) if f == key]
        if errs:
            print("  [FAIL] %s: '%s' %s" % (key, raw, errs[0]))
        else:
            print("  [PASS] %s: %s" % (key, raw))
            ok += 1
    total = 4 + len(PATH_FIELDS)
    print("self-test: %d of %d checks passed" % (ok, total))
    return 0 if ok == total else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="Browser front end for scan_backdoors.py, v" + VERSION)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="port on 127.0.0.1 (default %d; keep it fixed to use a bookmark)" % DEFAULT_PORT)
    ap.add_argument("--no-browser", action="store_true", help="do not open the browser")
    ap.add_argument("--self-test", action="store_true",
                    help="check the settings file, the scanner and the save paths, then exit (no server, no browser)")
    ap.add_argument("--version", action="version", version=APP_ID + " " + VERSION)
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:
            pass

    if not (1 <= args.port <= 65535):
        print("Invalid port %d (expected 1-65535)." % args.port)
        return 2

    if ping(args.port):
        url = "http://127.0.0.1:%d/" % args.port
        print("Scan Backdoors GUI is already running: %s" % url)
        if not args.no_browser:
            webbrowser.open(url)
        return 0

    server, port, bind_error = _pick_port(args.port)
    if server is None:
        for line in _bind_failure_lines(args.port, PORT_FALLBACK_SPAN, bind_error):
            print(line)
        return 1
    app = App(port)
    app.shutdown_cb = server.shutdown
    server.app = app
    url = "http://127.0.0.1:%d/" % port
    print("Scan Backdoors GUI %s" % VERSION)
    print("Open in your browser: %s   (bookmark it)" % url)
    if port != args.port:
        print("NOTE: port %d was not usable, using %d instead. The bookmark URL changes when the port does." % (args.port, port))
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