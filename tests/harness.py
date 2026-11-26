# -*- coding: utf-8 -*-
"""Small helpers shared by the tests: run the CLI tools, run the GUI, read reports.

Everything runs against the sources in src/ exactly the way a user does: as a
separate python process, with the same command line. No internal function of the
tools is imported, so the tests keep working when the tools are refactored - and
they also cover argument parsing, exit codes and the report files.
"""

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures_sites as fx  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "src")
DATA = os.path.join(REPO, "data")
WHITELIST = os.path.join(DATA, "whitelist-known-clean.txt")

PYTHON = sys.executable
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", PYTHONUNBUFFERED="1")

# printed when a test file never reached the tool that needed it
AV_HINT = ("a test file disappeared or could not be read - real-time protection is "
           "quarantining it. All test data (sites, reports, quarantine copies) lives "
           "under one folder: add %s to your antivirus exclusions, or set "
           "SBD_FIXTURE_ROOT to an excluded folder." % os.path.join(tempfile.gettempdir(), "sbd-fixtures"))


def workdir(prefix):
    """Throw-away directory under the fixtures root.

    Every file a test produces - sites, reports, quarantine copies - lives under the
    single stable fixtures root, so an antivirus exclusion only ever has to cover
    that one folder.
    """
    return tempfile.mkdtemp(prefix=prefix, dir=fx.fixtures_root())


def workfile(prefix, suffix):
    """Temp file under the fixtures root (same reason as workdir())."""
    return tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=fx.fixtures_root())


def tool_path(script):
    return os.path.join(SRC, script)


def run(script, args, cwd=None, timeout=600):
    """Run src/<script> with args -> CompletedProcess-like (returncode, out, err)."""
    proc = subprocess.Popen(
        [PYTHON, "-u", tool_path(script)] + [str(a) for a in args],
        cwd=cwd or SRC, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True, encoding="utf-8", errors="replace", env=ENV)
    try:
        out, err = proc.communicate(timeout=timeout) if timeout else proc.communicate()
    except Exception:
        proc.kill()
        out, err = proc.communicate()
        raise
    return _Result(proc.returncode, out or "", err or "")


class _Result(object):
    def __init__(self, returncode, out, err):
        self.returncode = returncode
        self.out = out
        self.err = err

    def lines(self):
        return [ln.rstrip() for ln in (self.out or "").splitlines()]

    def markers(self, tag):
        """Payloads of the machine-readable '@@TAG ...' lines."""
        prefix = "@@%s " % tag
        return [ln[len(prefix):].strip() for ln in self.lines() if ln.startswith(prefix)]


def scan(site, *args, **kw):
    """Run the scanner with --json and return (result, parsed report)."""
    json_path = kw.pop("json", None)
    if json_path is None:
        fd, json_path = tempfile.mkstemp(suffix=".json", prefix="sbd-report-",
                                         dir=fx.fixtures_root())
        os.close(fd)
        os.remove(json_path)        # the scanner must create it; it creates no file on a startup error
    cmd = [site, "--no-progress", "--no-csv", "--workers", kw.pop("workers", "1"), "--json", json_path]
    cmd.extend(args)
    res = run("scan_backdoors.py", cmd, **kw)
    report = read_json(json_path) if os.path.isfile(json_path) else {}
    try:
        os.remove(json_path)
    except OSError:
        pass
    return res, report


def read_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8-sig"))


def read_csv(path):
    """[{header: value}] for a report written by either tool."""
    import csv
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8-sig")
    return [dict(row) for row in csv.DictReader(raw.splitlines())]


def findings_by_path(report):
    """{'path/lower': {'verdict':.., 'signatures': [..]}} keyed by site-relative path."""
    out = {}
    for item in report.get("files", []):
        rel = (item.get("path") or "").replace("\\", "/").lower()
        out[rel] = {"verdict": item.get("verdict"),
                    "score": item.get("score"),
                    "signatures": [h.get("signature") or "" for h in item.get("hits", [])]}
    return out


def stats_of(report):
    return report.get("stats", {})


def bundle_version():
    ns = {}
    with open(os.path.join(SRC, "version.py"), encoding="utf-8") as f:
        exec(compile(f.read(), "version.py", "exec"), ns)
    return ns["VERSION"]


def bundle_min_scanner():
    ns = {}
    with open(os.path.join(SRC, "version.py"), encoding="utf-8") as f:
        exec(compile(f.read(), "version.py", "exec"), ns)
    return ns["MIN_SCANNER"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_hashes(root):
    """{relative path: sha256} for everything under root - used to prove 'nothing changed'."""
    out = {}
    for base, _dirs, files in os.walk(root):
        for n in files:
            p = os.path.join(base, n)
            out[os.path.relpath(p, root).replace(os.sep, "/")] = sha256(p)
    return out


def clean_site(name="clean"):
    """The synthetic legitimate site."""
    return fx.build(name, planted=False)


def planted_site(case, name="planted", min_present=3):
    """The synthetic infected site: (path, samples that really exist, samples that vanished).

    Antivirus may delete a sample between writing it and scanning it. Too few
    survivors is an environment problem, so the test is skipped with instructions
    instead of failing with a misleading "the detector missed it".
    """
    site = fx.build(name, planted=True)
    present, vanished = fx.wait_readables(site, list(fx.PLANTED))
    if len(present) < min_present:
        raise unittest.SkipTest(
            "only %d of %d planted samples reached the scanner. %s"
            % (len(present), len(fx.PLANTED), AV_HINT))
    if vanished:
        sys.stderr.write("NOTE: %d planted sample(s) were removed by real-time protection: %s\n"
                         % (len(vanished), ", ".join(vanished)))
    return site, present, vanished


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


class Gui(object):
    """The GUI as a subprocess on a private port with a private settings file.

    HOME/USERPROFILE are redirected into a temporary directory, so a test run can
    never read or overwrite the developer's real ~/.scan_backdoors_gui.json.
    """

    HEADER = {"Content-Type": "application/json", "X-Requested-With": "scan-backdoors-gui"}

    def __init__(self, home, port=None):
        self.home = os.path.abspath(home)
        if not os.path.isdir(self.home):
            os.makedirs(self.home)
        self.port = port or free_port()
        self.proc = None
        self.env = dict(ENV, HOME=self.home, USERPROFILE=self.home,
                        APPDATA=os.path.join(self.home, "AppData"),
                        LOCALAPPDATA=os.path.join(self.home, "AppData", "Local"))

    # -- lifecycle ---------------------------------------------------------
    def start(self, wait=40):
        self.proc = subprocess.Popen(
            [PYTHON, "-u", tool_path("scan_backdoors_gui.py"), "--no-browser", "--port", str(self.port)],
            cwd=SRC, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, encoding="utf-8", errors="replace", env=self.env)
        self._lines = []
        self._reader = threading.Thread(target=self._pump)
        self._reader.daemon = True
        self._reader.start()
        deadline = time.time() + wait
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("the GUI exited at once: %s" % (self.log() or "no output"))
            try:
                self.api("GET", "/api/ping")
                return self
            except Exception:
                time.sleep(0.25)
        raise RuntimeError("the GUI did not answer on port %d within %ds" % (self.port, wait))

    def _pump(self):
        try:
            for line in self.proc.stdout:
                self._lines.append(line.rstrip())
        except Exception:
            pass

    def log(self):
        return "\n".join(getattr(self, "_lines", []))

    def stop(self):
        if not self.proc or self.proc.poll() is not None:
            self._close_pipe()
            return
        try:
            self.api("POST", "/api/shutdown", {})
        except Exception:
            pass
        for _ in range(40):
            if self.proc.poll() is not None:
                break
            time.sleep(0.25)
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        self._close_pipe()

    def _close_pipe(self):
        try:
            if self.proc and self.proc.stdout:
                self.proc.stdout.close()
        except Exception:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False

    # -- HTTP --------------------------------------------------------------
    def api(self, method, path, body=None, raw=False, headers=None):
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen
        heads = dict(self.HEADER)
        heads.update(headers or {})
        req = Request("http://127.0.0.1:%d%s" % (self.port, path),
                      data=(json.dumps(body).encode("utf-8") if body is not None else None),
                      headers=heads, method=method)
        try:
            with urlopen(req, timeout=60) as resp:
                data = resp.read()
                return data if raw else json.loads(data.decode("utf-8"))
        except HTTPError as e:
            data = e.read()
            if raw:
                return data
            try:
                parsed = json.loads(data.decode("utf-8"))
            except ValueError:
                parsed = {"error": data.decode("utf-8", "replace")}
            parsed["_status"] = e.code
            raise ApiError(parsed)

    def settings(self):
        return self.api("GET", "/api/settings")["settings"]

    def wait_scan(self, timeout=120, expect_done=True):
        """Poll /api/state until the job is not running; return the state."""
        deadline = time.time() + timeout
        state = {}
        while time.time() < deadline:
            state = self.api("GET", "/api/state")
            status = (state.get("status") or "")
            if expect_done and ("Finished" in status or "error" in status.lower() or "stopped" in status.lower()):
                return state
            if not expect_done and status:
                return state
            time.sleep(0.3)
        raise RuntimeError("the GUI job did not finish in %ds (status=%r)" % (timeout, state.get("status")))

    def findings(self):
        data = self.api("GET", "/api/findings?since=0")
        return data.get("rows") or []


class ApiError(Exception):
    def __init__(self, payload):
        Exception.__init__(self, payload.get("error", str(payload)))
        self.payload = payload
        self.status = payload.get("_status")
