# -*- coding: utf-8 -*-
"""The GUI port fallback (black-box).

The GUI must not die because the requested port is unusable: a busy or
excluded port must trigger the fallback loop and an honest NOTE, never a
crash or a silently wrong address. An out-of-range --port is rejected up
front. The busy port is held by a plain (non-HTTP) listener so the GUI's
bind fallback has no other choice but to skip it.
"""

import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import unittest
from urllib.error import HTTPError  # noqa: F401  (imported for parity with harness)
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402


def hold_listener(port, hold):
    """Hold a plain listener on `port`; append the socket to `hold` on success."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        s.listen(1)
    except OSError:
        s.close()
        return None
    hold.append(s)
    return s


class GuiProc(object):
    """A long-running GUI subprocess with its stdout lines collected."""

    def __init__(self, home, *args):
        self.home = os.path.abspath(home)
        env = dict(h.ENV, HOME=self.home, USERPROFILE=self.home,
                   APPDATA=os.path.join(self.home, "AppData"),
                   LOCALAPPDATA=os.path.join(self.home, "AppData", "Local"))
        self.proc = subprocess.Popen(
            [h.PYTHON, "-u", h.tool_path("scan_backdoors_gui.py")] + [str(a) for a in args],
            cwd=h.SRC, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, encoding="utf-8", errors="replace", env=env)
        self.lines = []
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    @classmethod
    def run_once(cls, home, *args):
        """Start the GUI with an isolated home, wait for it to exit, return (rc, out)."""
        env = dict(h.ENV, HOME=os.path.abspath(home), USERPROFILE=os.path.abspath(home),
                   APPDATA=os.path.join(home, "AppData"),
                   LOCALAPPDATA=os.path.join(home, "AppData", "Local"))
        proc = subprocess.Popen(
            [h.PYTHON, "-u", h.tool_path("scan_backdoors_gui.py")] + [str(a) for a in args],
            cwd=h.SRC, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, encoding="utf-8", errors="replace", env=env)
        out, _ = proc.communicate(timeout=60)
        return proc.returncode, out or ""

    def _pump(self):
        try:
            for line in self.proc.stdout:
                self.lines.append(line.rstrip())
        except Exception:
            pass

    def stdout_text(self):
        return "\n".join(self.lines)

    def banner_port(self):
        for line in self.lines:
            if "Open in your browser:" in line:
                m = re.search(r"http://127\.0\.0\.1:(\d+)/", line)
                if m:
                    return int(m.group(1))
        return None

    def wait_banner(self, timeout=60):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return None
            port = self.banner_port()
            if port:
                return port
            time.sleep(0.2)
        return None

    def shutdown(self):
        port = self.banner_port()
        if port is None:
            port = self._shutdown_port_guess()
        if port:
            try:
                req = Request("http://127.0.0.1:%d/api/shutdown" % port,
                              data=b"{}", method="POST",
                              headers={"Content-Type": "application/json",
                                       "X-Requested-With": "scan-backdoors-gui"})
                urlopen(req, timeout=5)
            except Exception:
                pass
        for _ in range(40):
            if self.proc.poll() is not None:
                break
            time.sleep(0.25)
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        try:
            if self.proc and self.proc.stdout:
                self.proc.stdout.close()
        except Exception:
            pass

    def _shutdown_port_guess(self):
        for line in self.lines:
            m = re.search(r"http://127\.0\.0\.1:(\d+)/", line)
            if m:
                return int(m.group(1))
        return None


class InvalidPortTest(unittest.TestCase):
    def test_zero_port_is_rejected(self):
        res = h.run("scan_backdoors_gui.py", ["--port", "0"])
        self.assertEqual(res.returncode, 2, res.out)
        self.assertIn("Invalid port", res.out)

    def test_oversized_port_is_rejected(self):
        res = h.run("scan_backdoors_gui.py", ["--port", "70000"])
        self.assertEqual(res.returncode, 2, res.out)
        self.assertIn("Invalid port", res.out)


class FallbackTest(unittest.TestCase):
    def test_falls_back_when_the_requested_port_is_busy(self):
        hold = []
        busy = h.free_port()
        if hold_listener(busy, hold) is None:
            self.skipTest("cannot hold a listener on port %d" % busy)
        home = h.workdir("sbd-gui-port-")
        gui = GuiProc(home, "--no-browser", "--port", str(busy))
        try:
            bound = gui.wait_banner()
            self.assertIsNotNone(bound, "no banner appeared: %s" % gui.stdout_text())
            self.assertNotEqual(bound, busy)
            self.assertIn("not usable", gui.stdout_text())
            with urlopen("http://127.0.0.1:%d/api/ping" % bound, timeout=10) as r:
                self.assertEqual(json.loads(r.read().decode("utf-8")).get("app"),
                                 "scan_backdoors_gui")
        finally:
            gui.shutdown()
            for s in hold:
                s.close()

    def test_busy_requested_port_is_reported_as_the_fallback_cause(self):
        hold = []
        busy = h.free_port()
        if hold_listener(busy, hold) is None:
            self.skipTest("cannot hold a listener on port %d" % busy)
        home = h.workdir("sbd-gui-port-")
        gui = GuiProc(home, "--no-browser", "--port", str(busy))
        try:
            bound = gui.wait_banner()
            self.assertIsNotNone(bound, gui.stdout_text())
            note = [l for l in gui.lines if "NOTE:" in l]
            self.assertTrue(note, "no NOTE was printed")
            self.assertIn(str(busy), note[0])
            self.assertIn(str(bound), note[0])
        finally:
            gui.shutdown()
            for s in hold:
                s.close()


class AlreadyRunningTest(unittest.TestCase):
    def test_second_start_exits_instead_of_duplicating_the_server(self):
        home = h.workdir("sbd-gui-port-")
        port = h.free_port()
        gui = GuiProc(home, "--no-browser", "--port", str(port))
        try:
            bound = gui.wait_banner()
            self.assertEqual(bound, port, gui.stdout_text())
            second = GuiProc.run_once(home, "--no-browser", "--port", str(port))
            self.assertEqual(second[0], 0, second[1])
            self.assertIn("already running", second[1])
            # the original instance is still the only one answering
            with urlopen("http://127.0.0.1:%d/api/ping" % port, timeout=10) as r:
                self.assertEqual(json.loads(r.read().decode("utf-8")).get("app"),
                                 "scan_backdoors_gui")
        finally:
            gui.shutdown()


class FailurePathTest(unittest.TestCase):
    def test_every_port_in_range_busy_reports_the_range_and_exits_1(self):
        hold = []
        busy_port = 65535
        if hold_listener(busy_port, hold) is None:
            self.skipTest("cannot hold a listener on port %d" % busy_port)
        home = h.workdir("sbd-gui-port-")
        gui = GuiProc(home, "--no-browser", "--port", str(busy_port))
        try:
            # wait for the process to exit on its own (it must not serve)
            deadline = time.time() + 60
            while time.time() < deadline:
                if gui.proc.poll() is not None:
                    break
                time.sleep(0.2)
            rc = gui.proc.poll()
            self.assertEqual(rc, 1, gui.stdout_text())
            out = gui.stdout_text()
            self.assertIn("Could not bind a port in the range 65535-65535.", out)
            self.assertIn("refused to bind", out)
        finally:
            gui.shutdown()
            for s in hold:
                s.close()


if __name__ == "__main__":
    unittest.main()
