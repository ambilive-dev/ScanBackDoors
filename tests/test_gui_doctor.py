# -*- coding: utf-8 -*-
"""--self-test (doctor) and boot-time path validation of the GUI (black-box)."""
import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402


def run_doctor(home):
    env = dict(h.ENV, HOME=home, USERPROFILE=home, APPDATA=os.path.join(home, "AppData"))
    proc = subprocess.Popen(
        [h.PYTHON, "-u", h.tool_path("scan_backdoors_gui.py"), "--self-test"],
        cwd=h.SRC, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True, encoding="utf-8", errors="replace", env=env)
    out, _ = proc.communicate(timeout=120)
    return proc.returncode, out


class GuiDoctorTest(unittest.TestCase):
    def test_doctor_passes_with_defaults(self):
        home = h.workdir("sbd-gui-doc-")
        rc, out = run_doctor(home)
        self.assertEqual(rc, 0, out)
        self.assertIn("self-test: 11 of 11 checks passed", out)

    def test_doctor_fails_on_missing_scanner(self):
        home = h.workdir("sbd-gui-doc-")
        with open(os.path.join(home, ".scan_backdoors_gui.json"), "w", encoding="utf-8") as f:
            json.dump({"scanner_path": os.path.join(home, "no-such-scanner.py")}, f)
        rc, out = run_doctor(home)
        self.assertEqual(rc, 1, out)
        self.assertIn("scanner_path", out)
        self.assertIn("is not a file", out)

    def test_doctor_fails_on_broken_json(self):
        home = h.workdir("sbd-gui-doc-")
        with open(os.path.join(home, ".scan_backdoors_gui.json"), "w", encoding="utf-8") as f:
            f.write("{ not json")
        rc, out = run_doctor(home)
        self.assertEqual(rc, 1, out)
        self.assertIn("not valid JSON", out)

    def test_boot_reports_bad_scanner_but_server_runs(self):
        home = h.workdir("sbd-gui-doc-")
        with open(os.path.join(home, ".scan_backdoors_gui.json"), "w", encoding="utf-8") as f:
            json.dump({"scanner_path": os.path.join(home, "no-such-scanner.py")}, f)
        with h.Gui(home) as gui:
            self.assertIn("ERROR: settings: scanner_path", gui.log())
