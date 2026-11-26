# -*- coding: utf-8 -*-
"""The GUI: it boots, it answers, it scans, and it never touches the real home.

The GUI is a subprocess on a private port with a private home directory, exactly
like a user launching it. The scan test runs the real scanner against the
synthetic site, so it works without a real Joomla installation.
"""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402
import fixtures_sites as fx  # noqa: E402


class VersionTest(unittest.TestCase):
    def test_version_flag_prints_the_bundle_version(self):
        res = h.run("scan_backdoors_gui.py", ["--version"])
        self.assertEqual(res.returncode, 0, res.out)
        self.assertIn("scan_backdoors_gui", res.out)
        self.assertIn(h.bundle_version(), res.out)


class BootTest(unittest.TestCase):
    def test_the_gui_boots_and_answers_ping(self):
        home = h.workdir("sbd-gui-")
        with h.Gui(home) as gui:
            ping = gui.api("GET", "/api/ping")
            self.assertEqual(ping["version"], h.bundle_version())
            self.assertTrue(ping.get("app"))

    def test_the_api_requires_the_gui_header(self):
        # /api/ping is a lightweight health check and is deliberately exempt;
        # the guarded routes must reject a request without the header.
        home = h.workdir("sbd-gui-")
        with h.Gui(home) as gui:
            for bad in ({"X-Requested-With": ""}, {"X-Requested-With": "wrong"}):
                with self.assertRaises(h.ApiError) as cm:
                    gui.api("GET", "/api/state", headers=bad)
                self.assertEqual(cm.exception.status, 403)


class SettingsTest(unittest.TestCase):
    def test_settings_default_to_the_shipped_scanner(self):
        home = h.workdir("sbd-gui-")
        with h.Gui(home) as gui:
            settings = gui.settings()
            self.assertTrue(os.path.isfile(settings["scanner_path"]))
            self.assertEqual(os.path.basename(settings["scanner_path"]), "scan_backdoors.py")

    def test_settings_are_saved_into_the_isolated_home(self):
        home = h.workdir("sbd-gui-")
        site_dir = os.path.join(home, "site")
        os.makedirs(site_dir)
        with h.Gui(home) as gui:
            gui.api("POST", "/api/settings", {"settings": {"site_dir": site_dir}})
        saved = os.path.join(home, ".scan_backdoors_gui.json")
        self.assertTrue(os.path.isfile(saved), "settings must be saved next to the private home")
        with open(saved, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["site_dir"], site_dir)

    def test_the_real_home_is_never_touched(self):
        real = Path.home() / ".scan_backdoors_gui.json"
        before = None
        try:
            before = os.path.getmtime(real)
        except OSError:
            before = None
        home = h.workdir("sbd-gui-")
        with h.Gui(home) as gui:
            gui.api("POST", "/api/settings",
                    {"settings": {"site_dir": os.path.join(home, "site")}})
        after = None
        try:
            after = os.path.getmtime(real)
        except OSError:
            after = None
        self.assertEqual(before, after, "the real settings file must not be modified")


class ScanTest(unittest.TestCase):
    """The GUI launches the real scanner against the synthetic site."""

    def test_scan_finishes_with_critical_findings(self):
        home = h.workdir("sbd-gui-")
        site = fx.build("gui-planted", planted=True)
        present, _vanished = fx.wait_readables(site, list(fx.PLANTED))
        if len(present) < 2:
            raise unittest.SkipTest(
                "only %d planted samples reached the scanner: %s" % (len(present), h.AV_HINT))
        csv_path = os.path.join(home, "report.csv")
        with h.Gui(home) as gui:
            gui.api("POST", "/api/scan/start", {"settings": {
                "site_dir": site, "csv_path": csv_path, "workers": "1"}})
            state = gui.wait_scan(timeout=120)
        status = state.get("status") or ""
        self.assertIn("critical findings detected", status,
                      "the planted site must be reported as critical: %s" % status)
        self.assertIn("Files scanned", status)

    def test_scan_of_a_clean_site_reports_no_critical_findings(self):
        home = h.workdir("sbd-gui-")
        site = fx.build("gui-clean", planted=False)
        csv_path = os.path.join(home, "report.csv")
        with h.Gui(home) as gui:
            gui.api("POST", "/api/scan/start", {"settings": {
                "site_dir": site, "csv_path": csv_path, "workers": "1"}})
            state = gui.wait_scan(timeout=120)
        status = state.get("status") or ""
        self.assertIn("no critical findings", status,
                      "a clean site must not be reported as critical: %s" % status)


if __name__ == "__main__":
    unittest.main()
