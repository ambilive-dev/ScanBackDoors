# -*- coding: utf-8 -*-
"""The GUI: it boots, it answers, it scans, and it never touches the real home.

The GUI is a subprocess on a private port with a private home directory, exactly
like a user launching it. The scan test runs the real scanner against the
synthetic site, so it works without a real Joomla installation.
"""

import json
import os
import sys
import time
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


class BaselineFetchTest(unittest.TestCase):
    """The 'Fetch baseline' flow: version detection from the site's own files, and the
    fetch job wiring. The job itself is exercised with a stub joomla_baseline.py so the
    test never touches the network."""

    @staticmethod
    def _fake_site(home):
        site = os.path.join(home, "site")
        ver = os.path.join(site, "libraries", "cms", "version")
        os.makedirs(ver)
        with open(os.path.join(ver, "version.php"), "w", encoding="utf-8") as f:
            f.write("<?php class JVersion { public $RELEASE = '3.10'; public $DEV_LEVEL = '12'; }\n")
        return site

    def test_detect_reports_the_site_version(self):
        home = h.workdir("sbd-gui-")
        site = self._fake_site(home)
        with h.Gui(home) as gui:
            gui.api("POST", "/api/settings", {"settings": {"site_dir": site}})
            d = gui.api("POST", "/api/baseline/detect", {})
            self.assertEqual(d["version"], "3.10.12")

    def test_detect_refuses_without_a_site(self):
        home = h.workdir("sbd-gui-")
        with h.Gui(home) as gui:
            with self.assertRaises(h.ApiError):
                gui.api("POST", "/api/baseline/detect", {})

    def test_fetch_job_fills_the_baseline_dir_setting(self):
        home = h.workdir("sbd-gui-")
        site = self._fake_site(home)
        tools = os.path.join(home, "tools")
        os.makedirs(tools)
        stub = os.path.join(tools, "scan_backdoors.py")
        with open(stub, "w", encoding="utf-8") as f:
            f.write("# stub scanner - only the folder location matters here\n")
        fetcher = os.path.join(tools, "joomla_baseline.py")
        with open(fetcher, "w", encoding="utf-8") as f:
            f.write("import pathlib, sys\n"
                    "a = sys.argv[1:]\n"
                    "out = pathlib.Path(a[a.index('--out') + 1])\n"
                    "d = out / ('Joomla_' + a[0])\n"
                    "(d / 'libraries').mkdir(parents=True)\n"
                    "(d / 'index.php').write_text('<?php // stub baseline\\n')\n")
        with h.Gui(home) as gui:
            gui.api("POST", "/api/settings", {"settings": {"site_dir": site, "scanner_path": stub}})
            r = gui.api("POST", "/api/baseline/fetch", {})
            self.assertEqual(r["version"], "3.10.12")
            deadline = time.time() + 60
            while True:
                state = gui.api("GET", "/api/state")
                if state["job"] is None:
                    break
                if time.time() > deadline:
                    self.fail("the baseline job never finished")
                time.sleep(0.5)
            baseline_dir = gui.settings()["baseline_dir"]
        self.assertIn("Baseline ready", state.get("status") or "")
        expected = os.path.join(tools, "joomla-baselines", "Joomla_3.10.12")
        self.assertEqual(os.path.normpath(baseline_dir), os.path.normpath(expected))


class SignaturesTest(unittest.TestCase):
    """The signature endpoints: status from the manifest, update/rollback as a job.

    The browser never sends a path or a URL, so the tests only check what the server
    decides for itself: the private home (HOME/USERPROFILE are redirected by the
    harness), the installed release, and the scanner command line the GUI builds.
    """

    RULE = ('rule GuiProbe {\n    strings:\n        $a = "SBD_GUI_SIG_PROBE_771" ascii wide\n'
            "    condition:\n        $a\n}\n")

    @staticmethod
    def _root(home):
        return os.path.join(home, ".scan_backdoors")

    def _bundle(self, home, name):
        import hashlib
        import zipfile
        bundle = os.path.join(home, name + ".zip")
        entries = [{"path": "rules/a.yar",
                    "sha256": hashlib.sha256(self.RULE.encode("utf-8")).hexdigest()}]
        manifest = {"schema": 2, "package": {"name": name, "license": "CC0-1.0"}, "files": entries}
        with zipfile.ZipFile(bundle, "w") as z:
            z.writestr("rules/a.yar", self.RULE)
            z.writestr("manifest.json", json.dumps(manifest))
        return bundle

    def _install(self, home, name):
        bundle = self._bundle(home, name)
        res = h.run("updater.py", ["--update-from-bundle", bundle, "--data-dir", self._root(home),
                                   "--allow-unverified"])
        self.assertEqual(res.returncode, 0, res.out)

    def _wait_job(self, gui, timeout=90):
        deadline = time.time() + timeout
        while True:
            state = gui.api("GET", "/api/state")
            if state["job"] is None:
                return state
            if time.time() > deadline:
                self.fail("the signatures job never finished: %r" % (state.get("status"),))
            time.sleep(0.3)

    def _gui(self, home):
        """A started GUI whose data folder is pinned inside the private home (an
        inherited SBD_DATA_DIR must never point a test at the developer's real one)."""
        gui = h.Gui(home)
        gui.env["SBD_DATA_DIR"] = self._root(home)
        gui.start()
        return gui

    def test_status_reports_no_package_in_a_clean_home(self):
        home = h.workdir("sbd-gui-")
        gui = self._gui(home)
        try:
            st = gui.api("GET", "/api/signatures/status")
        finally:
            gui.stop()
        self.assertFalse(st["present"])
        self.assertIsNone(st["active"])
        self.assertTrue(st["tool"], "updater.py ships next to the GUI")
        self.assertEqual(os.path.normpath(st["data_dir"]),
                         os.path.normpath(os.path.join(self._root(home), "signatures")),
                         "the data folder must be inside the private home, never the real one")

    @unittest.skipUnless(h.have_yara(), "installing a release runs the real compile check")
    def test_an_installed_package_shows_up_and_rolls_back(self):
        home = h.workdir("sbd-gui-")
        self._install(home, "sbd-gui-sig-1")
        self._install(home, "sbd-gui-sig-2")
        gui = self._gui(home)
        try:
            st = gui.api("GET", "/api/signatures/status")
            self.assertTrue(st["present"])
            self.assertEqual(st["active"], "sbd-gui-sig-2")
            self.assertEqual(st["rules"], 1)
            self.assertEqual(sorted(st["releases"]), ["sbd-gui-sig-1", "sbd-gui-sig-2"])
            gui.api("POST", "/api/signatures/rollback", {})
            state = self._wait_job(gui)
            self.assertIn("Signature rollback done", state.get("status") or "")
            after = gui.api("GET", "/api/signatures/status")
        finally:
            gui.stop()
        self.assertEqual(after["active"], "sbd-gui-sig-1")

    @unittest.skipUnless(h.have_yara(), "installing a release runs the real compile check")
    def test_a_scan_gets_the_installed_rules_and_the_state_the_status(self):
        home = h.workdir("sbd-gui-")
        site = fx.build("gui-sig-scan", planted=False)
        self._install(home, "sbd-gui-sig-1")
        gui = self._gui(home)
        try:
            gui.api("POST", "/api/settings", {"settings": {"site_dir": site, "workers": "1"}})
            state = gui.api("GET", "/api/state")
            self.assertTrue(state["signatures"]["present"])
            gui.api("POST", "/api/scan/start", {"settings": {"site_dir": site, "workers": "1"}})
            gui.wait_scan(timeout=180)
            log = "\n".join(gui.api("GET", "/api/state?since=0")["log"]["lines"])
        finally:
            gui.stop()
        rules = os.path.join(self._root(home), "signatures", "releases", "sbd-gui-sig-1", "rules")
        log_fwd = log.replace("\\", "/")
        self.assertIn("--yara-rules", log_fwd,
                      "an installed package must be passed to the scanner (server-side path)")
        self.assertIn(rules.replace("\\", "/"), log_fwd)
        self.assertIn("YARA: 1 rule(s)", log_fwd, "the installed rule must actually load")

    def test_update_without_a_configured_channel_fails_loudly(self):
        # the job runs the real updater: with an empty sources.json template the project
        # channel refuses, and the GUI must report it as a failure (never as success)
        home = h.workdir("sbd-gui-")
        gui = self._gui(home)
        try:
            gui.api("POST", "/api/signatures/update", {})
            state = self._wait_job(gui)
            st = gui.api("GET", "/api/signatures/status")
        finally:
            gui.stop()
        self.assertIn("failed", (state.get("status") or "").lower())
        self.assertFalse(st["present"], "a refused update must not change the active package")


class PreflightTest(unittest.TestCase):
    """The check before a scan: the detected core version vs. the loaded clean baseline,
    and the engines list for the footer. Everything runs on synthetic folders."""

    @staticmethod
    def _site(home, version=("3", "10", "12"), ext=True):
        site = os.path.join(home, "site")
        ver = os.path.join(site, "libraries", "cms", "version")
        os.makedirs(ver)
        with open(os.path.join(ver, "version.php"), "w", encoding="utf-8") as f:
            f.write("<?php class JVersion { const RELEASE = '%s.%s'; const DEV_LEVEL = '%s'; }\n"
                    % version)
        if ext:
            comp = os.path.join(site, "administrator", "components", "com_fooext")
            os.makedirs(comp)
            with open(os.path.join(comp, "com_fooext.xml"), "w", encoding="utf-8") as f:
                f.write('<extension type="component" version="3.0" id="com_fooext">'
                        "<name>Foo Ext</name><version>1.2.3</version></extension>\n")
            core = os.path.join(site, "administrator", "components", "com_content")
            os.makedirs(core)
            with open(os.path.join(core, "com_content.xml"), "w", encoding="utf-8") as f:
                f.write('<extension type="component" version="3.0" id="com_content">'
                        "<name>Content</name><version>3.10.12</version></extension>\n")
        return site

    @staticmethod
    def _baseline(home, version):
        b = os.path.join(home, "Joomla_" + version)
        ver = os.path.join(b, "libraries", "src")
        os.makedirs(ver)
        major, minor, patch = version.split(".")
        with open(os.path.join(ver, "Version.php"), "w", encoding="utf-8") as f:
            f.write("<?php class Version { const MAJOR_VERSION = %s; const MINOR_VERSION = %s;"
                    " const PATCH_VERSION = %s; }\n" % (major, minor, patch))
        return b

    def test_preflight_without_a_baseline(self):
        home = h.workdir("sbd-gui-")
        site = self._site(home)
        with h.Gui(home) as gui:
            gui.api("POST", "/api/settings", {"settings": {"site_dir": site}})
            pf = gui.api("POST", "/api/preflight", {})
        self.assertEqual(pf["mode"], "no_baseline")
        self.assertEqual(pf["joomla"], "3.10.12")

    def test_preflight_mismatch(self):
        home = h.workdir("sbd-gui-")
        site = self._site(home)
        base = self._baseline(home, "4.2.1")
        with h.Gui(home) as gui:
            gui.api("POST", "/api/settings", {"settings": {"site_dir": site, "baseline_dir": base}})
            pf = gui.api("POST", "/api/preflight", {})
        self.assertEqual(pf["mode"], "mismatch")
        self.assertEqual(pf["baseline"]["version"], "4.2.1")

    def test_preflight_match_is_ok(self):
        home = h.workdir("sbd-gui-")
        site = self._site(home)
        base = self._baseline(home, "3.10.12")
        with h.Gui(home) as gui:
            gui.api("POST", "/api/settings", {"settings": {"site_dir": site, "baseline_dir": base}})
            pf = gui.api("POST", "/api/preflight", {})
        self.assertEqual(pf["mode"], "ok")

    def test_preflight_without_a_detectable_engine(self):
        home = h.workdir("sbd-gui-")
        site = self._site(home, ext=False)
        os.remove(os.path.join(site, "libraries", "cms", "version", "version.php"))
        with h.Gui(home) as gui:
            gui.api("POST", "/api/settings", {"settings": {"site_dir": site}})
            pf = gui.api("POST", "/api/preflight", {})
        self.assertEqual(pf["mode"], "no_engine")

    def test_engines_list_third_party_but_not_core(self):
        home = h.workdir("sbd-gui-")
        site = self._site(home)
        with h.Gui(home) as gui:
            gui.api("POST", "/api/settings", {"settings": {"site_dir": site}})
            names = {(e["name"], e["version"]) for e in gui.api("POST", "/api/preflight", {})["engines"]}
            self.assertIn(("Joomla", "3.10.12"), names)
            self.assertIn(("Foo Ext", "1.2.3"), names)
            self.assertNotIn(("Content", "3.10.12"), names)   # bundled core: not an engine
            # the same list reaches the footer through /api/state (refreshed on settings save)
            deadline = time.time() + 20
            while time.time() < deadline:
                st = gui.api("GET", "/api/state")
                names = {(e["name"], e["version"]) for e in st["engines"]}
                if ("Foo Ext", "1.2.3") in names:
                    break
                time.sleep(0.4)
            self.assertIn(("Foo Ext", "1.2.3"), names)
            # the Engines tab's 'original loaded' mark comes with it in /api/state
            self.assertEqual(st["baseline"]["dir"], "")
            self.assertFalse(st["baseline"]["match"])
            base = self._baseline(home, "3.10.12")
            gui.api("POST", "/api/settings", {"settings": {"baseline_dir": base}})
            deadline = time.time() + 20
            while time.time() < deadline:
                st = gui.api("GET", "/api/state")
                if st["baseline"]["match"]:
                    break
                time.sleep(0.4)
            self.assertTrue(st["baseline"]["match"])
            self.assertEqual(st["baseline"]["version"], "3.10.12")


if __name__ == "__main__":
    unittest.main()
