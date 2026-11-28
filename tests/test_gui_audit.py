# -*- coding: utf-8 -*-
"""TZ v2 Sprint 3 in the GUI: tick the audit, and a CVE becomes something to read.

The GUI runs the way a user starts it: a subprocess, a private home, a private
data folder, and the real scanner as its child. What is watched is the chain the
audit has to survive - settings -> the command that is really built -> the JSON
report -> /api/audit -> the panel - and, above everything else, that a known
vulnerability never becomes something the app offers to quarantine or delete.

Nothing here touches the network: the audit runs against a local database, which
is exactly the offline path the flag has to keep working.
"""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

WP_VERSION = "6.4.2"
SITE_FILES = {
    "index.php": "<?php\n// bootstrap\n",
    "wp-settings.php": "<?php\n// settings\n",
    "wp-includes/version.php": "<?php\n$wp_version = '%s';\n" % WP_VERSION,
    "wp-admin/about.php": "<?php\n// about\n",
    "wp-content/plugins/jobmanager/jobmanager.php":
        "<?php\n/**\n * Plugin Name: WP Job Manager\n * Version: 1.33.0\n */\n",
    "wp-content/plugins/akismet/akismet.php":
        "<?php\n/**\n * Plugin Name: Akismet\n * Version: 5.1\n */\n",
    "wp-content/themes/mytheme/style.css": "/*\nTheme Name: My Theme\nVersion: 1.0\n*/\n",
}

VULN_DATABASE = {"schema": 2, "generated": "2026-11-27T00:00:00Z", "entries": [
    {"cve": "CVE-2023-4000", "cms": "wordpress", "type": "plugin", "component": "jobmanager",
     "affected": [{"introduced": "1.0", "fixed": "1.34.0"}], "cvss": 9.8, "kev": True,
     "source": "test-fixture", "summary": "an outdated plugin with a published hole"},
    {"cve": "CVE-2024-1111", "cms": "wordpress", "type": "plugin", "component": "akismet",
     "affected": [{"introduced": "5.0", "fixed": "5.4"}], "cvss": 5.3, "kev": False,
     "source": "test-fixture", "summary": "a moderate one"},
]}


def wp_site(home):
    """A small WordPress of known components (written as bytes: no CRLF surprises)."""
    site = os.path.join(home, "site")
    for rel, content in SITE_FILES.items():
        path = os.path.join(site, *rel.split("/"))
        folder = os.path.dirname(path)
        if not os.path.isdir(folder):
            os.makedirs(folder)
        with open(path, "wb") as fh:
            fh.write(content.encode("utf-8"))
    return site


def prepared_home(home):
    """The private data folder with the local vulnerability database in it."""
    data = os.path.join(home, "data")
    audit = os.path.join(data, "audit")
    if not os.path.isdir(audit):
        os.makedirs(audit)
    with io.open(os.path.join(audit, "vulnerabilities.json"), "w", encoding="utf-8") as fh:
        json.dump(VULN_DATABASE, fh)
    return data


def gui_with_data(home):
    """A Gui harness whose child processes see a private SBD_DATA_DIR."""
    data = prepared_home(home)
    gui = h.Gui(home)
    gui.env["SBD_DATA_DIR"] = data
    return gui


def logged_command(gui):
    """The command line the GUI really handed to the scanner (it is written to the log)."""
    state = gui.api("GET", "/api/state?since=0")
    lines = state["log"]["lines"]
    if isinstance(lines, str):
        lines = lines.split("\n")
    for line in reversed(list(lines)):
        if "Command:" in line:
            return line.split("Command:", 1)[1]
    return ""


class AuditCommandTest(unittest.TestCase):
    """What the tick boxes turn into on the command line."""

    def test_ticked_boxes_reach_the_scanner_and_online_stays_off(self):
        home = h.workdir("sbd-guiaudit-")
        site = wp_site(home)
        gui = gui_with_data(home)
        with gui:
            gui.api("POST", "/api/scan/start", {"settings": {
                "site_dir": site, "csv_path": os.path.join(home, "report.csv"), "workers": "1",
                "audit_inventory": True, "audit_cve": True, "audit_integrity": True,
                "audit_online": False}})
            gui.wait_scan(timeout=180)
            command = logged_command(gui)
            audit = gui.api("GET", "/api/audit")
            findings = gui.findings()
            badge = gui.api("GET", "/api/state")["audit"]
        self.assertIn("--inventory", command, command)
        self.assertIn("--audit-cve", command, command)
        self.assertIn("--check-integrity", command, command)
        self.assertNotIn("--online", command,
                         "nothing may be allowed to leave the machine unless it was ticked")
        self.assertEqual(audit["integrity"], {},
                         "without --online there is no official catalogue: the panel must not "
                         "invent numbers for the core files")
        self.assertTrue(any("online" in note.lower() for note in audit["notes"]),
                        "the audit has to say what it could not check: %r" % audit["notes"])
        self.assertTrue(audit["available"], "the audit ran, so the panel must have its answer")
        self.assertEqual(sorted(row["cve"] for row in audit["vulnerabilities"]),
                         ["CVE-2023-4000", "CVE-2024-1111"])
        critical = [row for row in audit["vulnerabilities"] if row["cve"] == "CVE-2023-4000"][0]
        self.assertEqual(critical["component"], "jobmanager")
        self.assertEqual(critical["component_version"], "1.33.0")
        self.assertEqual(critical["severity"], "critical")
        self.assertTrue(critical["kev"])
        self.assertEqual(critical["fixed_in"], "1.34.0")
        self.assertEqual(badge["vulnerabilities"], 2)
        self.assertEqual(badge["kev"], 1)
        # the findings table is the file table: a CVE is not in it, and its folder
        # is not offered as a row either
        for row in findings:
            joined = " ".join([str(row.get("Signature", "")), str(row.get("File", ""))])
            self.assertNotIn("CVE-", joined, "a vulnerability leaked into the findings table")

    def test_unticked_boxes_send_no_audit_flags_at_all(self):
        home = h.workdir("sbd-guiaudit-")
        site = wp_site(home)
        gui = gui_with_data(home)
        with gui:
            # online is ticked but nothing needs it: it must not appear either
            gui.api("POST", "/api/scan/start", {"settings": {
                "site_dir": site, "csv_path": os.path.join(home, "report.csv"), "workers": "1",
                "audit_inventory": False, "audit_cve": False, "audit_integrity": False,
                "audit_online": True}})
            gui.wait_scan(timeout=180)
            command = logged_command(gui)
            audit = gui.api("GET", "/api/audit")
        for flag in ("--inventory", "--check-integrity", "--audit-cve", "--online"):
            self.assertNotIn(flag, command, "an unticked box sent %s anyway" % flag)
        self.assertFalse(audit["available"], "no audit ran, so the panel must say there is nothing")
        self.assertEqual(audit["vulnerabilities"], [])


class VulnNotActionableTest(unittest.TestCase):
    """The panel is for reading. Every action that can change the site is absent."""

    def test_the_vulnerability_panel_offers_no_file_action(self):
        home = h.workdir("sbd-guiaudit-")
        gui = h.Gui(home)
        with gui:
            html = gui.api("GET", "/", raw=True).decode("utf-8")
        start = html.index("CMS audit: the vulnerabilities panel")
        end = html.index("function showPanel(")
        panel_js = html[start:end]
        self.assertTrue(panel_js.strip(), "the panel renderer was not found in the served page")
        # the words Quarantine/Delete may appear in the panel's own explanation, but
        # none of the machinery that acts on a file may be reachable from the panel:
        # no endpoint, no action function, no row selection
        for hook in ("/api/files", "fileAction", "data-chk", "S.sel", "confirm_protected"):
            self.assertNotIn(hook, panel_js, "the vulnerability panel reaches %r" % hook)
        self.assertIn("never apply", panel_js, "the panel must say what it will not do")
        self.assertIn("update the component", panel_js)

    def test_the_audit_settings_are_separate_from_the_file_actions(self):
        home = h.workdir("sbd-guiaudit-")
        gui = h.Gui(home)
        with gui:
            settings = gui.settings()
            html = gui.api("GET", "/", raw=True).decode("utf-8")
        for key in ("audit_inventory", "audit_integrity", "audit_cve", "audit_online"):
            self.assertIn(key, settings, "the settings schema lost %s" % key)
            self.assertIs(settings[key], False, "%s must default to off" % key)
            self.assertIn("'%s'" % key, html, "%s has no control on the Settings tab" % key)
        self.assertIn('id="vuln"', html, "the Vulnerabilities panel is not in the page")
        self.assertIn('data-p="vuln"', html, "the Vulnerabilities tab is not in the page")


if __name__ == "__main__":
    unittest.main()
