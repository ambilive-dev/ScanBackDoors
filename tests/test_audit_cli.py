# -*- coding: utf-8 -*-
"""TZ v2 Sprint 3: the CMS audit through the scanner's own command line.

These tests run scan_backdoors.main() in this process so the audit can be watched
from the inside: the two services are replaced by a fake that records every URL
it was asked for, and one test replaces the socket layer with a trap - a default
run, and an audit run without --online, must never reach the network at all.

The WP fixtures are deliberately small: what is being tested is which facts reach
the report, the exit code and the console, not the size of a real site.
"""

import csv
import hashlib
import io
import json
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

sys.path.insert(0, h.REPO)
sys.path.insert(0, h.SRC)

import scan_backdoors as sb  # noqa: E402
from engines import cms_api as api  # noqa: E402

WP_VERSION = "6.4.2"
CORE_FILES = {
    "index.php": "<?php\n// bootstrap\n",
    "wp-settings.php": "<?php\n// settings\n",
    "wp-includes/version.php": "<?php\n$wp_version = '%s';\n" % WP_VERSION,
    "wp-includes/template.php": "<?php\n// template\n",
    "wp-admin/about.php": "<?php\n// about\n",
    "wp-content/plugins/jobmanager/jobmanager.php":
        "<?php\n/**\n * Plugin Name: WP Job Manager\n * Version: 1.33.0\n */\n",
    "wp-content/plugins/akismet/akismet.php":
        "<?php\n/**\n * Plugin Name: Akismet\n * Version: 5.1\n */\n",
    "wp-content/themes/mytheme/style.css": "/*\nTheme Name: My Theme\nVersion: 1.0\n*/\n",
}

CVE_DATABASE = {"schema": 2, "generated": "2026-11-27T00:00:00Z", "entries": [
    {"cve": "CVE-2023-4000", "cms": "wordpress", "type": "plugin", "component": "jobmanager",
     "affected": [{"introduced": "1.0", "fixed": "1.34.0"}], "cvss": 9.8, "kev": True,
     "source": "test-fixture", "summary": "an outdated plugin with a known hole"},
]}

SERVICE_VULN = {"uuid": "f" * 16, "name": "Akismet < 5.4", "description": None,
                "operator": {"min_version": "5.0", "min_operator": "ge",
                             "max_version": "5.4", "max_operator": "lt", "unfixed": "0"},
                "source": [{"id": "CVE-2024-7777", "name": "CVE-2024-7777",
                            "link": "https://www.cve.org/", "description": "service fixture",
                            "date": "2024-06-01"}],
                "impact": {"cvss3": {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                                                                 "S:U/C:L/I:L/A:N",
                                     "score": "6.3", "severity": "medium"}}}


def make_wp_site(extra=None, tamper=None):
    """The fixture site; `tamper` replaces or adds a file after the catalogue was made."""
    site = h.workdir("audit-site-")
    files = dict(CORE_FILES)
    files.update(extra or {})
    for rel, content in files.items():
        path = os.path.join(site, *rel.split("/"))
        folder = os.path.dirname(path)
        if not os.path.isdir(folder):
            os.makedirs(folder)
        with open(path, "wb") as fh:
            fh.write(content.encode("utf-8"))
    for rel, content in (tamper or {}).items():
        path = os.path.join(site, *rel.split("/"))
        folder = os.path.dirname(path)
        if not os.path.isdir(folder):
            os.makedirs(folder)
        with open(path, "wb") as fh:
            fh.write(content.encode("utf-8"))
    return site


def official_checksums(ignore=()):
    """What api.wordpress.org would answer for the untampered fixture."""
    return {rel: hashlib.md5(content.encode("utf-8")).hexdigest()
            for rel, content in CORE_FILES.items() if rel not in ignore}


class FakeAuditClient(object):
    """Replaces AuditClient inside the scanner: answers both services, records URLs."""

    instances = []

    def __init__(self, cache_dir=None, allowed_hosts=None, budget=None, timeout=None,
                 max_bytes=None, opener=None, cache_ttl=None, allow_network=True, **kw):
        self.calls = []
        self.notes = []
        self.requests = 0
        self.cache_hits = 0
        self.allow_network = allow_network
        self.checksums = type(self).checksums
        self.online_answers = type(self).online_answers
        FakeAuditClient.instances.append(self)

    def get_json(self, url, referer_note=""):
        api.check_url(url, api.ALLOWED_HOSTS)          # the same rules the real client has
        if not self.allow_network:
            raise api.OfflineMode("offline")
        self.calls.append(url)
        self.requests += 1
        if "core/checksums" in url:
            return {"checksums": self.checksums}
        for needle, payload in self.online_answers.items():
            if needle in url:
                return payload
        return {"error": 0, "data": {"vulnerability": []}}

    @property
    def hosts(self):
        from urllib.parse import urlsplit
        return sorted({urlsplit(u).hostname for u in self.calls})


class AuditCliCase(unittest.TestCase):
    """Shared scaffolding: a private data folder, a fake API, a captured stdout."""

    checksums = {}
    online_answers = {"plugin/jobmanager": {"error": 0, "data": {"vulnerability": []}},
                      "plugin/akismet": {"error": 0, "data": {"vulnerability": [SERVICE_VULN]}},
                      "core/": {"error": 0, "data": {"core": WP_VERSION, "vulnerability": []}},
                      "theme/": {"error": 0, "data": {"vulnerability": []}}}

    def setUp(self):
        self.data = h.workdir("audit-data-")
        self._saved_data = os.environ.get("SBD_DATA_DIR")
        os.environ["SBD_DATA_DIR"] = self.data
        self._real_client = api.AuditClient
        FakeAuditClient.instances = []
        FakeAuditClient.checksums = self.checksums
        FakeAuditClient.online_answers = self.online_answers
        api.AuditClient = FakeAuditClient
        self._real_stdout = sys.stdout
        sys.stdout = io.StringIO()

    def tearDown(self):
        try:
            self.output = sys.stdout.getvalue()
        finally:
            sys.stdout = self._real_stdout
            api.AuditClient = self._real_client
            if self._saved_data is None:
                os.environ.pop("SBD_DATA_DIR", None)
            else:
                os.environ["SBD_DATA_DIR"] = self._saved_data

    def run_scan(self, site, *args):
        out_json = os.path.join(h.workdir("audit-out-"), "report.json")
        code = sb.main([site, "--no-csv", "--no-progress", "--json", out_json] + list(args))
        report = h.read_json(out_json)
        return code, report

    def console(self):
        """What the scanner printed so far (the console is captured for the test)."""
        return sys.stdout.getvalue()

    def assert_no_requests(self, report=None):
        for client in FakeAuditClient.instances:
            self.assertEqual(client.calls, [],
                             "a request was made without --online: %r" % client.calls)


class NoNetworkByDefaultTest(AuditCliCase):
    def test_an_audit_without_online_never_touches_the_network(self):
        # the trap: not a fake that happens to be quiet, a socket that is gone
        real_socket, real_connect = socket.socket, socket.create_connection
        socket.socket = socket.create_connection = lambda *a, **kw: self.fail(
            "the audit reached the network without --online")
        try:
            site = make_wp_site()
            code, report = self.run_scan(site, "--inventory", "--audit-cve", "--check-integrity")
        finally:
            socket.socket, socket.create_connection = real_socket, real_connect
        self.assertIn(code, (0, 2))
        self.assertIn("inventory", report)
        self.assertEqual(report["integrity"], None,
                         "without --online there is no catalogue: integrity reports nothing, "
                         "it does not guess")
        self.assertTrue(any("needs --online" in line for line in self.console().splitlines()),
                        "the scanner must say what it could not do: %r" % self.console())

    def test_a_default_run_has_no_audit_sections_at_all(self):
        site = make_wp_site()
        code, report = self.run_scan(site)
        for key in ("inventory", "integrity", "vulnerabilities", "audit_notes"):
            self.assertNotIn(key, report, "the default report grew a new section: %s" % key)
        self.assertEqual(FakeAuditClient.instances, [])

    def test_online_is_what_opens_the_door(self):
        FakeAuditClient.checksums = official_checksums()
        site = make_wp_site()
        code, report = self.run_scan(site, "--audit-cve", "--check-integrity", "--online")
        self.assertIn(code, (0, 2))
        clients = FakeAuditClient.instances
        self.assertTrue(clients, "with --online the audit must actually look")
        hosts = clients[0].hosts
        self.assertIn("api.wordpress.org", hosts)
        self.assertIn("api.wpvulnerability.com", hosts)
        self.assertEqual(set(hosts) - set(api.ALLOWED_HOSTS), set(),
                         "the audit asked somewhere that is not allowlisted: %r" % hosts)
        cves = [row["cve"] for row in report["vulnerabilities"]]
        self.assertIn("CVE-2024-7777", cves, "the service answer must reach the report: %r" % cves)
        self.assertTrue(any("ONLINE" in line for line in self.console().splitlines()),
                        "--online has to warn before the first request")


class IntegrityThroughTheCliTest(AuditCliCase):
    def test_a_modified_core_file_becomes_an_ordinary_finding(self):
        FakeAuditClient.checksums = official_checksums()
        site = make_wp_site(tamper={"wp-includes/template.php": "<?php\n// and a shell\n"
                                                                "eval($_POST[0]);\n"})
        code, report = self.run_scan(site, "--check-integrity", "--online")
        self.assertEqual(code, 2, "a modified core file is a [CRITICAL] finding")
        flagged = {f["path"]: f for f in report["files"]}
        self.assertIn("wp-includes/template.php", flagged)
        labels = [hit["signature"] for hit in flagged["wp-includes/template.php"]["hits"]]
        self.assertTrue(any("modified WordPress core" in l for l in labels), labels)
        self.assertEqual(report["integrity"]["summary"]["modified"], 1)
        self.assertGreaterEqual(flagged["wp-includes/template.php"]["score"], sb.HIGH_SCORE)

    def test_a_new_file_inside_wp_admin_is_reported_on_the_file(self):
        FakeAuditClient.checksums = official_checksums()
        site = make_wp_site(tamper={"wp-admin/network/upup.php": "<?php system($_GET[0]);\n"})
        code, report = self.run_scan(site, "--check-integrity", "--online")
        self.assertEqual(code, 2)
        paths = {f["path"] for f in report["files"]}
        self.assertIn("wp-admin/network/upup.php", paths)
        self.assertEqual(report["integrity"]["summary"]["extra"], 1)

    def test_a_clean_site_of_known_files_is_not_flagged(self):
        FakeAuditClient.checksums = official_checksums()
        site = make_wp_site()
        code, report = self.run_scan(site, "--check-integrity", "--online")
        self.assertEqual(code, 0)
        summary = report["integrity"]["summary"]
        self.assertEqual((summary["modified"], summary["extra"], summary["missing"]), (0, 0, 0))
        self.assertEqual(summary["verified"], len(CORE_FILES))
        self.assertTrue(summary["complete"])

    def test_a_missing_core_file_is_reported_but_never_as_a_file_to_delete(self):
        FakeAuditClient.checksums = official_checksums()
        site = make_wp_site()
        os.remove(os.path.join(site, "wp-admin", "about.php"))
        code, report = self.run_scan(site, "--check-integrity", "--online")
        self.assertEqual(report["integrity"]["summary"]["missing"], 1)
        self.assertEqual(report["integrity"]["missing"], ["wp-admin/about.php"])
        self.assertNotIn("wp-admin/about.php", {f["path"] for f in report["files"]},
                         "a file that is not there cannot be offered for quarantine")


class CveThroughTheCliTest(AuditCliCase):
    def _db(self, entries=None):
        path = os.path.join(self.data, "vulnerabilities.json")
        doc = dict(CVE_DATABASE)
        if entries is not None:
            doc["entries"] = entries
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return path

    def test_the_vulnerability_table_is_a_file_of_its_own(self):
        """TZ 8.5: a separate table, and the findings CSV stays parseable as findings.

        The GUI reads the report with a header-first parser: a second table appended
        to the same file would come back as malformed findings, so the verdicts get
        their own file and the findings CSV keeps exactly its own columns.
        """
        site = make_wp_site()
        out_csv = os.path.join(h.workdir("audit-out-"), "report.csv")
        code = sb.main([site, "--no-progress", "--csv", out_csv, "--audit-cve",
                        "--vuln-db", self._db()])
        self.assertIn(code, (0, 2))
        side = sb.vulnerabilities_csv_path(out_csv)
        self.assertTrue(os.path.isfile(side), "the verdicts must be written somewhere: %r" % code)
        with io.open(side, encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        self.assertEqual(rows[0], sb.VULN_CSV_HEADER)
        self.assertEqual(len(rows), 1 + len(CVE_DATABASE["entries"]))
        self.assertIn("CVE-2023-4000", rows[1])
        with io.open(out_csv, encoding="utf-8-sig", newline="") as fh:
            findings_text = fh.read()
        self.assertNotIn("CVE-", findings_text,
                         "the findings CSV must hold nothing but findings")
        for row in h.read_csv(out_csv):
            self.assertIn("Score", row)          # the header-first readers still work
            self.assertEqual(list(row.keys())[0], "Score")

    def test_a_local_database_entry_is_enough_offline(self):
        site = make_wp_site()
        code, report = self.run_scan(site, "--audit-cve", "--vuln-db", self._db())
        self.assertEqual(code, 0, "a CVE never changes the exit code without --fail-on")
        cves = [row["cve"] for row in report["vulnerabilities"]]
        self.assertEqual(cves, ["CVE-2023-4000"])
        self.assert_no_requests()
        row = report["vulnerabilities"][0]
        self.assertTrue(row["kev"])
        self.assertEqual(row["severity"], "critical")
        self.assertEqual(row["component_version"], "1.33.0")

    def test_fail_on_turns_a_verdict_into_an_exit_code(self):
        site = make_wp_site()
        code, _report = self.run_scan(site, "--audit-cve", "--vuln-db", self._db(),
                                      "--fail-on", "critical")
        self.assertEqual(code, 4)
        code, _report = self.run_scan(site, "--audit-cve", "--vuln-db", self._db(),
                                      "--fail-on", "high")
        self.assertEqual(code, 4, "critical is above the bar too")

    def test_fail_on_ignores_verdicts_that_could_not_be_decided(self):
        entries = [dict(CVE_DATABASE["entries"][0], component="no-such-plugin")]
        site = make_wp_site()
        code, _report = self.run_scan(site, "--audit-cve", "--vuln-db", self._db(entries),
                                      "--fail-on", "critical")
        self.assertEqual(code, 0, "nothing matched this site, so nothing may fail the run")

    def test_fail_on_without_the_audit_is_a_usage_error(self):
        site = make_wp_site()
        code = sb.main([site, "--no-csv", "--no-progress", "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_a_broken_database_is_a_note_and_the_scan_survives(self):
        path = os.path.join(self.data, "broken.json")
        with io.open(path, "w", encoding="utf-8") as fh:
            fh.write("{ not json")
        site = make_wp_site()
        code, report = self.run_scan(site, "--audit-cve", "--vuln-db", path)
        self.assertIn(code, (0, 2))
        self.assertEqual(report["vulnerabilities"], [])
        self.assertTrue(any("not JSON" in n for n in report["audit_notes"]), report["audit_notes"])

    def test_a_component_without_a_version_is_reported_as_unauditable(self):
        site = make_wp_site(tamper={"wp-content/plugins/mystery/mystery.php": "<?php\n"})
        entries = [dict(CVE_DATABASE["entries"][0], component="mystery")]
        code, report = self.run_scan(site, "--audit-cve", "--vuln-db", self._db(entries))
        rows = [row for row in report["vulnerabilities"] if row["component"] == "mystery"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["confidence"], "low")
        self.assertIn("could not be read", rows[0]["summary"])

    def test_the_report_sections_stay_apart(self):
        FakeAuditClient.checksums = official_checksums()
        site = make_wp_site(tamper={"wp-admin/tools/tmp.php": "<?php eval($_GET[1]);\n"})
        code, report = self.run_scan(site, "--check-integrity", "--audit-cve",
                                     "--vuln-db", self._db(), "--online")
        # a CVE is not a file finding: it lives in its own section only
        for found in report["files"]:
            for hit in found["hits"]:
                self.assertNotIn("CVE-", hit["signature"],
                                 "a CVE leaked into the findings table of %s" % found["path"])
        self.assertTrue(report["vulnerabilities"])
        self.assertEqual(code, 2, "the [CRITICAL] file finding decides the exit code")


class InventoryThroughTheCliTest(AuditCliCase):
    def test_the_inventory_names_the_components_and_their_declared_versions(self):
        site = make_wp_site()
        code, report = self.run_scan(site, "--inventory")
        self.assertEqual(code, 0)
        self.assertEqual(report["inventory_summary"]["cms"], "wordpress")
        self.assertEqual(report["inventory_summary"]["cms_version"], WP_VERSION)
        slugs = {c["slug"]: c for c in report["inventory"]["components"]}
        self.assertEqual(slugs["jobmanager"]["version"], "1.33.0")
        self.assertEqual(slugs["jobmanager"]["version_source"], "declared")
        for comp in report["inventory"]["components"]:
            self.assertFalse(os.path.isabs(comp["path"]))
        self.assertIn(code, (0,))
        self.assert_no_requests()

    def test_a_non_cms_site_is_said_so(self):
        site = h.workdir("audit-plain-")
        with open(os.path.join(site, "index.html"), "w", encoding="utf-8") as fh:
            fh.write("<html>plain</html>\n")
        code, report = self.run_scan(site, "--inventory", "--audit-cve")
        self.assertEqual(code, 0)
        self.assertEqual(report["inventory_summary"]["cms"], "unknown")
        self.assertEqual(report["vulnerabilities"], [])

    def test_the_joomla_inventory_reaches_the_report_too(self):
        site = h.workdir("audit-joomla-")
        files = {
            "configuration.php": "<?php\nclass JConfig {}\n",
            "administrator/manifests/files/joomla.xml":
                '<?xml version="1.0"?><extension type="file" version="3.9">'
                "<name>Joomla!</name><version>4.4.10</version></extension>",
            "administrator/components/com_foobar/foobar.xml":
                '<?xml version="1.0"?><extension type="component" version="3.0">'
                "<name>FooBar</name><version>1.4.2</version></extension>",
        }
        for rel, content in files.items():
            path = os.path.join(site, *rel.split("/"))
            if not os.path.isdir(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))
            with open(path, "wb") as fh:
                fh.write(content.encode("utf-8"))
        code, report = self.run_scan(site, "--inventory")
        self.assertEqual(report["inventory_summary"]["cms"], "joomla")
        self.assertEqual(report["inventory_summary"]["cms_version"], "4.4.10")
        self.assertEqual([c["slug"] for c in report["inventory"]["components"]], ["com_foobar"])


if __name__ == "__main__":
    unittest.main()
