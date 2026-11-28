# -*- coding: utf-8 -*-
"""TZ v2 Sprint 3: engines/vuln_engine.py - matching components to vulnerabilities.

The service answers are recorded fixtures of the shape WPVulnerability sends (an
envelope, a version range, the CVSS/SSVC blocks); the fake client never opens a
socket. What the tests insist on: a component that cannot be identified is
reported as unauditable rather than skipped, an entry that cannot be read is
dropped with a complaint, and the answer "you are not affected" is only allowed
when a comparison really happened.
"""

import io
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

sys.path.insert(0, h.REPO)

from engines import cms_api as api  # noqa: E402
from engines import vuln_engine as ve  # noqa: E402


def entry(cve="CVE-2024-1111", cms="wordpress", ctype="plugin", component="akismet",
          introduced="5.0", fixed="5.3", cvss=7.5, kev=False, source="local-test",
          **extra):
    doc = {"cve": cve, "cms": cms, "type": ctype, "component": component,
           "affected": [{"introduced": introduced, "fixed": fixed}],
           "cvss": cvss, "kev": kev, "source": source,
           "summary": "a test vulnerability"}
    doc.update(extra)
    return doc


def component(slug="akismet", version="5.1", ctype="plugin", cms="wordpress",
              path="wp-content/plugins/akismet", source="declared"):
    return {"cms": cms, "type": ctype, "slug": slug, "name": slug.title(),
            "version": version, "version_source": source, "path": path}


def db_path(entries, name="vulns.json"):
    path = os.path.join(h.workdir("vulndb-"), name)
    with io.open(path, "w", encoding="utf-8") as fh:
        json.dump({"schema": 2,
                   "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "entries": entries}, fh)
    return path


class DatabaseTest(unittest.TestCase):
    def test_the_template_is_a_valid_empty_database(self):
        doc = ve.db_template()
        self.assertEqual(doc["schema"], 2)
        self.assertEqual(doc["entries"], [])

    def test_a_missing_file_is_a_note_not_a_crash(self):
        entries, problems = ve.load_database(os.path.join(h.workdir("vulndb-"), "nope.json"))
        self.assertEqual(entries, [])
        self.assertTrue(problems)

    def test_a_non_database_is_refused(self):
        for body in ("not json at all", "[]", "{}", '{"schema": 1, "entries": []}',
                     '{"schema": 2}'):
            path = os.path.join(h.workdir("vulndb-"), "db.json")
            with io.open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            with self.subTest(body=body[:24]):
                entries, problems = ve.load_database(path)
                self.assertEqual(entries, [])
                self.assertTrue(problems)

    def test_a_usable_database_is_read(self):
        path = db_path([entry(), entry(cve="CVE-2024-2222", cvss=9.8, kev=True)])
        entries, problems = ve.load_database(path)
        self.assertEqual(len(entries), 2)
        self.assertEqual(problems, [])
        self.assertTrue(entries[1]["kev"])

    def test_a_broken_entry_is_dropped_and_complained_about(self):
        bad = [entry(),
               entry(cve="CVE-2024-2222", cvss=9.8, kev=True),
               entry(cve="<script>"),
               entry(cve="CVE-2024-3333", cms="drupal"),
               entry(cve="CVE-2024-4444", ctype="widget"),
               entry(cve="CVE-2024-5555", component="../../etc"),
               entry(cve="CVE-2024-6666", introduced="soon"),
               entry(cve="CVE-2024-7777", cvss=42),
               {"cve": "CVE-2024-8888", "cms": "wordpress", "type": "plugin",
                "component": "x", "affected": []},
               "not an entry at all"]
        path = db_path(bad)
        entries, problems = ve.load_database(path)
        self.assertEqual([e["cve"] for e in entries], ["CVE-2024-1111", "CVE-2024-2222"])
        self.assertEqual(len(problems), len(bad) - 2, "every dropped entry is reported: %r" % problems)

    def test_an_old_database_says_so(self):
        path = os.path.join(h.workdir("vulndb-"), "old.json")
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump({"schema": 2, "generated": "2020-01-01T00:00:00Z", "entries": []}, fh)
        _entries, problems = ve.load_database(path)
        self.assertTrue(any("old" in p for p in problems), problems)

    def test_an_oversized_database_is_refused(self):
        path = db_path([entry()])
        with io.open(path, "a", encoding="utf-8") as fh:
            fh.write(" " * (ve.DB_MAX_BYTES + 10))
        entries, problems = ve.load_database(path)
        self.assertEqual(entries, [])
        self.assertTrue(any("larger" in p for p in problems))


class LocalAuditTest(unittest.TestCase):
    def _index(self, entries):
        return ve.index_of(entries)

    def test_a_version_inside_the_range_is_reported(self):
        got = ve.audit_local(component(version="5.1"), self._index([entry()]))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["cve"], "CVE-2024-1111")
        self.assertEqual(got[0]["severity"], "high")
        self.assertEqual(got[0]["confidence"], "high")
        self.assertEqual(got[0]["fixed_in"], "5.3")
        self.assertEqual(got[0]["path"], "wp-content/plugins/akismet")

    def test_the_bounds(self):
        index = self._index([entry()])
        self.assertEqual(ve.audit_local(component(version="4.9"), index), [])
        self.assertEqual([f["cve"] for f in ve.audit_local(component(version="5.0"), index)],
                         ["CVE-2024-1111"], "introduced is inclusive")
        self.assertEqual(ve.audit_local(component(version="5.3"), index), [],
                         "fixed is the first version that is no longer affected")

    def test_a_component_that_is_not_in_the_database_is_silent(self):
        self.assertEqual(ve.audit_local(component(slug="other-plugin"), self._index([entry()])), [])

    def test_an_unknown_version_gives_one_honest_record(self):
        entries = [entry(cve="CVE-2024-%04d" % i) for i in range(30)]
        got = ve.audit_local(component(version=""), self._index(entries))
        self.assertEqual(len(got), 1, "an unauditable component is one question, not 30 rows")
        self.assertEqual(got[0]["confidence"], "low")
        self.assertIn("30 vulnerability record", got[0]["summary"])

    def test_an_uncomparable_version_is_not_reported_as_safe(self):
        got = ve.audit_local(component(version="nightly"), self._index([entry()]))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["confidence"], "low")

    def test_an_open_ended_entry_is_medium_confidence(self):
        entries = [entry(introduced="5.0", fixed=None)]
        entries[0]["affected"] = [{"introduced": "5.0"}]
        got = ve.audit_local(component(version="9.9"), self._index(entries))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["confidence"], "medium")
        self.assertIsNone(got[0]["fixed_in"], "no fix has been published")

    def test_a_distrusted_version_file_lowers_the_confidence(self):
        got = ve.audit_local(component(version="5.1"), self._index([entry()]),
                             version_trusted=False)
        self.assertEqual(got[0]["confidence"], "medium")

    def test_severity_bands_and_kev(self):
        index = self._index([entry(cvss=9.9, kev=True), entry(cve="CVE-2024-9999", cvss=4.4)])
        got = ve.audit_local(component(version="5.1"), index)
        by_cve = {f["cve"]: f for f in got}
        self.assertEqual(by_cve["CVE-2024-1111"]["severity"], "critical")
        self.assertTrue(by_cve["CVE-2024-1111"]["kev"])
        self.assertEqual(by_cve["CVE-2024-9999"]["severity"], "medium")

    def test_the_record_is_not_a_file_finding(self):
        got = ve.audit_local(component(version="5.1"), self._index([entry()]))[0]
        for absent in ("line", "hits", "snippet", "score", "sha256", "verdict"):
            self.assertNotIn(absent, got,
                             "a CVE has no %r: it must not look like a file to quarantine" % absent)
        self.assertEqual(set(ve.VULN_FIELDS) - set(got), set())


class FakeClient(object):
    """Stand-in for AuditClient: answers the URLs the engine is allowed to build."""

    def __init__(self, answers):
        self.answers = answers                 # {url substring: payload}
        self.calls = []

    def get_json(self, url, referer_note=""):
        self.calls.append(url)
        for needle, payload in self.answers.items():
            if needle in url:
                if isinstance(payload, Exception):
                    raise payload
                return payload
        raise AssertionError("unexpected request: %s" % url)


def wp_entry(name="akismet < 5.3", min_version="5.0", min_operator="ge",
             max_version="5.3", max_operator="lt", cve="CVE-2024-2000",
             score="7.5", severity="high", kev=False, unfixed="0"):
    impact = {"cvss3": {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "score": score, "severity": severity}}
    if kev:
        impact["ssvc"] = {"exploitation": "active", "kev": True, "kev_date": "2024-05-01"}
    return {"uuid": "x" * 16, "name": name, "description": None,
            "operator": {"min_version": min_version, "min_operator": min_operator,
                         "max_version": max_version, "max_operator": max_operator,
                         "unfixed": unfixed, "closed": "0"},
            "source": [{"id": cve, "name": cve, "link": "https://www.cve.org/",
                        "description": "the test description", "date": "2024-01-01"}],
            "impact": impact}


class OnlineAuditTest(unittest.TestCase):
    def test_a_plugin_range_is_compared_locally(self):
        url = api.wpvuln_url("plugin", "akismet")
        client = FakeClient({"plugin/akismet": {"error": 0, "data": {
            "plugin": "akismet", "vulnerability": [wp_entry()]}}})
        got = ve.audit_online_component(component(version="5.1"), [], client)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["cve"], "CVE-2024-2000")
        self.assertEqual(got[0]["fixed_in"], "5.3")
        self.assertEqual(got[0]["source"], "wpvulnerability")
        self.assertEqual(got[0]["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        self.assertEqual(client.calls, [url])

    def test_a_version_outside_the_range_produces_nothing(self):
        client = FakeClient({"plugin/akismet": {"error": 0, "data": {
            "vulnerability": [wp_entry(max_version="5.3")]}}})
        self.assertEqual(ve.audit_online_component(component(version="6.0"), [], client), [])

    def test_kev_and_no_impact_data(self):
        client = FakeClient({"plugin/akismet": {"error": 0, "data": {
            "vulnerability": [wp_entry(kev=True),
                              dict(uuid="y", name="unscored", operator={"max_version": "9.9",
                                                                        "max_operator": "lt"},
                                   source=[{"id": "1a2f30", "description": "no CVE here"}],
                                   impact=[])]}}})
        got = ve.audit_online_component(component(version="5.1"), [], client)
        by_cve = {f["cve"]: f for f in got}
        self.assertTrue(by_cve["CVE-2024-2000"]["kev"])
        self.assertEqual(by_cve["1a2f30"]["severity"], "unknown")
        self.assertIsNone(by_cve["1a2f30"]["cvss"])

    def test_an_unfixed_entry_has_no_fixed_in_and_only_medium_confidence(self):
        client = FakeClient({"plugin/akismet": {"error": 0, "data": {
            "vulnerability": [wp_entry(max_version=None, max_operator=None, unfixed="1")]}}})
        got = ve.audit_online_component(component(version="5.1"), [], client)
        self.assertEqual(len(got), 1)
        self.assertIsNone(got[0]["fixed_in"])
        self.assertEqual(got[0]["confidence"], "medium")

    def test_a_joomla_component_is_never_sent_to_wordpress(self):
        client = FakeClient({})
        got = ve.audit_online_component(component(cms="joomla", ctype="component",
                                                  slug="com_foobar"), [], client)
        self.assertEqual(got, [])
        self.assertEqual(client.calls, [])

    def test_a_slug_that_is_not_a_slug_is_not_requested(self):
        client = FakeClient({})
        ve.audit_online_component(component(slug="../../config"), [], client)
        ve.audit_online_component(component(slug="Привет"), [], client)
        self.assertEqual(client.calls, [])

    def test_the_core_is_asked_about_by_version(self):
        core = component(slug="core", version="6.4.2", ctype="core", path="wp-includes/")
        client = FakeClient({"core/6.4.2": {"error": 0, "data": {
            "core": "6.4.2", "vulnerability": [
                {"uuid": "z", "name": "6.4.2", "description": None,
                 "source": [{"id": "CVE-2024-3000", "description": "core issue"}],
                 "impact": {"cvss3": {"score": "9.8", "severity": "critical"}}}]}}})
        got = ve.audit_online_component(core, [], client)
        self.assertEqual(client.calls, [api.wpvuln_url("core", "6.4.2")])
        self.assertEqual(got[0]["cve"], "CVE-2024-3000")
        self.assertEqual(got[0]["severity"], "critical")

    def test_a_core_version_that_cannot_be_read_is_asked_about_as_unknown(self):
        core = component(slug="core", version="nightly", ctype="core")
        client = FakeClient({})
        got = ve.audit_online_component(core, [], client)
        self.assertEqual(client.calls, [], "an unreadable version must not become a query")
        self.assertEqual(got[0]["confidence"], "low")

    def test_a_service_failure_is_a_note_not_a_verdict(self):
        client = FakeClient({"plugin/akismet": api.AuditError("wpvulnerability answered HTTP 503")})
        with self.assertRaises(api.AuditError):
            ve.audit_online_component(component(), [], client)


class AuditTest(unittest.TestCase):
    CORE_OK = {"core/6.4.2": {"error": 0, "data": {"core": "6.4.2", "vulnerability": []}}}

    def test_local_and_online_are_combined_and_sorted(self):
        entries = [entry(cve="CVE-2024-1111", cvss=6.0)]
        answers = dict(self.CORE_OK)
        answers["plugin/akismet"] = {"error": 0, "data": {
            "vulnerability": [wp_entry(cve="CVE-2024-2000", score="9.8", severity="critical")]}}
        client = FakeClient(answers)
        inventory = {"cms": "wordpress",
                     "cms_version": {"version": "6.4.2", "source": "declared",
                                     "file": "wp-includes/version.php"},
                     "components": [component()], "problems": []}
        findings, notes = ve.audit(inventory, entries=entries, client=client)
        self.assertEqual([f["cve"] for f in findings], ["CVE-2024-2000", "CVE-2024-1111"],
                         "the most severe first")
        self.assertEqual(notes, [])

    def test_the_wordpress_core_is_audited_as_a_component(self):
        inventory = {"cms": "wordpress",
                     "cms_version": {"version": "6.4.2", "source": "declared",
                                     "file": "wp-includes/version.php"},
                     "components": [], "problems": []}
        entries = [entry(cve="CVE-2023-1000", cms="wordpress", ctype="core",
                         component="core", introduced="6.0", fixed="6.5")]
        findings, _notes = ve.audit(inventory, entries=entries)
        self.assertEqual([f["cve"] for f in findings], ["CVE-2023-1000"])
        self.assertEqual(findings[0]["type"], "core")

    def test_a_service_failure_becomes_a_note_and_the_audit_goes_on(self):
        answers = {"plugin/a": api.AuditError("HTTP 503"),
                   "plugin/b": {"error": 0, "data": {"vulnerability": [wp_entry()]}}}
        answers.update(self.CORE_OK)
        client = FakeClient(answers)
        inventory = {"cms": "wordpress",
                     "cms_version": {"version": "6.4.2", "source": "declared",
                                     "file": "wp-includes/version.php"},
                     "components": [component(slug="a"), component(slug="b")], "problems": []}
        findings, notes = ve.audit(inventory, entries=[], client=client)
        self.assertEqual(len(notes), 1)
        self.assertIn("503", notes[0])
        self.assertIn("plugin a", notes[0])
        self.assertEqual([f["cve"] for f in findings], ["CVE-2024-2000"],
                         "one failing component must not stop the others")

    def test_an_unreadable_core_version_is_reported_not_skipped(self):
        inventory = {"cms": "wordpress",
                     "cms_version": {"version": "nightly", "source": "declared",
                                     "file": "wp-includes/version.php"},
                     "components": [], "problems": []}
        findings, _notes = ve.audit(inventory, entries=[], client=FakeClient({}))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "core")
        self.assertEqual(findings[0]["confidence"], "low")

    def test_a_modified_version_file_makes_every_verdict_a_guess(self):
        inventory = {"cms": "wordpress",
                     "cms_version": {"version": "6.4.2", "source": "declared",
                                     "file": "wp-includes/version.php"},
                     "components": [component()], "problems": []}
        integrity = {"modified": [{"path": "wp-includes/version.php", "expected": "a" * 32,
                                   "actual": "b" * 32}],
                     "extra": [], "missing": []}
        self.assertFalse(ve.version_is_trusted(inventory, integrity))
        findings, notes = ve.audit(inventory, entries=[entry()], integrity=integrity)
        self.assertTrue(all(f["confidence"] != "high" for f in findings), findings)
        self.assertTrue(any("does not match the official release" in n for n in notes))

    def test_an_intact_version_file_is_trusted(self):
        inventory = {"cms": "wordpress",
                     "cms_version": {"version": "6.4.2", "source": "declared",
                                     "file": "wp-includes/version.php"},
                     "components": [component()]}
        self.assertTrue(ve.version_is_trusted(inventory, {"modified": [], "extra": [],
                                                          "missing": []}))

    def test_an_unknown_cms_is_audited_as_nothing(self):
        findings, notes = ve.audit({"cms": "unknown", "cms_version": {}, "components": [],
                                    "problems": ["CMS not identified"]})
        self.assertEqual(findings, [])

    def test_a_joomla_site_is_audited_offline_only(self):
        entries = [entry(cve="JVNA-1234", cms="joomla", ctype="component",
                         component="com_foobar", introduced="1.0", fixed="2.0", cvss=8.1)]
        inventory = {"cms": "joomla", "cms_version": {"version": "4.4.10"},
                     "components": [component(cms="joomla", ctype="component",
                                              slug="com_foobar", version="1.4.2",
                                              path="administrator/components/com_foobar")]}

        class ExplodingClient(object):
            def get_json(self, url, referer_note=""):
                raise AssertionError("an offline audit must not ask anything: " + url)

        findings, _notes = ve.audit(inventory, entries=entries, client=ExplodingClient())
        self.assertEqual([f["cve"] for f in findings], ["JVNA-1234"])
        self.assertEqual(findings[0]["severity"], "high")


class ThresholdTest(unittest.TestCase):
    def _finding(self, severity, confidence="high", kev=False):
        return {"cve": "CVE-2024-0000", "severity": severity, "confidence": confidence,
                "kev": kev, "cvss": 5.0}

    def test_max_severity_ignores_low_confidence(self):
        rows = [self._finding("critical", confidence="low"), self._finding("medium")]
        self.assertEqual(ve.max_severity(rows), "medium")
        self.assertIsNone(ve.max_severity([self._finding("critical", confidence="low")]))

    def test_meets_threshold(self):
        rows = [self._finding("high")]
        self.assertTrue(ve.meets_threshold(rows, "high"))
        self.assertTrue(ve.meets_threshold(rows, "medium"))
        self.assertFalse(ve.meets_threshold(rows, "critical"))
        self.assertFalse(ve.meets_threshold(rows, ""))
        self.assertFalse(ve.meets_threshold(rows, "banana"))

    def test_summarize(self):
        summary = ve.summarize([self._finding("high"), self._finding("medium", kev=True),
                               self._finding("low", confidence="low")], notes=["x"])
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["kev"], 1)
        self.assertEqual(summary["low_confidence"], 1)
        self.assertEqual(summary["by_severity"]["high"], 1)
        self.assertEqual(summary["notes"], ["x"])


if __name__ == "__main__":
    unittest.main()
