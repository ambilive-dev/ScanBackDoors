# -*- coding: utf-8 -*-
"""The pipeline core's own behaviour, measured in-process.

Everything here calls the shipped functions and `scan_backdoors.main()` directly.
The CLI is normally driven as a child process (that is how a CLI should be tested,
and tests/test_scanner.py and friends do exactly that), but a child process is
invisible to coverage of this process, so the report writers, the exit-code rules
and the console summary are asserted here as well: they are the part of the pipeline
that decides what an operator reads and what CI sees, and "covered somewhere in a
subprocess" is not a statement anyone can check.

The planted tree comes from the same fixture builder as the golden master, so the
numbers below are about a site that really is found dirty.
"""

import io
import json
import os
import re
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h          # noqa: E402
import fixtures_sites as fx  # noqa: E402

sys.path.insert(0, h.SRC)
import scan_backdoors as sb  # noqa: E402


def run_main(argv):
    """(exit code, stdout) for one in-process run of the scanner."""
    out = io.StringIO()
    old = sys.stdout
    sys.stdout = out
    try:
        code = sb.main(argv)
    finally:
        sys.stdout = old
    return code, out.getvalue()


def base(site, *extra):
    """A run that writes no report files: a case about exit codes or console text must
    not depend on, or pay for, the report writers."""
    return [site, "--no-progress", "--no-csv", "--workers", "1"] + list(extra)


class PlantedSite(unittest.TestCase):
    """One synthetic dirty site, shared read-only by the cases in this class."""

    @classmethod
    def setUpClass(cls):
        cls.site = fx.build("pipeline-inprocess", planted=True)
        present, _vanished = fx.wait_readables(cls.site, list(fx.PLANTED))
        if len(present) < len(fx.PLANTED):
            raise unittest.SkipTest("the antivirus ate fixtures under %s" % cls.site)
        cls.reports = h.workdir("pipeline-reports-")

    def base(self, *extra):
        """A run that writes no report files: a case about exit codes or console text
        must not depend on, or pay for, the report writers."""
        return [self.site, "--no-progress", "--no-csv", "--workers", "1"] + list(extra)

    # ------------------------------------------------------------- report files
    def test_the_three_report_formats_describe_the_same_findings(self):
        paths = {"csv": os.path.join(self.reports, "r.csv"),
                 "json": os.path.join(self.reports, "r.json"),
                 "sarif": os.path.join(self.reports, "r.sarif")}
        code, _ = run_main([self.site, "--no-progress", "--workers", "1",
                            "--csv", paths["csv"], "--json", paths["json"],
                            "--sarif", paths["sarif"]])
        self.assertIn(code, (0, 2), "the scan itself must have run")
        for kind, path in paths.items():
            self.assertTrue(os.path.isfile(path), "%s report was not written" % kind)

        report = h.read_json(paths["json"])
        findings = h.read_csv(paths["csv"])
        with io.open(paths["sarif"], encoding="utf-8") as fh:
            sarif = json.load(fh)
        # The two formats have deliberately different shapes: the CSV is one row per
        # HIT (an operator works through it line by line), the JSON is one object per
        # FILE with its hits inside. What must be identical is the SET OF FILES.
        csv_files = set(row["File"].replace("\\", "/") for row in findings)
        json_files = set(item["path"].replace("\\", "/") for item in report["files"])
        self.assertTrue(json_files, "the planted tree must flag something")
        self.assertEqual(csv_files, json_files,
                         "CSV and JSON must agree about which files are flagged")
        hits = sum(len(item["hits"]) for item in report["files"])
        self.assertEqual(len(findings), hits, "one CSV row per hit")
        results = sarif["runs"][0]["results"]
        # SARIF reports findings, not files: one result per hit at or above the
        # report threshold, so it may exceed the file count but never fall below it
        self.assertGreaterEqual(len(results), len(report["files"]))
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "ScanBackDoors")
        for loc in [l for r in results for l in r["locations"]]:
            uri = loc["physicalLocation"]["artifactLocation"]["uri"]
            self.assertFalse(os.path.isabs(uri), "SARIF locations stay relative: %s" % uri)
            self.assertFalse(uri.startswith("../"), "and stay inside the scanned tree")

    def test_xlsx_is_a_real_workbook_with_the_findings_sheet(self):
        out = os.path.join(self.reports, "r.xlsx")
        code, _ = run_main(self.base("--xlsx", out))
        self.assertIn(code, (0, 2))
        with zipfile.ZipFile(out) as zf:
            names = zf.namelist()
            self.assertIn("xl/workbook.xml", names)
            self.assertIn("xl/worksheets/sheet1.xml", names)
            workbook = zf.read("xl/workbook.xml").decode("utf-8")
            for sheet in ("Files", "Summary"):
                self.assertIn(sheet, workbook,
                              "the workbook must carry the findings sheet and the totals: %s"
                              % workbook[:400])

    # ------------------------------------------------------------- exit codes
    def test_only_critical_and_strict_change_the_exit_code_in_documented_ways(self):
        code, _text = run_main(base(self.site, "--only-critical"))
        self.assertIn(code, (0, 2))
        code_strict, text = run_main(base(self.site, "--strict"))
        # --strict turns an incomplete scan into exit 3; a complete scan of a dirty
        # tree must still be 2, never 3 - otherwise "3" would stop meaning "unreadable"
        self.assertEqual(code_strict, 2,
                         "--strict must not invent a coverage problem that is not there")
        self.assertIn("STATISTICS", text)

    def test_the_summary_numbers_add_up(self):
        code, text = run_main(base(self.site))
        self.assertEqual(code, 2, "the planted tree must report [CRITICAL] findings")
        m = re.search(r"Files visited\s*:\s*(\d+) \(scanned (\d+)\)", text)
        self.assertTrue(m, "the console summary must say what it scanned:\n%s" % text[-600:])
        visited, scanned = int(m.group(1)), int(m.group(2))
        self.assertGreater(visited, 0)
        self.assertLessEqual(scanned, visited,
                             "'scanned' is the part of the tree that was read")
        flagged = int(re.search(r"Files flagged\s*:\s*(\d+)", text).group(1))
        self.assertGreater(flagged, 0, "a planted tree that flags nothing is not measured")

    def test_self_test_passes_and_does_not_touch_the_site(self):
        """`--self-test` is what a support person runs first; it also has to work on
        the oldest interpreter, which is why CI calls it on Python 3.6."""
        before = h.tree_hashes(self.site)
        code, text = run_main(["--self-test"])
        self.assertEqual(code, 0, text[-800:])
        self.assertIn("checks passed", text)
        self.assertEqual(h.tree_hashes(self.site), before,
                         "the self-test works in a temporary folder")


class ArgumentRulesTest(unittest.TestCase):
    """The startup refusals: cheap to state, and the reason an operator's cron job
    does not report 'clean' when it never scanned anything. Each of these prints the
    reason and exits 1 - none of them may write a report that looks like a scan.

    An existing empty folder is the subject of every case here: a run must refuse
    because of the option, not because of the path - the path refusal has its own case.
    """

    @classmethod
    def setUpClass(cls):
        cls.empty = os.path.join(h.workdir("pipeline-arg-"), "site")
        os.makedirs(cls.empty)

    def refuses(self, *extra):
        argv = base(self.empty, *extra)
        code, text = run_main(argv)
        self.assertEqual(code, 1, "expected exit 1 for %s, got %d:\n%s"
                         % (" ".join(extra), code, text[-600:]))
        return text.lower()

    def test_a_missing_folder_is_a_startup_error(self):
        code, text = run_main([os.path.join(h.workdir("pipeline-absent-"), "nope"),
                               "--no-progress"])
        self.assertEqual(code, 1)
        self.assertIn("not found", text.lower())

    def test_a_misread_date_range_is_refused(self):
        """A bare number is not a period: guessing "days" would scan a different tree
        than the one the operator asked for, so `--since` wants `14d` or `2026-09-01`."""
        self.assertIn("invalid --since", self.refuses("--since", "7"))

    def test_an_unreadable_whitelist_is_refused(self):
        """A whitelist that could not be read must not turn into "nothing is
        whitelisted" and then into a report that hides nothing at all."""
        self.assertIn("cannot read the whitelist",
                      self.refuses("--whitelist",
                                   os.path.join(self.empty, "no-such-wl.txt")))

    def test_a_missing_user_signature_library_is_refused(self):
        self.assertIn("cannot read the user signatures",
                      self.refuses("--user-signatures",
                                   os.path.join(self.empty, "no-such-sigs.json")))

    def test_a_missing_baseline_folder_is_refused(self):
        self.assertIn("not found", self.refuses("--baseline-dir",
                                                os.path.join(self.empty, "no-such-clean")))

    def test_fail_on_without_the_audit_is_refused(self):
        self.assertIn("--audit-cve", self.refuses("--fail-on", "high"))


if __name__ == "__main__":
    unittest.main()
