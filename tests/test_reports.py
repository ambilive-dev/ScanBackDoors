# -*- coding: utf-8 -*-
"""The CLI's output contract: files, exit codes and the machine-readable markers."""

import csv
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402
import fixtures_sites as fx  # noqa: E402


def load_json(path):
    with io.open(path, encoding="utf-8") as f:
        return json.load(f)

class OutputContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sbd-reports-")
        cls.site = fx.build("planted-reports", planted=True, binaries=True)
        cls.present, _vanished = fx.wait_readables(cls.site, list(fx.PLANTED))
        if len(cls.present) < 3:
            raise unittest.SkipTest("%d samples survived: %s" % (len(cls.present), h.AV_HINT))

    def reports(self, *extra):
        csv_path = os.path.join(self.tmp, "report.csv")
        json_path = os.path.join(self.tmp, "report.json")
        xlsx_path = os.path.join(self.tmp, "report.xlsx")
        cmd = [self.site, "--csv", csv_path, "--json", json_path, "--xlsx", xlsx_path] + list(extra)
        res = h.run("scan_backdoors.py", cmd)
        return res, csv_path, json_path, xlsx_path

    def test_csv_is_written_and_parseable(self):
        res, csv_path, _json_path, _xlsx = self.reports()
        self.assertEqual(res.returncode, 2)           # findings are expected
        self.assertTrue(os.path.isfile(csv_path))
        with io.open(csv_path, encoding="utf-8-sig") as f:
            rows = list(csv.reader(f))
        self.assertTrue(rows, "CSV has no header")
        header = [c.lower() for c in rows[0]]
        self.assertIn("verdict", header)
        self.assertIn("file", header)

    def test_json_is_valid_and_reports_the_bundle_version(self):
        _res, _csv, json_path, _xlsx = self.reports()
        report = load_json(json_path)
        self.assertEqual(report["version"], h.bundle_version())
        self.assertIn("stats", report)
        self.assertIsInstance(report["files"], list)

    def test_xlsx_is_a_valid_zip_with_a_worksheet(self):
        import zipfile
        _res, _csv, _json, xlsx_path = self.reports()
        self.assertTrue(zipfile.is_zipfile(xlsx_path), "report.xlsx is not a zip")
        with zipfile.ZipFile(xlsx_path) as z:
            names = z.namelist()
        self.assertIn("xl/worksheets/sheet1.xml", names)

    def test_progress_lines_carry_the_gui_contract(self):
        csv_path = os.path.join(self.tmp, "pl.csv")
        res = h.run("scan_backdoors.py", [self.site, "--progress-lines", "--csv", csv_path])
        self.assertIn("@@STATS", res.out)
        self.assertIn("@@DONE", res.out)
        self.assertIn("@@PHASE", res.out)
        stats_line = [ln for ln in res.lines() if ln.startswith("@@STATS")][0]
        stats = json.loads(stats_line[len("@@STATS "):])
        self.assertEqual(stats["Files visited"], max(1, stats["Files visited"]))
        self.assertEqual(res.markers("DONE")[0].isdigit(), True)

    def test_workers_change_the_speed_not_the_result(self):
        res_1, _c, json_1, _x = self.reports("--workers", "1")
        res_2, _c, json_2, _x = self.reports("--workers", "2")
        self.assertEqual(res_1.returncode, res_2.returncode)
        report_1 = load_json(json_1)
        report_2 = load_json(json_2)
        self.assertEqual(report_1["stats"]["Files flagged"], report_2["stats"]["Files flagged"])
        self.assertEqual(len(report_1["files"]), len(report_2["files"]))

    def test_only_critical_shows_less_than_the_full_report(self):
        res_full, _c, json_full, _x = self.reports()
        res_crit, _c, json_crit, _x = self.reports("--only-critical")
        report_full = load_json(json_full)
        report_crit = load_json(json_crit)
        self.assertLessEqual(report_crit["stats"]["Files flagged"], report_full["stats"]["Files flagged"])
        self.assertEqual(res_full.returncode, res_crit.returncode)

    def test_exclude_dir_removes_samples(self):
        res_all, _c, _j, _x = self.reports()
        res_exc, _c, json_exc, _x = self.reports("--exclude-dir", "media")
        report_exc = load_json(json_exc)
        media = [f for f in report_exc["files"] if f["path"].replace("\\", "/").lower().startswith("media/")]
        self.assertEqual(media, [])

    def test_no_csv_silences_the_default_report(self):
        res = h.run("scan_backdoors.py", [self.site, "--no-csv", "--json",
                                         os.path.join(self.tmp, "nc.json")])
        self.assertNotIn("CSV :", res.out)


class WhitelistBehaviourTest(unittest.TestCase):
    """--whitelist suppresses the findings it names.

    The hash-based whitelist only applies to files the scanner can really
    read, so the target must survive the scan; the path-based one is checked
    before the file is touched at all.
    """

    @classmethod
    def setUpClass(cls):
        cls.site = fx.build("planted-wl", planted=True, binaries=True)
        cls.present, _v = fx.wait_readables(cls.site, list(fx.PLANTED))
        if not cls.present:
            raise unittest.SkipTest("no planted samples survived: %s" % h.AV_HINT)
        cls.res_full, cls.report_full = h.scan(cls.site)
        by_path = h.findings_by_path(cls.report_full)
        cls.readable = []
        for rel in cls.present:
            key = rel.lower().replace("\\", "/")
            if key not in by_path:
                continue
            if "file could NOT be read" in " | ".join(by_path[key]["signatures"]):
                continue
            cls.readable.append(rel)

    def test_hash_whitelist_suppresses_a_finding(self):
        import hashlib
        if not self.readable:
            raise unittest.SkipTest("all planted samples were blocked by antivirus: %s" % h.AV_HINT)
        key = self.readable[0].lower().replace("\\", "/")
        sha = hashlib.sha256(fx.payload(fx.PLANTED[self.readable[0]]["payload"])).hexdigest()
        wl = os.path.join(tempfile.mkdtemp(prefix="sbd-wl-"), "wl.txt")
        with io.open(wl, "w", encoding="utf-8") as f:
            f.write("%s\n" % sha)
        res_wl, report_wl = h.scan(self.site, "--whitelist", wl)
        self.assertIn(key, set(h.findings_by_path(self.report_full)),
                      "the sample must be reported before the whitelisted run")
        self.assertNotIn(key, set(h.findings_by_path(report_wl)),
                         "the whitelisted sample must not be reported")
        self.assertGreaterEqual(h.stats_of(report_wl)["Whitelisted"], 1)

    def test_path_whitelist_suppresses_a_whole_folder(self):
        target = self.present[0]
        folder = target.split("/")[0]
        wl = os.path.join(tempfile.mkdtemp(prefix="sbd-wl-"), "wl.txt")
        with io.open(wl, "w", encoding="utf-8") as f:
            f.write("%s/\n" % folder)
        _res, report = h.scan(self.site, "--whitelist", wl)
        key = target.lower().replace("\\", "/")
        self.assertNotIn(key, set(h.findings_by_path(report)))


if __name__ == "__main__":
    unittest.main()
