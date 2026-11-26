# -*- coding: utf-8 -*-
"""A corrupted whitelist file: every bad line is named, the scan still runs."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402


class WhitelistProblemsTest(unittest.TestCase):
    def _wl(self, content):
        fd, path = h.workfile("sbd-wl-prob-", ".txt")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self.addCleanup(os.remove, path)
        return path

    def test_malformed_lines_are_reported_and_scan_continues(self):
        site = h.clean_site("wl-problems")
        wl = self._wl("# a comment\n" + "a" * 64 + "\ndeadbeef\n"
                      "\x00\x01binary garbage\x02\nlibraries/vendor/\n")
        res, _report = h.scan(site, "--whitelist", wl)
        self.assertEqual(res.returncode, 0, res.out)
        self.assertIn("whitelist: line 3: hex string with 8 chars", res.out)
        self.assertIn("whitelist: line 4: unprintable", res.out)
        self.assertNotIn("line 5:", res.out)      # a folder entry is fine
        self.assertIn("2 malformed line(s)", res.out)

    def test_cleaner_reports_malformed_whitelist_too(self):
        site = h.clean_site("wl-problems-cleaner")
        fd, report = h.workfile("sbd-wl-prob-report-", ".csv")
        os.close(fd)
        os.remove(report)
        wl = self._wl("# a comment\n" + "a" * 64 + "\ndeadbeef\n"
                      "\x00\x01binary garbage\x02\nlibraries/vendor/\n")
        res = h.run("clean_malware.py", [site, "--whitelist", wl, "--report", report], timeout=180)
        self.assertEqual(res.returncode, 0, res.out)
        self.assertIn("whitelist: line 3: hex string with 8 chars", res.out)
        self.assertIn("2 malformed line(s)", res.out)
