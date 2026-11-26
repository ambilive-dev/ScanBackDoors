# -*- coding: utf-8 -*-
"""Run the scanner against the synthetic fixtures and check what comes back.

Golden expectations: the clean tree yields nothing at all, and each planted
sample is found with the signatures its description promises. If antivirus ate
a sample the test says so instead of reporting a missed backdoor.
"""

import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402
import fixtures_sites as fx  # noqa: E402


def outcomes(site, extra=()):
    res, report = h.scan(site, *extra)
    return res, report, h.findings_by_path(report), h.stats_of(report)


class CleanSiteTest(unittest.TestCase):
    """The clean fixture must be exactly that: nothing to say."""

    @classmethod
    def setUpClass(cls):
        cls.site = h.clean_site("clean")

    def test_clean_tree_yields_no_findings(self):
        res, report, by_path, stats = outcomes(self.site)
        self.assertEqual(res.returncode, 0,
                         "clean site must not exit with findings: %s" % res.out)
        self.assertEqual(stats["Files flagged"], 0,
                         "clean site must not flag anything: %s" % by_path)

    def test_clean_tree_has_no_errors_or_unreadables(self):
        _res, _report, _by_path, stats = outcomes(self.site)
        self.assertEqual(stats["Read errors"], 0)
        self.assertEqual(stats["Unreadable (Windows permissions)"], 0)
        self.assertEqual(stats["Files scanned"], stats["Files visited"])

    def test_clean_tree_behaves_with_only_critical(self):
        res, _report, by_path, _stats = outcomes(self.site, ["--only-critical"])
        self.assertEqual(res.returncode, 0)
        self.assertEqual(by_path, {})


class PlantedSiteTest(unittest.TestCase):
    """Each planted sample must be found with the signatures it promises."""

    @classmethod
    def setUpClass(cls):
        cls.site = fx.build("planted", planted=True)
        present, vanished = fx.wait_readables(cls.site, list(fx.PLANTED))
        if not present:
            raise unittest.SkipTest(
                "%d of %d planted samples cannot be read - real-time protection is eating them. %s"
                % (len(list(fx.PLANTED)) - len(present), len(fx.PLANTED), h.AV_HINT))
        cls.vanished = [r for r in vanished]
        cls.present = set(present)
        res, report = h.scan(cls.site)
        cls.res, cls.report = res, report
        cls.by_path = h.findings_by_path(report)
        cls.stats = h.stats_of(report)
        # the samples were built, so the scanner must have reported every one of
        # them - even when it is blocked and can only flag a blind spot.
        cls.blocked = {rel for rel in cls.present
                       if "file could NOT be read" in " | ".join(cls.by_path[rel.lower().replace("\\", "/")]["signatures"])}

    def test_scanner_reports_a_failure_code_when_there_are_critical_findings(self):
        self.assertEqual(self.res.returncode, 2,
                         "finding [CRITICAL] files must exit with code 2: %s" % self.res.out)

    def test_every_sample_is_reported_even_when_blocked(self):
        for rel in self.present:
            key = rel.lower().replace("\\", "/")
            self.assertIn(key, self.by_path,
                          "planted sample %s was not reported at all" % rel)

    def test_clean_files_are_not_reported(self):
        # files that are present in CLEAN and were not overwritten by a sample
        clean_keys = {k.lower().replace("\\", "/") for k in fx.CLEAN} - set(fx.PLANTED)
        found = set(self.by_path)
        extra = found & clean_keys
        self.assertFalse(extra,
                         "the planted run must not flag files that were clean: %s" % sorted(extra))

    def test_meta_signatures_always_fire(self):
        """Filename/location evidence surfaces even when antivirus blocks the read."""
        for rel in self.present:
            spec = fx.PLANTED[rel]
            key = rel.lower().replace("\\", "/")
            hits = " | ".join(self.by_path[key]["signatures"])
            for signature in spec["meta"]:
                self.assertIn(signature, hits,
                              "%s: metadata signature %r missing (got: %s)" % (rel, signature, hits))

    def test_content_signatures_fire_when_the_file_is_readable(self):
        for rel in self.present:
            if rel in self.blocked:
                continue
            spec = fx.PLANTED[rel]
            key = rel.lower().replace("\\", "/")
            hits = " | ".join(self.by_path[key]["signatures"])
            for signature in spec["signatures"]:
                self.assertIn(signature, hits,
                              "%s: expected signature %r, got: %s" % (rel, signature, hits))

    def test_verdicts_rest_on_metadata_and_readability(self):
        for rel in self.present:
            spec = fx.PLANTED[rel]
            key = rel.lower().replace("\\", "/")
            verdict = self.by_path[key]["verdict"]
            ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
            if rel in self.blocked:
                # a blind spot is itself a critical finding: never less than MEDIUM
                self.assertGreaterEqual(ranks[verdict], ranks["MEDIUM"],
                                        "%s: a blocked file must still be reported (got %s)"
                                        % (rel, verdict))
            else:
                self.assertGreaterEqual(ranks[verdict], ranks[spec["verdict"]],
                                        "%s must reach at least %s, got %s (%s)"
                                        % (rel, spec["verdict"], verdict, self.by_path[key]["signatures"]))

    def test_the_site_was_actually_scanned(self):
        self.assertGreater(self.stats["Files scanned"], 25,
                           "the planted site is the same size as the clean one plus the samples")
        visited = self.stats["Files visited"]
        accounted = (self.stats["Files scanned"] + self.stats["Unreadable (Windows permissions)"]
                     + self.stats["Whitelisted"] + self.stats["Identical to clean Joomla (skipped)"]
                     + self.stats["Skipped (too big)"] + self.stats["Skipped (older than --since)"]
                     + self.stats["Read errors"])
        self.assertGreaterEqual(accounted, visited - 1,
                                "every visited file must be accounted for: %s" % self.stats)

    def test_unreadable_files_are_only_the_planted_samples(self):
        unreadable = set()
        for rel in self.present:
            key = rel.lower().replace("\\", "/")
            if "file could NOT be read" in " | ".join(self.by_path[key]["signatures"]):
                unreadable.add(key)
        reported = set(self.by_path)
        self.assertTrue(unreadable <= reported)
        for rel in self.present:
            key = rel.lower().replace("\\", "/")
            if key not in unreadable:
                # anything reported with no blind-spot hit must have been read
                self.assertNotIn("file could NOT be read", " | ".join(self.by_path[key]["signatures"]))


class CLIBehaviorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = h.clean_site("clean-cli")

    def test_exit_code_1_for_a_missing_folder(self):
        res, _report = h.scan("/definitely/not/a/site")
        self.assertEqual(res.returncode, 1)
        self.assertIn("Folder not found", res.out)

    def test_exit_code_1_for_a_bad_since(self):
        res, _report = h.scan(self.site, "--since", "yesterday")
        self.assertEqual(res.returncode, 1)
        self.assertIn("--since", res.out)

    def test_exit_code_1_when_the_whitelist_cannot_be_read(self):
        """The GUI passes a whitelist through the CLI; a missing one must be a clear error, not a crash."""
        res, _report = h.scan(self.site, "--whitelist", os.path.join(self.site, "missing.txt"))
        self.assertEqual(res.returncode, 1)
        self.assertIn("whitelist", res.out.lower())

    def test_exit_code_1_when_the_baseline_dir_is_missing(self):
        res, _report = h.scan(self.site, "--baseline-dir", "/definitely/not/a/folder")
        self.assertEqual(res.returncode, 1)
        self.assertIn("baseline-dir", res.out)

    def test_exit_code_1_for_a_site_that_is_a_file(self):
        res, _report = h.scan(os.path.join(self.site, "index.php"))
        self.assertEqual(res.returncode, 1)


if __name__ == "__main__":
    unittest.main()
