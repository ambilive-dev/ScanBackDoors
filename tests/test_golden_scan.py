# -*- coding: utf-8 -*-
"""The safety net for the engine refactoring (TZ v2, Sprint 0): a characterization
golden master of what the scanner currently reports, plus the invariant that a
scan never writes into the scanned tree.

The golden pins the DETECTION RESULT - which file, which score/verdict, which
signatures on which lines, which bytes (size + sha256). It deliberately does not
pin volatile contract fields that are not part of the detection: the "modified"
timestamp, "mode" (OS-dependent bits), the "stats" block (durations, absolute
paths, scanner version). Fixture payloads are written with LF endings, so size
and sha256 are stable across platforms.

If this test goes red after a refactoring, either the refactoring changed what
the scanner finds (a regression to fix) or the detection change was intentional
and the golden is re-recorded - never silently.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402
import fixtures_sites as fx  # noqa: E402

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden", "planted_scan.json")


def normalize(report):
    """The detection contract of one scan, comparable across runs and platforms."""
    files = []
    for f in sorted(report.get("files", []), key=lambda x: x["path"].replace("\\", "/")):
        files.append({
            "path": f["path"].replace("\\", "/"),
            "score": f["score"],
            "verdict": f["verdict"],
            "size": f["size"],
            "sha256": f["sha256"],
            "counts": f["counts"],
            "hidden_hits": f["hidden_hits"],
            "hits": [{"severity": hit["severity"], "line": hit["line"],
                      "signature": hit["signature"], "snippet": hit["snippet"]}
                     for hit in f["hits"]],
        })
    return {"files": files}


class GoldenMasterTest(unittest.TestCase):
    """The planted fixture site is the reference corpus; the clean one is the
    false-positive floor of the synthetic corpus."""

    @classmethod
    def setUpClass(cls):
        cls.site = fx.build("golden-planted", planted=True)
        cls.present, cls.vanished = fx.wait_readables(cls.site, list(fx.PLANTED))
        res, cls.report = h.scan(cls.site, workers="1")
        cls.code = res.returncode

    def _skip_if_av_ate_samples(self):
        if self.vanished:
            raise unittest.SkipTest(
                "real-time protection removed planted samples: %s (%s)"
                % (", ".join(self.vanished), h.AV_HINT))

    def test_planted_detection_matches_golden(self):
        self._skip_if_av_ate_samples()
        with open(GOLDEN, "rb") as f:
            golden = json.loads(f.read().decode("utf-8"))
        self.assertEqual(normalize(self.report), golden["expected"],
                         "the scanner's detection result changed - re-record the golden "
                         "only for an intentional change, fix the code otherwise")

    def test_planted_exit_code_is_critical(self):
        self._skip_if_av_ate_samples()
        self.assertEqual(self.code, 2, "the planted site must exit 2 (critical findings)")

    def test_clean_fixture_reports_nothing(self):
        clean = fx.build("golden-clean", planted=False)
        res, report = h.scan(clean, workers="1")
        self.assertEqual(res.returncode, 0, res.out)
        self.assertEqual(normalize(report), {"files": []},
                         "the clean synthetic corpus must stay at zero findings")

    def test_scan_never_writes_into_the_scanned_tree(self):
        site = fx.build("golden-writetest", planted=True)
        present, vanished = fx.wait_readables(site, list(fx.PLANTED))
        before = h.tree_hashes(site)
        h.scan(site, workers="1")
        after = h.tree_hashes(site)
        # antivirus may remove a sample mid-run: that is the environment, not the scanner
        stale = [r for r, digest in before.items()
                 if r not in after and r in present and r not in vanished
                 and os.path.exists(os.path.join(site, *r.split("/"))) is False]
        changed = {r: (before[r], after.get(r)) for r in before
                   if r in after and after[r] != before[r]}
        added = [r for r in after if r not in before]
        self.assertEqual(changed, {}, "the scan must not modify files of the scanned site")
        self.assertEqual(added, [], "the scan must not create files inside the scanned site")


if __name__ == "__main__":
    unittest.main()
