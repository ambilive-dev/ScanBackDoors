# -*- coding: utf-8 -*-
"""--self-test: the built-in liveness check of each script (black-box)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402


class ScannerSelfTest(unittest.TestCase):
    def test_selftest_passes(self):
        res = h.run("scan_backdoors.py", ["--self-test"], timeout=180)
        self.assertEqual(res.returncode, 0, res.out)
        self.assertIn("self-test: 4 of 4 checks passed", res.out)
        self.assertNotIn("[FAIL]", res.out)
