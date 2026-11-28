#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-record the detection golden master (tests/golden/planted_scan.json).

Run this only when a detection change is INTENTIONAL; it rewrites the contract
the safety-net test (tests/test_golden_scan.py) checks. Read the diff it produces
before committing: every added/removed/changed finding must be one you meant.

    python tools/record_golden.py
"""
from __future__ import print_function

import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TESTS = os.path.join(REPO, "tests")
sys.path.insert(0, TESTS)

import harness as h                       # noqa: E402
import fixtures_sites as fx               # noqa: E402
from test_golden_scan import normalize     # noqa: E402


def main():
    site = fx.build("golden-planted", planted=True)
    _present, vanished = fx.wait_readables(site, list(fx.PLANTED))
    if vanished:
        print("WARNING: real-time protection removed samples: %s" % ", ".join(vanished))
        print("The golden may be incomplete; re-run with AV exclusion for %s" % fx.fixtures_root())
    _res, report = h.scan(site, workers="1")
    golden = {
        "_comment": "Detection golden master for the planted synthetic fixture "
                    "(tests/fixtures_sites.py). Re-record only for an intentional detection "
                    "change: python tools/record_golden.py",
        "corpus": "fixtures_sites.build('planted=True') with every PLANTED sample readable",
        "expected": normalize(report),
    }
    outdir = os.path.join(TESTS, "golden")
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    path = os.path.join(outdir, "planted_scan.json")
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(golden, f, ensure_ascii=False, indent=1, sort_keys=False)
        f.write("\n")
    print("wrote %s: %d flagged files, %d hits" % (
        path, len(golden["expected"]["files"]),
        sum(len(x["hits"]) for x in golden["expected"]["files"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
