#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Measure the false-positive profile of the scanner over clean corpus folders.

The number Sprint 1+ must not regress: scanned/flagged/by-level counts and the
per-signature hit census over corpora that contain NO known malware. Re-running
this on the same corpora and scanner version must reproduce the same JSON (the
output carries no timestamps), so `git diff` on the baseline file is the whole
regression report.

    python tools/fp_measure.py <clean-dir> [<clean-dir> ...] --out tests/golden/fp_baseline_synthetic.json

Corpus policy (TZ v2 §5.1 p.4): the real clean-CMS corpus is a separate study
(licences, integrity, size) - see docs/OPEN_QUESTIONS.md. Until it is decided,
the baseline is recorded on the synthetic clean fixture of tests/fixtures_sites.py
and on the fetched Joomla baseline tree when one is available locally.
"""
from __future__ import print_function

import argparse
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SCANNER = os.path.join(REPO, "src", "scan_backdoors.py")


def scan_one(folder, workers):
    fd, json_path = tempfile.mkstemp(suffix=".json", prefix="fp-report-")
    os.close(fd)
    os.remove(json_path)
    cmd = [sys.executable, "-u", SCANNER, folder, "--no-progress", "--no-csv",
           "--workers", str(workers), "--json", json_path]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    res = subprocess.call(cmd, env=env)
    if not os.path.isfile(json_path):
        raise SystemExit("scanner failed on %s (exit %d)" % (folder, res))
    with io.open(json_path, "rb") as f:
        report = json.loads(f.read().decode("utf-8-sig"))
    os.remove(json_path)
    return report


def measure(folder, workers):
    report = scan_one(folder, workers)
    by_sig, by_level = {}, {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    flagged = 0
    for f in report.get("files", []):
        flagged += 1
        by_level[f["verdict"]] = by_level.get(f["verdict"], 0) + 1
        for hit in f["hits"]:
            by_sig[hit["signature"]] = by_sig.get(hit["signature"], 0) + 1
    stats = report.get("stats", {})
    return {
        "label": os.path.basename(os.path.abspath(folder).rstrip("\\/")) or str(folder),
        "files_visited": stats.get("Files visited", 0),
        "files_flagged": flagged,
        "by_level": by_level,
        "by_signature": dict(sorted(by_sig.items())),
    }


def main():
    ap = argparse.ArgumentParser(description="record the scanner's clean-corpus (FP) baseline")
    ap.add_argument("corpus", nargs="+", help="folder that contains no known malware")
    ap.add_argument("--out", default=None, help="where to write the baseline JSON")
    ap.add_argument("--workers", default="1", help="scanner workers (1 = deterministic)")
    args = ap.parse_args()

    corpora = []
    totals = {"files_visited": 0, "files_flagged": 0,
              "by_level": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}, "by_signature": {}}
    for folder in args.corpus:
        if not os.path.isdir(folder):
            raise SystemExit("not a folder: %s" % folder)
        got = measure(folder, args.workers)
        corpora.append(got)
        totals["files_visited"] += got["files_visited"]
        totals["files_flagged"] += got["files_flagged"]
        for k, v in got["by_level"].items():
            totals["by_level"][k] = totals["by_level"].get(k, 0) + v
        for k, v in got["by_signature"].items():
            totals["by_signature"][k] = totals["by_signature"].get(k, 0) + v

    data = {
        "_comment": "False-positive baseline over clean corpora: detections the scanner "
                    "reports on files with no known malware. Compare after every signature/"
                    "engine change. Regenerate: see the header of tools/fp_measure.py.",
        "corpora": corpora,
        "totals": {"files_visited": totals["files_visited"],
                   "files_flagged": totals["files_flagged"],
                   "by_level": dict(sorted(totals["by_level"].items())),
                   "by_signature": dict(sorted(totals["by_signature"].items()))},
    }
    text = json.dumps(data, ensure_ascii=False, indent=1, sort_keys=False) + "\n"
    if args.out:
        with io.open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("wrote %s (%d files visited, %d flagged)"
              % (args.out, totals["files_visited"], totals["files_flagged"]))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
