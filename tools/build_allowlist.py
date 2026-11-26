#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a known-clean allowlist for scan_backdoors.py.

Point it at a site you consider clean. It runs the scanner once (to learn which
files are flagged), walks the tree, and writes one line per file in the exact
whitelist format the scanner reads with --whitelist:

    <sha256>  # <relative path>      --format hashes (the default)
    <relative path>                  --format paths

Pass the result back into a later scan to suppress those files:

    python3 src/scan_backdoors.py /path/to/site --whitelist allowlist.txt

By default EVERY file is whitelisted (this is a "whitelist a known-clean
baseline" tool - you are asserting the site is clean). Use --skip-matching and
--min-score to narrow the list if the site still carries findings you do not
want to pin.

Hashes are exact content matches: if a whitelisted file is later modified its
SHA-256 changes and it is re-scanned (a good safety property for a baseline).

Standard library only, Python 3.6+.
"""

import argparse
import datetime
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile

PROG = "build_allowlist"


def repo_root():
    # tools/build_allowlist.py -> <repo>/tools -> <repo>
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def scanner_path():
    p = os.path.join(repo_root(), "src", "scan_backdoors.py")
    if not os.path.isfile(p):
        sys.exit("%s: cannot find the scanner at %s" % (PROG, p))
    return p


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_flags(scanner, site):
    """Run the scanner once -> ({rel_path: (score, n_hits)}, version).

    The scanner only reports files that have at least one finding, so a file
    absent from the map is clean (score 0, 0 hits). A non-zero exit code just
    means it found something - expected here; we only need the JSON report.
    """
    fd, tmp = tempfile.mkstemp(suffix=".json", prefix="sbd-allowlist-")
    os.close(fd)
    try:
        subprocess.run(
            [sys.executable, scanner, site, "--json", tmp,
             "--no-csv", "--no-progress", "--workers", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with io.open(tmp, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        sys.exit("%s: the scanner did not produce a readable report: %s" % (PROG, e))
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    flags = {r["path"].replace("\\", "/"): (r.get("score", 0), len(r.get("hits", [])))
             for r in data.get("files", [])}
    return flags, data.get("version", "?")


def collect(site, flags, fmt, min_score, skip_matching):
    """Walk the site, apply the filters, return (sorted lines, stats)."""
    entries = []
    seen = skipped_match = skipped_score = flagged_kept = 0
    for root, _dirs, files in os.walk(site):
        for n in files:
            p = os.path.join(root, n)
            rel = os.path.relpath(p, site).replace(os.sep, "/")
            seen += 1
            score, hits = flags.get(rel, (0, 0))
            if skip_matching and hits > 0:
                skipped_match += 1
                continue
            if min_score is not None and score >= min_score:
                skipped_score += 1
                continue
            if score > 0:
                flagged_kept += 1
            if fmt == "hashes":
                try:
                    line = "%s  # %s" % (sha256_file(p), rel)
                except OSError:
                    continue          # unreadable file: cannot hash it, skip
            else:
                line = rel
            entries.append((rel, line))
    entries.sort(key=lambda t: t[0])
    stats = {"seen": seen, "whitelisted": len(entries),
             "skipped_matching": skipped_match, "skipped_score": skipped_score,
             "flagged_kept": flagged_kept}
    return [line for _rel, line in entries], stats


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog=PROG,
        description="Build a known-clean allowlist (SHA-256 or paths) for "
                    "scan_backdoors.py --whitelist.")
    ap.add_argument("site", help="folder with the site to whitelist (it must be clean)")
    ap.add_argument("--format", choices=["hashes", "paths"], default="hashes",
                    help="what to write per file (default: hashes - exact SHA-256)")
    ap.add_argument("--min-score", type=int, default=None, metavar="N",
                    help="only whitelist files with a score < N (default: no limit)")
    ap.add_argument("--skip-matching", action="store_true",
                    help="only whitelist files the scanner reports no finding for")
    ap.add_argument("--out", default=None,
                    help="output file (default: standard output; '-' also means stdout)")
    ap.add_argument("--quiet", action="store_true", help="no progress on stderr")
    args = ap.parse_args(argv)

    site = os.path.abspath(args.site)
    if not os.path.isdir(site):
        sys.exit("%s: folder not found: %s" % (PROG, site))

    def log(msg):
        if not args.quiet:
            sys.stderr.write(msg + "\n")

    log("scanning %s (to learn which files are flagged) ..." % site)
    flags, version = scan_flags(scanner_path(), site)
    lines, stats = collect(site, flags, args.format, args.min_score, args.skip_matching)

    header = [
        "# Scan Backdoors - known-clean allowlist",
        "#",
        "# generated by %s v%s from %s on %s" % (
            PROG, version, site, datetime.date.today().strftime("%Y-%m-%d")),
        "# format: %s | files seen: %d | whitelisted: %d" % (
            args.format, stats["seen"], stats["whitelisted"]),
        "# filters: min-score=%s skip-matching=%s" % (
            args.min_score if args.min_score is not None else "off",
            "on" if args.skip_matching else "off"),
        "# use it with:  python3 src/scan_backdoors.py <site> --whitelist <this-file>",
        "",
    ]
    body = "\n".join(header + lines) + ("\n" if lines else "")

    if args.out and args.out != "-":
        out = os.path.abspath(args.out)
        parent = os.path.dirname(out)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with io.open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
        log("wrote %d line(s) to %s" % (len(lines), out))
    else:
        sys.stdout.write(body)
        log("wrote %d line(s) to standard output" % len(lines))

    note = "whitelisted %d of %d file(s)" % (stats["whitelisted"], stats["seen"])
    if stats["skipped_matching"]:
        note += "  (%d skipped: they have findings)" % stats["skipped_matching"]
    if stats["skipped_score"]:
        note += "  (%d skipped: score >= %s)" % (stats["skipped_score"], args.min_score)
    sys.stderr.write(note + "\n")
    if stats["flagged_kept"]:
        sys.stderr.write(
            "WARNING: %d file(s) carry findings yet are whitelisted - verify the site "
            "really is clean before trusting this list.\n" % stats["flagged_kept"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
