#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run the test suite with coverage of the whole process family, not just the parent.

Why this exists
---------------
`python -m coverage run -m unittest discover ...` is the usual recipe and it reports
nonsense here: most of this project is driven through a subprocess (the tests launch
the CLI, the GUI and the cleaner the way a user does), and the usual recipe traces the
parent only. The same code measured with and without the children differs by a factor
of two - 57 % for src/scan_backdoors.py against 94 %. A number like that is worse than
no number: it invites someone to "improve coverage" by testing what is already tested
from the other side of a process boundary.

A child process is only traced if coverage is started inside it, before anything else
imports. coverage.py supports exactly that: `coverage.process_startup()` reads
COVERAGE_PROCESS_START and starts tracing, and Python imports `sitecustomize` at
interpreter start-up. So this script:

  1. puts a scratch directory containing one sitecustomize.py at the front of
     PYTHONPATH and exports COVERAGE_PROCESS_START pointing at a generated config;
  2. points COVERAGE_FILE at an absolute path **outside every tree the tests write
     to**. That is not tidiness: the child processes have their own working
     directories, and a relative data file means `.coverage.<host>.<pid>` files
     appearing inside the fixture sites - which then show up as unknown files in the
     very reports the tests assert about;
  3. runs the command it was given (the test suite by default);
  4. combines the family's data files and prints the report, failing below --require.

Nothing is installed into site-packages and nothing is left behind in the repository:
the hook lives in a temporary directory that Python deletes, and the data files live in
--data-dir. The price of the honest measurement is that the interpreter on the other
side of the boundary must be able to import `coverage` - so run this with the same
interpreter that has it (see requirements-dev.txt).

Usage
-----
    python tools/coverage_run.py                        # suite + report
    python tools/coverage_run.py --require 70           # the CI gate
    python tools/coverage_run.py -m unittest tests.test_scanner
    python tools/coverage_run.py --data-dir /tmp/cov --report-only

Standard library only, Python 3.6+.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO, ".coveragerc")

# The runtime configuration for the measurement. It is generated with **absolute**
# source paths instead of reusing the repository's .coveragerc, and that is not
# decoration: [run] source resolves relative to the CWD of the process that reads it,
# and this project's child processes do not share the parent's CWD - tests/harness.py
# launches the CLI with cwd=src/. A child given "source = src" therefore looks for
# <repo>/src/src, finds nothing, and measures nothing: the result is a report where
# src/clean_malware.py and src/scan_backdoors_gui.py read 0.0 % although the
# end-to-end tests drive them hard. Absolute paths mean every process in the family
# measures the same files.
RUNTIME_CONFIG = """\
[run]
branch = True
parallel = True
source =
    {src}
    {engines}

[report]
precision = 1
omit =
    tests/*
"""

# Written into a scratch directory that is put on PYTHONPATH. It has to be defensive:
# this runs at the start of EVERY Python process the tests spawn, including ones where
# coverage is not installed or another COVERAGE_PROCESS_START was already in effect.
SITECUSTOMIZE = '''\
"""Added to sys.path by tools/coverage_run.py - see that file for why."""
try:
    import coverage
except ImportError:      # a child interpreter without coverage: measure nothing
    pass
else:
    try:
        coverage.process_startup()
    except Exception:    # a broken config must not break the program under test
        pass
'''


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="coverage over the whole process family")
    ap.add_argument("--data-dir", default=None,
                    help="where to keep the coverage data files (default: a temporary "
                         "directory). Must be outside every tree the tests write to.")
    ap.add_argument("--require", type=float, default=None,
                    help="exit 1 if total branch coverage is below this percent")
    ap.add_argument("--core", action="append", default=[], metavar="PREFIX",
                    help="a module or directory (repo-relative, e.g. engines or "
                         "src/scan_backdoors.py) that must reach --require on its own; "
                         "repeatable. TZ v2 9.1 asks for the pipeline core, not for an "
                         "average that a well-tested corner can pay for")
    ap.add_argument("--report-only", action="store_true",
                    help="skip the run: combine and report what --data-dir already holds")
    ap.add_argument("--keep", action="store_true",
                    help="keep the data files instead of removing them after the report")
    ap.add_argument("--show", choices=("total", "short", "full"), default="short",
                    help="report style (default: one line per module)")
    ap.add_argument("command", nargs=argparse.REMAINDER,
                    help="command to run (default: the unittest suite)")
    return ap.parse_args(argv)


def _outside_trees(path):
    """Refuse a data directory inside a tree the tests write into.

    `--data-dir` inside the fixtures root means a `.coverage.<host>.<pid>` file inside a
    site the tests are scanning: it is read back as an unknown file in the report a test
    then asserts about, and the failure mentions neither coverage nor the flag. Inside
    the checkout it is worse - tests/test_release.py walks the tree, and the self-scan
    job in CI scans it.
    """
    real = os.path.realpath(path)
    candidates = [os.path.realpath(os.environ.get("SBD_FIXTURE_ROOT")
                                   or os.path.join(tempfile.gettempdir(), "sbd-fixtures")),
                  os.path.realpath(REPO)]
    for bad in candidates:
        if real == bad or real.startswith(bad + os.sep):
            sys.stderr.write("ERROR: --data-dir is inside a tree the tests write to "
                             "(%s).\nCoverage data files would be scanned as files of "
                             "the site. Choose a folder of its own.\n" % bad)
            return None
    return real


def _subset_percent(data, prefix):
    """The percentage of one part of the tree, summed the way coverage sums it.

    Not an average of the per-file numbers: a 1500-line file and a 2-line file are not
    equally important, and an average is how a well-tested corner hides an untested
    core. `prefix` is repo-relative, and a directory prefix covers everything under it.
    """
    want = os.path.normcase(os.path.abspath(os.path.join(REPO, prefix)))
    total = covered = 0
    for path, info in data["files"].items():
        real = os.path.normcase(os.path.abspath(path))
        if not (real == want or real.startswith(want + os.sep)):
            continue
        summary = info["summary"]
        # coverage's own arithmetic: a measured line and a taken branch count once each
        total += summary["num_statements"] + summary.get("num_branches", 0)
        covered += (summary["num_statements"] - summary["missing_lines"]
                    + summary.get("covered_branches", 0))
    if not total:
        return None
    return 100.0 * covered / total


def main(argv=None):
    args = parse_args(argv)
    if not os.path.isdir(os.path.join(REPO, "src")):
        sys.stderr.write("ERROR: %s does not look like this repository\n" % REPO)
        return 2

    if args.data_dir:
        data_root = os.path.abspath(args.data_dir)
        if not os.path.isdir(data_root):
            os.makedirs(data_root)
        data_root = _outside_trees(data_root)
        if data_root is None:
            return 2
        keep_dir = True                      # a folder someone named is never deleted
    else:
        data_root = tempfile.mkdtemp(prefix="sbd-coverage-")
        keep_dir = args.keep

    data_file = os.path.join(data_root, ".cov")          # combine adds the suffixes
    hook_dir = os.path.join(data_root, "_hook")
    os.makedirs(hook_dir, exist_ok=True)
    with open(os.path.join(hook_dir, "sitecustomize.py"), "w", encoding="utf-8") as fh:
        fh.write(SITECUSTOMIZE)
    runtime_config = os.path.join(data_root, "coveragerc")
    with open(runtime_config, "w", encoding="utf-8") as fh:
        fh.write(RUNTIME_CONFIG.format(src=os.path.join(REPO, "src"),
                                       engines=os.path.join(REPO, "engines")))

    env = os.environ.copy()
    env["COVERAGE_PROCESS_START"] = runtime_config
    env["COVERAGE_FILE"] = data_file
    env["PYTHONPATH"] = (hook_dir + os.pathsep + env["PYTHONPATH"]
                         if env.get("PYTHONPATH") else hook_dir)
    env.setdefault("PYTHONUNBUFFERED", "1")

    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if command and command[0].startswith("-"):
        # `-m unittest ...` / `-c ...`: the interpreter that runs this tool is the one
        # that must run the suite, otherwise the hook and `coverage` may not exist there.
        command = [sys.executable] + command
    if not command:
        command = [sys.executable, "-m", "unittest", "discover", "-s", "tests",
                   "-p", "test_*.py"]

    if not args.report_only:
        # cwd = the repository: the report paths, and the `source` of .coveragerc, are
        # relative to it, whatever the child processes do to their own directories.
        proc = subprocess.Popen(command, cwd=REPO, env=env)
        code = proc.wait()
        if code != 0:
            sys.stderr.write("the run exited %d; the coverage report below is whatever "
                             "the processes recorded before that\n" % code)
    else:
        code = 0

    combine = subprocess.call([sys.executable, "-m", "coverage", "combine",
                               "--data-file", data_file], cwd=data_root, env=env)
    if combine != 0:
        sys.stderr.write("ERROR: nothing to combine in %s - the run recorded no data "
                         "(is coverage importable by the interpreter you ran?)\n"
                         % data_root)
        return 1

    import json as _json
    report_json = os.path.join(data_root, "report.json")
    style = {"total": ["--fail-under", "0"], "short": [], "full": ["-m"]}[args.show]
    with open(report_json, "wb") as fh:
        subprocess.check_call([sys.executable, "-m", "coverage", "json", "-o", "-",
                               "--data-file", data_file] + style,
                              cwd=data_root, env=env, stdout=fh)
    with open(report_json, "rb") as fh:
        data = _json.loads(fh.read().decode("utf-8"))
    total = data["totals"]["percent_covered"]

    def display(path):
        """Absolute source paths back to the repository: the configuration this script
        writes uses absolute paths (they have to - see RUNTIME_CONFIG), so that is what
        the data files contain."""
        real = os.path.normcase(os.path.abspath(path))
        home = os.path.normcase(os.path.abspath(REPO))
        if real.startswith(home + os.sep):
            return os.path.relpath(path, REPO).replace(os.sep, "/")
        return path

    for path, info in sorted(data["files"].items(), key=lambda kv: display(kv[0])):
        print("%6.1f%%  %s" % (info["summary"]["percent_covered"], display(path)))
    print("%6.1f%%  TOTAL (%d statements)" % (total, data["totals"]["num_statements"]))

    if keep_dir:
        print("data kept in %s" % data_root)
    else:
        # The hook directory has a __pycache__ of its own (every child interpreter
        # imports sitecustomize), so this is a tree removal, not a file loop.
        shutil.rmtree(data_root, ignore_errors=True)
        if os.path.isdir(data_root):
            print("could not remove %s - delete it by hand" % data_root)

    if args.require is not None:
        if total + 1e-9 < args.require:
            sys.stderr.write("TOTAL %.1f %% is BELOW the required %.1f %%\n"
                             % (total, args.require))
            return 1
        print("TOTAL %.1f %% meets the required %.1f %%" % (total, args.require))
    for prefix in args.core:
        need = args.require if args.require is not None else 70.0
        have = _subset_percent(data, prefix)
        if have is None:
            sys.stderr.write("ERROR: nothing was measured under %r - the gate path does "
                             "not match any measured file\n" % prefix)
            return 1
        if have + 1e-9 < need:
            sys.stderr.write("core %s is %.1f %%, BELOW the required %.1f %%\n"
                             % (prefix, have, need))
            return 1
        print("core %s: %.1f %% (needs %.1f %%)" % (prefix, have, need))
    return code


if __name__ == "__main__":
    sys.exit(main())
