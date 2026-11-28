# -*- coding: utf-8 -*-
"""Compile every rule file in a folder separately and report JSON (TZ v2 6.2 / 7.2).

Used by the updater BEFORE a new rule set is activated, and by CI as a linter:
    python engines/yara_check.py <rules-dir> [--timeout N]

One malicious or overly heavy file must not hang the caller: every file is
compiled on its own, and the caller runs this as a subprocess with its own
timeout. Output (stdout): {"ok": [file...], "bad": [{"file","error"}...]}.
Exit code: 0 when nothing is bad, 1 otherwise, 2 on usage/dependency errors.
"""

import argparse
import json
import os
import sys

try:
    from .yara_engine import YARA_EXTS, PLACEHOLDER_EXTERNS, _forbid_include
except ImportError:                        # run directly: python engines/yara_check.py
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from engines.yara_engine import YARA_EXTS, PLACEHOLDER_EXTERNS, _forbid_include


def check_dir(rules_dir):
    yara = None
    try:
        import yara
    except ImportError:
        pass
    if yara is None:
        return None, ["yara-python is not installed: the rule set cannot be compile-checked"]

    ok, bad = [], []
    try:
        names = sorted(os.listdir(rules_dir))
    except OSError as exc:
        return None, ["cannot read the folder: %s" % exc]
    for name in names:
        path = os.path.join(rules_dir, name)
        if not os.path.isfile(path) or not name.lower().endswith(YARA_EXTS):
            continue
        try:
            yara.compile(filepath=path, externals=PLACEHOLDER_EXTERNS,
                         include_callback=_forbid_include)
            ok.append(name)
        except Exception as exc:
            bad.append({"file": name, "error": str(exc).splitlines()[0][:300]})
    return (ok, bad), []


def main(argv=None):
    ap = argparse.ArgumentParser(description="compile-check YARA rule files (JSON report)")
    ap.add_argument("rules_dir")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.rules_dir):
        sys.stderr.write("not a folder: %s\n" % a.rules_dir)
        return 2
    result, problems = check_dir(a.rules_dir)
    if result is None:
        for p in problems:
            sys.stderr.write(p + "\n")
        return 2
    ok, bad = result
    print(json.dumps({"ok": ok, "bad": bad}, ensure_ascii=True))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
