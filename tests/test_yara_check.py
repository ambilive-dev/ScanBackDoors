# -*- coding: utf-8 -*-
"""TZ v2 6.2 / 7.2: `engines/yara_check.py` is the rule linter - the updater runs it
before a rule set is activated, and CI runs it as a gate, so its contract matters:
one JSON object on stdout, one exit code per outcome, and a folder that contains a
broken rule must not look like a folder that contains no rules.

Everything here calls `main()` in-process: the module is a pure function of the
folder it is given, and the updater is what spawns it. The process boundary is
tested in tests/test_updater.py, where the compile check belongs to the install.
"""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

sys.path.insert(0, h.REPO)
from engines import yara_check  # noqa: E402

GOOD = ('rule SbLintGood {\n'
        '    strings:\n        $a = "SBD_LINT_MARKER_77123" ascii wide\n'
        '    condition:\n        $a\n}\n')
ALSO_GOOD = ('rule SbLintSecond {\n'
             '    strings:\n        $b = { 4D 69 63 72 6F 73 6F 66 74 }\n'
             '    condition:\n        $b at 0\n}\n')
BROKEN = "rule SbLintBroken {\n    condition: this is not yara at all\n}\n"
INCLUDES = ('include "sibling.yar"\n'
            'rule SbLintInclude {\n    condition: true\n}\n')


def rules_dir(files):
    """{name: text} -> a throw-away rules folder, written in binary (a stray \\r would
    change what the compiler sees)."""
    root = h.workdir("lint-rules-")
    for name, text in files.items():
        with open(os.path.join(root, name), "wb") as fh:
            fh.write(text.encode("utf-8"))
    return root


def run_main(argv):
    """(exit code, parsed stdout JSON or None, stderr text) for one linter run."""
    out, err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        code = yara_check.main(argv)
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    text = out.getvalue().strip()
    try:
        payload = json.loads(text) if text else None
    except ValueError:
        payload = None
    return code, payload, err.getvalue()


@unittest.skipUnless(h.have_yara(), "yara-python is not installed")
class LinterTest(unittest.TestCase):
    def test_a_clean_folder_is_ok_and_says_which_files_it_checked(self):
        root = rules_dir({"good.yar": GOOD, "second.yar": ALSO_GOOD})
        code, payload, err = run_main([root])
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["bad"], [])
        self.assertEqual(sorted(payload["ok"]), ["good.yar", "second.yar"],
                         "the linter must name the files it compiled: silence about a "
                         "file is how an empty package starts")

    def test_one_broken_rule_fails_the_folder_and_names_the_file(self):
        root = rules_dir({"good.yar": GOOD, "broken.yar": BROKEN})
        code, payload, err = run_main([root])
        self.assertEqual(code, 1, "a folder with a broken rule is not a pass: %s" % err)
        self.assertEqual([b["file"] for b in payload["bad"]], ["broken.yar"])
        self.assertIn("good.yar", payload["ok"],
                      "one broken file must not hide that the other one compiles")
        self.assertTrue(payload["bad"][0]["error"], "an error without a message is useless")

    def test_a_folder_of_only_broken_rules_is_still_one_json_object(self):
        root = rules_dir({"broken.yar": BROKEN})
        code, payload, err = run_main([root])
        self.assertEqual(code, 1, err)
        self.assertIsNotNone(payload, "the updater parses this stdout: it must be one object")
        self.assertEqual(payload["ok"], [])

    def test_include_is_refused_and_reported(self):
        """A rule file that pulls in another file is a rule file the caller cannot
        ship: the package is a closed set, so `include` is refused, not followed."""
        root = rules_dir({"pulls.yar": INCLUDES, "sibling.yar": GOOD})
        code, payload, err = run_main([root])
        self.assertEqual(code, 1, "an include must not pass the linter: %s" % payload)
        self.assertEqual([b["file"] for b in payload["bad"]], ["pulls.yar"])

    def test_files_that_are_not_rules_are_ignored(self):
        root = rules_dir({"good.yar": GOOD, "README.md": b"not a rule".decode(),
                          "notes.txt": "text"})
        code, payload, err = run_main([root])
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["ok"], ["good.yar"])

    def test_a_missing_folder_is_a_usage_error_not_a_clean_report(self):
        code, payload, err = run_main([os.path.join(h.workdir("lint-none-"), "absent")])
        self.assertEqual(code, 2)
        self.assertIsNone(payload, "exit 2 must not print an 'everything is fine' object")
        self.assertIn("not a folder", err)

    def test_an_empty_folder_is_a_pass_of_nothing(self):
        """The linter's job is to answer about what is there. Saying 'no rules' is the
        updater's decision, and tests/test_updater.py checks that it refuses."""
        code, payload, err = run_main([h.workdir("lint-empty-")])
        self.assertEqual(code, 0, err)
        self.assertEqual(payload, {"ok": [], "bad": []})


class WithoutTheLibraryTest(unittest.TestCase):
    def test_without_yara_it_refuses_instead_of_claiming_a_clean_pass(self):
        """The same discipline as the scanner: an engine that cannot run says so and
        exits 2, it never answers with an empty 'bad' list that reads like a pass."""
        saved = sys.modules.get("yara")
        sys.modules["yara"] = None          # `import yara` raises ImportError with None
        try:
            root = rules_dir({"good.yar": GOOD})
            code, payload, err = run_main([root])
        finally:
            if saved is None:
                del sys.modules["yara"]
            else:
                sys.modules["yara"] = saved
        self.assertEqual(code, 2)
        self.assertIsNone(payload)
        self.assertIn("not installed", err)


class EngineInterfaceTest(unittest.TestCase):
    def test_the_linter_shares_the_limits_of_the_engine(self):
        """The linter compiles with the same externals and the same include policy as
        the runtime engine, or it certifies something the scanner will not accept."""
        from engines import yara_engine
        self.assertTrue(yara_engine.PLACEHOLDER_EXTERNS)
        self.assertTrue(callable(yara_engine._forbid_include))
        self.assertEqual(set(yara_check.YARA_EXTS), set(yara_engine.YARA_EXTS))


if __name__ == "__main__":
    unittest.main()
