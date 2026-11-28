# -*- coding: utf-8 -*-
"""The tools promise "standard library only, Python 3.6+" - that has to be true.

The sources are checked against the grammar of the oldest supported Python rather
than run on it: a web host with an old interpreter is exactly where this scanner
gets copied to, and a single walrus operator would make the tool unusable there.
"""

import ast
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

OLDEST = (3, 6)               # what the docstrings promise


def read(path):
    with io.open(path, encoding="utf-8") as f:
        return f.read()


def sources():
    return [os.path.join(h.SRC, f) for f in sorted(os.listdir(h.SRC)) if f.endswith(".py")]


def engine_sources():
    eng = os.path.join(h.REPO, "engines")
    return [os.path.join(eng, f) for f in sorted(os.listdir(eng)) if f.endswith(".py")]


FIRST_PARTY = {"version", "engines"}     # modules that live in this repository


def imported_names(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for mod in [a.name.split(".")[0] for a in node.names]:
                yield node, mod
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            yield node, node.module.split(".")[0]


class SyntaxFloorTest(unittest.TestCase):
    @unittest.skipIf(sys.version_info < (3, 8), "ast.parse(feature_version=) needs Python 3.8+")
    def test_sources_parse_as_python_36(self):
        for path in sources() + engine_sources():
            with self.subTest(script=os.path.basename(path)):
                try:
                    ast.parse(read(path), filename=path, feature_version=OLDEST)
                except SyntaxError as exc:
                    self.fail("%s uses syntax newer than Python %d.%d: %s"
                              % (os.path.basename(path), OLDEST[0], OLDEST[1], exc))

    def test_the_floor_is_stated_in_every_script(self):
        for path in sources():
            text = read(path)
            if os.path.basename(path) == "version.py":
                continue
            self.assertIn("%d.%d" % OLDEST, text[:2500],
                          "%s no longer says it supports Python %d.%d"
                          % (os.path.basename(path), OLDEST[0], OLDEST[1]))

    def test_no_third_party_imports(self):
        """No dependencies: the whole point of the tool."""
        stdlib = set(getattr(sys, "stdlib_module_names", ()))
        allowed_third = set()
        for path in sources():
            tree = ast.parse(read(path), filename=path)
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                    names = [node.module.split(".")[0]]
                for name in names:
                    if name in allowed_third or name in FIRST_PARTY:
                        continue
                    if stdlib and name not in stdlib:
                        self.fail("%s imports %r: the tools must run on a stdlib-only Python"
                                  % (os.path.basename(path), name))

    def test_engines_may_only_import_third_party_lazily(self):
        """engines/ is first-party and follows the same rules; the single
        exception is a THIRD-PARTY module imported inside a function body
        (the optional yara-python): a module-level import would break the
        stdlib-only promise for every user who did not install it."""
        stdlib = set(getattr(sys, "stdlib_module_names", ()))
        for path in engine_sources():
            tree = ast.parse(read(path), filename=path)
            for node, mod in imported_names(tree):
                if mod in FIRST_PARTY or (stdlib and mod in stdlib):
                    continue
                if mod == "yara":         # the one optional dependency (requirements-optional.txt)
                    self.assertTrue(self._inside_function(tree, node),
                                    "%s imports %r at module level: an optional engine "
                                    "dependency must be imported lazily inside a function"
                                    % (os.path.basename(path), mod))
                    continue
                self.fail("%s imports %r: the tools must run on a stdlib-only Python"
                          % (os.path.basename(path), mod))

    @staticmethod
    def _inside_function(tree, target):
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for sub in ast.walk(fn):
                    if sub is target:
                        return True
        return False

    def test_tests_parse_on_the_running_interpreter(self):
        for name in sorted(os.listdir(h.HERE)):
            if name.endswith(".py"):
                with self.subTest(test=name):
                    ast.parse(read(os.path.join(h.HERE, name)), filename=name)


if __name__ == "__main__":
    unittest.main()
