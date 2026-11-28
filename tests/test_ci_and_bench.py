# -*- coding: utf-8 -*-
"""The CI files themselves are data the repository promises about itself.

A workflow can be wrong in ways that never show up as a failing test: a step that
launches something that does not exist, an action pinned to a tag instead of a commit,
a Python version the project does not support, a job that no longer mentions the
directory it is supposed to gate. Those are the mistakes this file looks for, by reading
the YAML as text (the repository has no YAML parser in the standard library, and the
assertions are about tokens, not about the document tree).

The second class of checks is the one that needs no CI to be meaningful: the pieces CI
runs must work when they are invoked exactly the way the workflow invokes them. A
benchmark that crashes on its smallest invocation, or a linter that cannot answer
without the optional library, is a red pipeline tomorrow either way - better to learn
it here.
"""

import json
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h          # noqa: E402
import fixtures_sites as fx  # noqa: E402

WORKFLOW = os.path.join(h.REPO, ".github", "workflows", "ci.yml")
DEV_TOOLS = os.path.join(h.REPO, "requirements-dev.txt")
BENCH = os.path.join(h.REPO, "benchmarks", "bench_scan.py")


def workflow_text():
    if not os.path.isfile(WORKFLOW):
        return None
    with open(WORKFLOW, "rb") as fh:
        return fh.read().decode("utf-8")


@unittest.skipUnless(workflow_text() is not None, "no workflow file")
class WorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = workflow_text()

    def test_every_action_is_pinned_to_a_commit(self):
        unpinned = []
        for line in self.text.splitlines():
            m = re.match(r"\s*-?\s*uses:\s*(\S+)@", line)
            if not m:
                continue
            ref = line.split("@", 1)[1].split()[0].split("#")[0]
            if not re.match(r"^[0-9a-f]{40}$", ref):
                unpinned.append(line.strip())
        self.assertFalse(unpinned,
                         "actions must be pinned to a 40-character commit, not a tag "
                         "someone can move: %s" % "\n".join(unpinned))

    def test_a_pin_is_written_with_the_version_it_is(self):
        """A SHA nobody can name is a lock that no one will ever update: the comment has
        to say which release the commit is."""
        bad = []
        for line in self.text.splitlines():
            if line.lstrip().startswith("#") or "uses:" not in line or "@" not in line:
                continue
            comment = line.split("#", 1)[1].strip() if "#" in line else ""
            if not re.match(r"^v\d", comment):
                bad.append(line.strip())
        self.assertFalse(bad, "every pinned action needs `# vN...` next to it: %s"
                         % "\n".join(bad))

    def test_the_interpreters_it_installs_are_the_ones_we_promise(self):
        floor = (3, 6)
        for m in re.finditer(r"python-version:\s*[\"']?([0-9]+\.[0-9]+)", self.text):
            version = tuple(int(x) for x in m.group(1).split("."))
            self.assertGreaterEqual(version, floor,
                                    "CI would test Python %s, which the tools do not "
                                    "support" % m.group(1))
            self.assertLess(version, (3, 14), "a version this suite has never seen")
        self.assertIn("3.6", self.text, "the oldest promised interpreter must be tested")

    def test_it_gates_the_directories_that_hold_code(self):
        for target in ("src", "engines", "tests", "tools", "benchmarks"):
            self.assertRegex(self.text, r"ruff check[^\n]*\b%s\b" % target,
                             "the lint job does not look at %s/" % target)
        self.assertRegex(self.text, r"bandit[^\n]*-r[^\n]*\bsrc\b")
        self.assertRegex(self.text, r"coverage_run\.py[^\n]*--require\s+(\d+)",
                         "the coverage job must set a threshold, not just print numbers")

    def test_the_optional_engine_is_installed_and_absent_on_purpose(self):
        self.assertRegex(self.text, r"pip install[\s\S]{0,40}yara-python",
                         "no leg installs the optional engine: the YARA promise would "
                         "go untested")
        self.assertRegex(self.text, r"yara:\s*false",
                         "no leg runs with nothing installed, which is the mode most "
                         "users are in")

    def test_no_job_writes_secrets_or_uses_a_floating_container(self):
        self.assertNotIn("secrets.", self.text,
                         "nothing here needs a secret; a token in CI is an attack surface")
        for m in re.finditer(r"image:\s*(\S+)", self.text):
            if m.group(1).startswith("${{"):
                continue                    # the real value is in the matrix, checked below
            self.assertIn("@sha256:", m.group(1),
                          "%s is not pinned by digest: the interpreter under the job "
                          "would be whatever the registry serves that day" % m.group(1))
        containers = re.findall(r"python:[0-9.]+-[a-z]+@(sha256:[0-9a-f]{64})", self.text)
        self.assertGreaterEqual(len(containers), 2,
                                "the floor jobs must run in a digest-pinned image")
        self.assertRegex(self.text, r"permissions:\s*\n\s*contents:\s*read",
                         "the workflow must not get write permissions by default")


class DevRequirementsTest(unittest.TestCase):
    @unittest.skipUnless(os.path.isfile(DEV_TOOLS), "no requirements-dev.txt")
    def test_the_development_tools_are_pinned(self):
        for line in open(DEV_TOOLS, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self.assertRegex(line, r"^[A-Za-z0-9._-]+==[0-9][0-9a-zA-Z.]*$",
                             "a development tool must be pinned with ==: %s" % line)

    @unittest.skipUnless(os.path.isfile(DEV_TOOLS), "no requirements-dev.txt")
    def test_the_declared_tools_are_the_ones_ci_calls(self):
        text, workflow = open(DEV_TOOLS, encoding="utf-8").read(), workflow_text()
        declared = {line.split("==")[0].strip().lower()
                    for line in text.splitlines() if "==" in line}
        for tool in ("coverage", "ruff", "bandit"):
            self.assertIn(tool, declared)
            self.assertRegex(workflow, r"(python -m )?%s" % tool,
                             "%s is installed but never run: delete it from the file"
                             % tool)


@unittest.skipUnless(h.have_yara(), "yara-python is not installed")
class BenchmarkTest(unittest.TestCase):
    """CI runs benchmarks/bench_scan.py; here it runs on its smallest sensible corpus.

    The point is not the timing - a test process on a shared machine measures nothing
    reliable. The point is that the harness starts, produces a record with every field a
    later reader needs, refuses to compare unlike runs, and reports the ratio against
    the budget instead of a bare number.
    """

    @classmethod
    def setUpClass(cls):
        cls.rules = h.workdir("bench-rules-")
        for i in range(3):
            with open(os.path.join(cls.rules, "t%d.yar" % i), "wb") as fh:
                fh.write(('rule SbTestBench%d {\n  strings:\n    $a = "SBD_TEST_%d"'
                          ' ascii wide\n  condition:\n    $a\n}\n' % (i, i)).encode())

    def run_bench(self, args):
        cmd = [sys.executable, BENCH] + args
        proc = subprocess.Popen(cmd, cwd=h.REPO, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, universal_newlines=True,
                                encoding="utf-8", errors="replace")
        out, _ = proc.communicate(timeout=1800)
        return proc.returncode, out

    def test_the_smallest_run_produces_a_record_that_explains_itself(self):
        out = os.path.join(h.workdir("bench-record-"), "record.json")
        code, text = self.run_bench(["--files", "40", "--yara-rules", self.rules,
                                     "--workers", "1", "--out", out])
        self.assertEqual(code, 0, text[-1500:])
        with open(out, "rb") as fh:
            rec = json.loads(fh.read().decode("utf-8"))
        self.assertEqual(rec["record"], 1, "the record format has a version: a reader "
                                          "from next year has to know what it holds")
        for field in ("python", "platform", "machine_cpus", "corpus", "runs",
                      "budget_ratio", "verdict"):
            self.assertIn(field, rec)
        self.assertIn("baseline", rec["runs"])
        run = rec["runs"]["baseline"]
        for field in ("wall_s", "files_per_s", "peak_rss_bytes", "peak_rss_source",
                      "files_scanned", "exit_code", "command", "yara_rules_loaded"):
            self.assertIn(field, run, "a record without one of these cannot be compared")
        self.assertGreater(run["files_scanned"], 0)
        self.assertIsNotNone(run["peak_rss_source"],
                             "a memory number without the name of the source that "
                             "produced it is not a measurement")
        self.assertIs(rec["verdict"]["same_tree_scanned"], True,
                      "the same corpus was scanned twice: the record has to say so")

    def test_a_record_never_carries_the_paths_of_the_machine_that_made_it(self):
        """The reference records live in the repository; a corpus path would carry a user
        name into a published file (tests/test_release.py would reject it, but by then
        the file already exists)."""
        out = os.path.join(h.workdir("bench-record-"), "record.json")
        code, text = self.run_bench(["--files", "30", "--yara-rules", self.rules,
                                     "--workers", "1", "--out", out])
        self.assertEqual(code, 0, text[-1500:])
        with open(out, "rb") as fh:
            raw = fh.read().decode("utf-8")
        leak = re.search(r"[A-Za-z]:[\\/]", raw)
        self.assertIsNone(leak, "a drive-absolute path leaked into the record: %r"
                          % (raw[max(0, leak.start() - 40):leak.start() + 40]
                             if leak else ""))
        self.assertNotIn(h.REPO, raw, "the checkout path leaked into a record")
        for part in json.loads(raw)["runs"]["baseline"]["command"]:
            self.assertFalse(os.path.isabs(part), "absolute path in the command: %s" % part)

    def test_the_budget_verdict_is_part_of_the_run_not_an_eye_test(self):
        """--budget decides the exit code. A CI job that prints a ratio and always passes
        measures nothing."""
        out = os.path.join(h.workdir("bench-record-"), "record.json")
        code, text = self.run_bench(["--files", "40", "--yara-rules", self.rules,
                                     "--workers", "1", "--budget", "0.001", "--out", out])
        self.assertEqual(code, 3, "an impossible budget must fail the run:\n%s" % text[-800:])
        self.assertIn("OVER", text)
        with open(out, "rb") as fh:
            rec = json.loads(fh.read().decode("utf-8"))
        self.assertIs(rec["verdict"]["yara_cold_within_budget"], False)

    def test_it_says_so_when_the_two_records_are_not_the_same_work(self):
        """The corpus size and seed are part of the record for this reason: the only
        meaningful benchmark difference is the same tree scanned twice."""
        first = os.path.join(h.workdir("bench-record-"), "a.json")
        second = os.path.join(h.workdir("bench-record-"), "b.json")
        code, text = self.run_bench(["--files", "30", "--out", first])
        self.assertEqual(code, 0, text[-800:])
        code, text = self.run_bench(["--files", "45", "--out", second, "--compare", first])
        self.assertEqual(code, 0, text[-1500:])
        self.assertIn("different corpus", text,
                      "comparing 45 files against 30 is how a benchmark starts lying: "
                      "%s" % text[-800:])
        code, text = self.run_bench(["--files", "30", "--out", second, "--compare", first])
        self.assertEqual(code, 0, text[-800:])
        self.assertNotIn("different corpus", text)


class CoverageToolTest(unittest.TestCase):
    """tools/coverage_run.py decides the number CI gates on; it has to refuse the setups
    that produce a confident wrong answer."""

    def script(self):
        return os.path.join(h.REPO, "tools", "coverage_run.py")

    def test_it_refuses_a_data_directory_inside_a_test_scratch_tree(self):
        inside = os.path.join(fx.fixtures_root(), "sbd-cov-inside")
        if not os.path.isdir(inside):
            os.makedirs(inside)
        proc = subprocess.Popen([sys.executable, self.script(), "--data-dir", inside,
                                 "--report-only"], cwd=h.REPO, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, universal_newlines=True,
                                encoding="utf-8", errors="replace")
        out, _ = proc.communicate(timeout=300)
        self.assertEqual(proc.returncode, 2,
                         "data files written next to fixture trees are scanned as files "
                         "of the site: %s" % out)
        self.assertIn("inside a tree the tests write to", out)


if __name__ == "__main__":
    unittest.main()
