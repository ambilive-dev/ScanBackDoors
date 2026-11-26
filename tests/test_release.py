# -*- coding: utf-8 -*-
"""Release hygiene: one version everywhere, the documented layout, nothing private in git.

These checks are cheap and they fail exactly on the mistakes that already happened
in this project once: the scanner was tagged 2.1.1 while its file said 2.1, the
GUI had no --version at all, and the version of the bundle was written in three
places.
"""

import io
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

# script -> the name its --version must print
SCRIPTS = {
    "scan_backdoors.py": "scan_backdoors",
    "scan_backdoors_gui.py": "scan_backdoors_gui",
    "clean_malware.py": "clean_malware",
    "joomla_baseline.py": "joomla_baseline",
}
ROOT_FILES = ["README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md", "start.bat", ".gitignore"]
INTERNAL_FLAGS = {"progress-lines", "release-url"}   # plumbing, not documented as a user option


def read(path):
    with io.open(path, encoding="utf-8") as f:
        return f.read()


def bundle_namespace():
    ns = {}
    exec(compile(read(os.path.join(h.SRC, "version.py")), "version.py", "exec"), ns)
    return ns


BUNDLE = bundle_namespace()
VERSION = BUNDLE["VERSION"]


def git(args):
    """git in the repository, or None when the tests run outside a checkout."""
    if not os.path.isdir(os.path.join(h.REPO, ".git")):
        return None
    proc = subprocess.Popen(["git", "-C", h.REPO] + args, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, universal_newlines=True,
                            encoding="utf-8", errors="replace")
    out = proc.communicate()[0]
    return out if proc.returncode == 0 else None


class VersionTest(unittest.TestCase):
    def test_version_is_written_once(self):
        """Only src/version.py holds the number; the scripts import it."""
        self.assertRegex(VERSION, r"^\d+\.\d+(\.\d+)?$",
                         "src/version.py must hold a plain N.N or N.N.P version")
        for script in SCRIPTS:
            text = read(os.path.join(h.SRC, script))
            self.assertIn("from version import VERSION", text,
                          "%s must take VERSION from version.py" % script)
            self.assertNotRegex(
                text, r"(?m)^VERSION\s*=\s*[\"']",
                "%s has its own VERSION literal again - use src/version.py" % script)

    def test_fallbacks_equal_the_bundle_version(self):
        """The single-file fallback literals must not drift from version.py."""
        for script in SCRIPTS:
            text = read(os.path.join(h.SRC, script))
            self.assertIn('"%s"' % VERSION, text,
                          "%s: the fallback version differs from src/version.py" % script)

    def test_cli_version_reports_the_bundle_version(self):
        for script, label in SCRIPTS.items():
            res = h.run(script, ["--version"], timeout=120)
            self.assertEqual(res.returncode, 0, "%s --version failed: %s" % (script, res.out))
            self.assertEqual(res.out.strip(), "%s %s" % (label, VERSION),
                             "%s --version must print the bundle version" % script)

    def test_a_single_script_without_version_py_still_starts(self):
        """The CLI scanner is uploaded to servers as one file: the fallback must work."""
        keep = h.workdir("sbd-single-")
        try:
            for script in ("scan_backdoors.py", "clean_malware.py", "joomla_baseline.py"):
                shutil.copy2(os.path.join(h.SRC, script), keep)
                proc = subprocess.Popen([sys.executable, "-u", os.path.join(keep, script), "--version"],
                                        cwd=keep, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        universal_newlines=True, encoding="utf-8", errors="replace")
                out = proc.communicate()[0]
                self.assertEqual(proc.returncode, 0, out)
                self.assertIn(VERSION, out,
                              "%s alone must report the same version (fallback literal)" % script)
        finally:
            shutil.rmtree(keep, ignore_errors=True)

    def test_minimum_scanner_the_gui_can_drive(self):
        """The GUI warns about an old scanner; that threshold must stay sane."""
        self.assertRegex(BUNDLE["MIN_SCANNER"], r"^\d+\.\d+$")
        self.assertLessEqual(tuple(int(x) for x in BUNDLE["MIN_SCANNER"].split(".")),
                             tuple(int(x) for x in VERSION.split(".")))
        self.assertIn("MIN_SCANNER", read(os.path.join(h.SRC, "scan_backdoors_gui.py")))


class LayoutTest(unittest.TestCase):
    def test_shipped_scripts(self):
        found = sorted(f for f in os.listdir(h.SRC) if f.endswith(".py"))
        self.assertEqual(found, sorted(SCRIPTS) + ["version.py"],
                         "src/ must contain exactly the scanner, the GUI, the cleaner and version.py")

    def test_root_files_exist(self):
        for name in ROOT_FILES:
            self.assertTrue(os.path.isfile(os.path.join(h.REPO, name)), "%s is missing" % name)
        for name in (os.path.join("docs", "README_RU.md"), os.path.join("data", "whitelist-known-clean.txt")):
            self.assertTrue(os.path.isfile(os.path.join(h.REPO, name)), "%s is missing" % name)

    def test_readme_matches_start_bat(self):
        """start.bat has to launch the GUI that is actually in src/."""
        bat = read(os.path.join(h.REPO, "start.bat")).replace("\\", "/")
        self.assertIn("scan_backdoors_gui.py", bat)
        self.assertNotRegex(bat, r"(?m)^\s*python\s+scan_backdoors_gui\.py",
                            "start.bat must not point at a GUI in the repository root")

    def test_docs_mention_the_shipped_version(self):
        readme = read(os.path.join(h.REPO, "README.md"))
        self.assertRegex(readme, r"\b%s\b" % re.escape(VERSION),
                         "README.md must show the version that is actually shipped")
        changelog = read(os.path.join(h.REPO, "CHANGELOG.md"))
        self.assertRegex(changelog, r"(?m)^#{2,}\s+v?%s(?:\s|---|[—–-]|\b)" % re.escape(VERSION),
                         "CHANGELOG.md must have a section for the shipped version")

    def test_issue_templates_exist(self):
        d = os.path.join(h.REPO, ".github", "ISSUE_TEMPLATE")
        for name in ("config.yml", "false-positive.yml", "bug.yml", "feature_request.yml"):
            self.assertTrue(os.path.isfile(os.path.join(d, name)), "%s is missing" % name)
        self.assertIn("blank_issues_enabled: false", read(os.path.join(d, "config.yml")))

    def test_every_cli_flag_is_documented(self):
        readme = read(os.path.join(h.REPO, "README.md")).replace("\\", "/")
        for script in SCRIPTS:
            res = h.run(script, ["--help"], timeout=120)
            self.assertEqual(res.returncode, 0, res.out)
            flags = set(re.findall(r"--([a-z][a-z0-9-]+)", res.out)) - INTERNAL_FLAGS - {"help", "version"}
            missing = sorted(f for f in flags if "--" + f not in readme)
            self.assertFalse(missing, "%s: flags missing from README.md: %s" % (script, ", ".join(missing)))


@unittest.skipIf(git(["rev-parse", "HEAD"]) is None, "not a git checkout")
class PublishedTreeTest(unittest.TestCase):
    """Nothing a customer could recognise may ever enter this repository."""

    FORBIDDEN_PATH = [
        r"report-data\.csv$", r"cleanup-report\.csv$", r"WhiteList\.txt$", r"^whitelist\.txt$",
        r"_quarantine", r"\.modified$", r"\.xlsx$", r"\.pem$", r"\.key$", r"^\.env$",
        r"__pycache__", r"\.scan_backdoors_gui\.json$",
    ]
    LOCAL_PATHS = [r"(?i)[a-z]:\\(?:users|program files|web|www|inetpub|home|ai|xampp|tmp)\b",
                   r"(?i)[a-z]:\\[a-z0-9_.\-]{1,20}\\[a-z0-9_.\-]{1,20}\\"]
    EMAILS = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
    PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net", "example.edu"}

    def tracked_files(self):
        return [ln for ln in (git(["ls-files"]) or "").splitlines() if ln.strip()]

    def test_no_work_artifacts_tracked(self):
        bad = []
        for path in self.tracked_files():
            for pattern in self.FORBIDDEN_PATH:
                if re.search(pattern, path.replace("\\", "/")):
                    bad.append("%s (%s)" % (path, pattern))
        self.assertFalse(bad, "working artifacts must not be committed: %s" % ", ".join(bad))

    def test_no_local_paths_or_emails_in_tracked_text(self):
        bad = []
        for path in self.tracked_files():
            full = os.path.join(h.REPO, path)
            if not os.path.isfile(full) or os.path.getsize(full) > 4 * 1024 * 1024:
                continue
            try:
                text = read(full)
            except UnicodeDecodeError:
                continue                                    # binaries are not scanned here
            for pattern in self.LOCAL_PATHS:
                if re.search(pattern, text):
                    bad.append("%s: local path %s" % (path, pattern))
            for domain in self.EMAILS.findall(text):
                if domain.lower() not in self.PLACEHOLDER_DOMAINS:
                    bad.append("%s: e-mail address %s" % (path, domain))
        self.assertFalse(bad, "the published tree leaks something:\n  " + "\n  ".join(sorted(set(bad))))

    def test_gitignore_covers_what_the_tools_write(self):
        """Reports, quarantines and the GUI's whitelist must never be committable."""
        checks = ["report-data.csv", "cleanup-report.csv", "src/whitelist.txt",
                  "site/_quarantine_site/2026/x.php", "configuration.php.modified",
                  "__pycache__/scan_backdoors.pyc", ".scan_backdoors_gui.json",
                  "joomla-baselines/Joomla_3.9.27/index.php",
                  "joomla-baselines/Joomla_3.9.27.baseline.json"]
        for rel in checks:
            proc = subprocess.Popen(["git", "-C", h.REPO, "check-ignore", "--no-index", "-q", rel],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.communicate()
            self.assertEqual(proc.returncode, 0,
                             ".gitignore does not cover %s - a working file can be committed" % rel)


if __name__ == "__main__":
    unittest.main()
