# -*- coding: utf-8 -*-
"""Regression tests for the findings of the November 2026 external code review.

Supplied with the review package and adapted to the shared test harness: sites,
reports and quarantine copies live under the single AV-excluded fixtures root
(%TEMP%\sbd-fixtures), and the tools run through harness.run() exactly like
every other test in this folder. The logic and assertions of the reviewer's
tests are kept as written; every scan test plants the one-line classic web
shell the scanner's own --self-test already uses, so nothing new is introduced.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
import harness as h  # noqa: E402
import scan_backdoors as sbd            # noqa: E402
import joomla_baseline as jb            # noqa: E402

SHELL = "<?php system($_GET['c']); ?>\n"


def file_url(path):
    """An absolute local path as a file:// URL (the scanner's uri_of() does the same)."""
    p = path.replace(os.sep, "/")
    return ("file:///" if re.match(r"^[A-Za-z]:/", p) else "file://") + p


def run_scan(site, *extra):
    """Run the scanner as a subprocess; return (exit code, {path: [signature labels]}, stats, stdout)."""
    out = os.path.join(site, "report.json")
    res = h.run("scan_backdoors.py",
                [site, "--no-csv", "--no-progress", "--workers", "1", "--json", out] + list(extra))
    if not os.path.isfile(out):
        return res.returncode, {}, {}, res.out
    data = h.read_json(out)
    return (res.returncode,
            {x["path"]: [hit["signature"] for hit in x["hits"]] for x in data["files"]},
            data["stats"], res.out)


def write(root, rel, text=""):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    return path


class Site(unittest.TestCase):
    def setUp(self):
        self.root = h.workdir("sbd-audit-site-")
        self.addCleanup(shutil.rmtree, self.root, True)


class CommentMasker(Site):
    """The masker must never hide live code."""

    def test_code_after_a_closing_tag_is_not_masked(self):
        m = sbd.mask_php_comments("<?php defined('_JEXEC') or die; ?>\n<a href=http://x.org><?php echo $x; ?>\n")
        self.assertIn("echo $x", m)

    def test_line_comment_ends_at_a_closing_tag(self):
        m = sbd.mask_php_comments("<?php // note ?><?php echo $y; ?>\n")
        self.assertIn("echo $y", m)

    def test_real_comments_are_still_masked(self):
        m = sbd.mask_php_comments("<?php\n// system($_GET['c'])\n/** $_POST docblock */\necho 1;\n")
        self.assertNotIn("system", m)
        self.assertNotIn("docblock", m)
        self.assertIn("echo 1", m)

    def test_length_and_newlines_are_preserved(self):
        src = "<?php // a ?>\n<b>#x</b><?php /* c\n d */ echo 2; ?>\n"
        m = sbd.mask_php_comments(src)
        self.assertEqual(len(m), len(src))
        self.assertEqual([i for i, c in enumerate(m) if c == "\n"], [i for i, c in enumerate(src) if c == "\n"])

    def test_the_shell_is_found_end_to_end(self):
        write(self.root, "t/plain.php", SHELL)
        write(self.root, "t/after_html_slashes.php",
              "<?php defined('_JEXEC') or die; ?>\n<a href=http://example.org><?php system($_GET['c']); ?>\n")
        write(self.root, "t/comment_closed.php", "<?php // x ?><?php system($_GET['c']); ?>\n")
        rc, files, _stats, _out = run_scan(self.root)
        for name in ("plain", "after_html_slashes", "comment_closed"):
            self.assertIn("system/exec(request data)", files.get("t/%s.php" % name, []), name)
        self.assertEqual(rc, 2)


class CmsDetection(Site):
    def test_one_planted_marker_does_not_switch_cms(self):
        write(self.root, "configuration.php", "<?php\nclass JConfig {}\n")
        write(self.root, "wp-load.php", "<?php // planted\n")
        write(self.root, "wp-admin/c99.php", "")
        self.assertEqual(sbd.detect_cms(self.root), "joomla")
        _rc, files, _s, out = run_scan(self.root)
        self.assertIn("typical webshell filename", files.get("wp-admin/c99.php", []))

    def test_conflicting_markers_suppress_nothing(self):
        for d in ("wp-includes", "wp-admin", "administrator"):
            os.makedirs(os.path.join(self.root, d))
        write(self.root, "wp-config.php", "<?php\n")
        self.assertEqual(sbd.detect_cms(self.root), "ambiguous")

    def test_real_wordpress_is_still_recognised(self):
        for d in ("wp-includes", "wp-admin"):
            os.makedirs(os.path.join(self.root, d))
        write(self.root, "wp-config.php", "<?php\n")
        self.assertEqual(sbd.detect_cms(self.root), "wp")

    def test_wp_core_exemption_is_one_exact_file(self):
        for d in ("wp-includes", "wp-admin"):
            os.makedirs(os.path.join(self.root, d))
        write(self.root, "wp-config.php", "<?php\n")
        write(self.root, "wp-includes/Text/Diff/Engine/shell.php", "")      # the legitimate core file
        write(self.root, "wp-admin/c99.php", "")                           # a dropped shell
        write(self.root, "wp-includes/shell.php", "")                      # a dropped shell
        _rc, files, _s, _o = run_scan(self.root)
        self.assertNotIn("typical webshell filename", files.get("wp-includes/Text/Diff/Engine/shell.php", []))
        self.assertIn("typical webshell filename", files.get("wp-admin/c99.php", []))
        self.assertIn("typical webshell filename", files.get("wp-includes/shell.php", []))


class Whitelist(Site):
    def test_mask_does_not_span_folders(self):
        self.assertTrue(sbd.path_whitelisted("components/com_k2/a.php", ["components/com_k2/*.php"]))
        self.assertFalse(sbd.path_whitelisted("components/com_k2/sub/a.php", ["components/com_k2/*.php"]))
        self.assertTrue(sbd.path_whitelisted("libraries/vendor/x/a.php", ["libraries/vendor/"]))

    def test_path_whitelisted_files_are_counted_separately(self):
        write(self.root, "libraries/vendor/x/dropped.php", SHELL)
        wl = os.path.join(h.workdir("sbd-wl-"), "wl.txt")
        with open(wl, "w") as f:
            f.write("libraries/vendor/\n")
        self.addCleanup(shutil.rmtree, os.path.dirname(wl), True)
        _rc, files, stats, _o = run_scan(self.root, "--whitelist", wl)
        self.assertEqual(files, {})
        self.assertEqual(stats["Whitelisted by path (content NOT scanned)"], 1)

    def test_audit_mode_still_reports_critical_in_whitelisted_paths(self):
        write(self.root, "libraries/vendor/x/dropped.php", SHELL)
        wl = os.path.join(h.workdir("sbd-wl-"), "wl.txt")
        with open(wl, "w") as f:
            f.write("libraries/vendor/\n")
        self.addCleanup(shutil.rmtree, os.path.dirname(wl), True)
        rc, files, _s, _o = run_scan(self.root, "--whitelist", wl, "--audit-whitelisted")
        self.assertIn("system/exec(request data)", files.get("libraries/vendor/x/dropped.php", []))
        self.assertEqual(rc, 2)


class Walk(Site):
    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_symlink_to_a_folder_is_reported(self):
        target = tempfile.mkdtemp(prefix="sbd-target-", dir=h.workdir("sbd-audit-target-"))
        self.addCleanup(shutil.rmtree, os.path.dirname(target), True)
        os.symlink(target, os.path.join(self.root, "linkdir"))
        _rc, files, _s, _o = run_scan(self.root)
        self.assertIn("symlink inside web root", files.get("linkdir", []))

    def test_php_tag_in_unknown_extension_names_no_none(self):
        write(self.root, "data.xyz", "<?php echo 1; ?>\n")
        _rc, files, _s, _o = run_scan(self.root)
        labels = files.get("data.xyz", [])
        self.assertTrue(labels)
        self.assertFalse(any("None" in l for l in labels), labels)


class Workers(Site):
    def test_uninitialised_worker_fails_loudly(self):
        saved = sbd.CFG
        try:
            sbd._init({})
            with self.assertRaises(RuntimeError):
                sbd.scan_batch(["x"])
        finally:
            sbd._init(saved)

    def test_pool_entry_point_for_old_pythons_carries_the_config(self):
        write(self.root, "a.php", SHELL)
        cfg = {"start": self.root, "max_size": 1 << 20, "max_matches": 10, "since": None,
               "enabled": {sbd.SEV_CRIT, sbd.SEV_OBF, sbd.SEV_WARN}, "wl_hashes": set(), "wl_paths": [],
               "baseline": None, "baseline_dirs": set(), "skip_paths": set(), "baseline_pkgs": set(),
               "posix": os.name != "nt", "exclude_ext": set(), "cms": None}
        saved = sbd.CFG
        try:
            sbd._init({})
            results, counters = sbd.scan_batch_cfg(([os.path.join(self.root, "a.php")], cfg))
        finally:
            sbd._init(saved)
        self.assertEqual(len(results), 1)
        self.assertEqual(counters.get("error", 0), 0)

    def test_strict_turns_read_errors_into_exit_code_3(self):
        write(self.root, "ok.php", "<?php echo 1;\n")
        driver = (
            "import sys; sys.path.insert(0, %r); import scan_backdoors as s\n"
            "def boom(p):\n"
            "    raise OSError('simulated')\n"
            "s.scan_file = boom\n"
            "sys.exit(s.main([%r, '--no-csv', '--no-progress'] + sys.argv[1:]))\n" % (h.SRC, self.root))
        plain = subprocess.run([h.PYTHON, "-c", driver], stdout=subprocess.PIPE,
                               universal_newlines=True, env=h.ENV)
        strict = subprocess.run([h.PYTHON, "-c", driver, "--strict"], stdout=subprocess.PIPE,
                                universal_newlines=True, env=h.ENV)
        self.assertIn("INCOMPLETE", plain.stdout)
        self.assertEqual(plain.returncode, 0)
        self.assertEqual(strict.returncode, 3)


class BaselineDownload(Site):
    def test_truncated_archive_is_an_explained_failure_not_a_traceback(self):
        good = os.path.join(self.root, "good.zip")
        with zipfile.ZipFile(good, "w") as z:
            z.writestr("index.php", "<?php\n")
        with open(good, "rb") as f:
            data = f.read()
        bad = os.path.join(self.root, "Joomla_3.9.27-Stable-Full_Package.zip")
        with open(bad, "wb") as f:
            f.write(data[:len(data) // 2])
        release = os.path.join(self.root, "release.json")
        with open(release, "w") as f:
            json.dump({"assets": [{"name": os.path.basename(bad),
                                   "browser_download_url": file_url(bad)}]}, f)
        # run() must turn a corrupt archive into the ValueError that main() prints, never a BadZipFile traceback.
        # (An explicit release_url is the user's own choice, so the file:// URL is not restricted here.)
        with self.assertRaises(ValueError):
            jb.run("3.9.27", os.path.join(self.root, "out"), release_url=file_url(release))

    def test_download_url_from_the_release_api_must_be_https_on_github(self):
        for ok in ("https://github.com/joomla/joomla-cms/releases/download/3.9.27/a.zip",
                   "https://objects.githubusercontent.com/x"):
            jb.require_official_https(ok)
        for bad in ("http://github.com/a.zip", "file:///tmp/a.zip", "https://evil.example/github.com/a.zip", ""):
            with self.assertRaises(ValueError):
                jb.require_official_https(bad)


class RestoreFromManifest(Site):
    def _manifest(self, original, sha):
        q = write(self.root, "q/x.quarantine", "payload\n")
        m = {"version": "t", "start": os.path.join(self.root, "site"), "created": "t",
             "entries": [{"rel": "x", "original": original, "family": "backdoor", "sha256": sha,
                          "action": "quarantine", "quarantined": q}]}
        os.makedirs(os.path.join(self.root, "site"), exist_ok=True)
        path = os.path.join(self.root, "q", "manifest.json")
        with open(path, "w") as f:
            json.dump(m, f)
        return path, q

    def _restore(self, manifest):
        return h.run("clean_malware.py", ["--restore", manifest])

    def test_refuses_a_path_outside_the_recorded_site(self):
        outside = os.path.join(self.root, "outside.txt")
        manifest, q = self._manifest(outside, hashlib.sha256(b"payload\n").hexdigest())
        p = self._restore(manifest)
        self.assertFalse(os.path.exists(outside))
        self.assertTrue(os.path.exists(q))
        self.assertIn("REFUSED", p.out)
        self.assertEqual(p.returncode, 2)

    def test_refuses_a_swapped_quarantine_file(self):
        target = os.path.join(self.root, "site", "a.php")
        manifest, q = self._manifest(target, "0" * 64)
        p = self._restore(manifest)
        self.assertFalse(os.path.exists(target))
        self.assertIn("REFUSED", p.out)

    def test_a_valid_manifest_still_restores(self):
        target = os.path.join(self.root, "site", "a.php")
        manifest, q = self._manifest(target, hashlib.sha256(b"payload\n").hexdigest())
        p = self._restore(manifest)
        self.assertTrue(os.path.exists(target))
        self.assertEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
