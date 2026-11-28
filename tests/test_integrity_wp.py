# -*- coding: utf-8 -*-
"""TZ v2 Sprint 3: engines/integrity_wp.py - comparing a site with the official release.

The "official catalogue" here is a dict the test builds with MD5 of its own
fixtures: the service is exercised in tests/test_cms_api.py, and what matters
here is the comparison - what counts as modified, what counts as extra, and what
must never be reported at all.
"""

import hashlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

sys.path.insert(0, h.REPO)

from engines import integrity_wp as ic  # noqa: E402

CORE = {
    "index.php": "<?php\n// WordPress bootstrap\n",
    "wp-login.php": "<?php\n// login\n",
    "wp-settings.php": "<?php\n// settings\n",
    "wp-cron.php": "<?php\n// cron\n",
    "wp-includes/version.php": "<?php\n$wp_version = '6.4.2';\n",
    "wp-includes/l10n.php": "<?php\n// l10n\n",
    "wp-includes/js/jquery/jquery.js": "jQuery stub\n",
    "wp-includes/images/blank.gif": b"GIF89a\x00",
    "wp-admin/index.php": "<?php\n// admin\n",
    "wp-admin/css/common.css": "body{}\n",
    "readme.html": "<h1>WordPress</h1>\n",
    "license.txt": "GPL\n",
    "wp-content/themes/twentytwentythree/style.css": "/* Theme */\n",
    "wp-content/themes/twentytwentythree/functions.php": "<?php\n// theme\n",
}


def md5_of(content):
    data = content if isinstance(content, bytes) else content.encode("utf-8")
    return hashlib.md5(data).hexdigest()


def make_site(files=None):
    site = h.workdir("integ-site-")
    all_files = dict(CORE)
    all_files.update(files or {})
    write_tree(site, all_files)
    return site


def write_tree(site, files):
    """Write the bytes the catalogue will hash: text is written as UTF-8 with
    plain \\n, because the MD5 of the fixture is computed over those bytes and a
    Windows text mode would quietly turn them into \\r\\n."""
    for rel, content in files.items():
        path = os.path.join(site, *rel.split("/"))
        folder = os.path.dirname(path)
        if not os.path.isdir(folder):
            os.makedirs(folder)
        data = content if isinstance(content, bytes) else content.encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(data)
    return site


def catalogue(files=None):
    return {rel: md5_of(content) for rel, content in (files or CORE).items()}


class CleanSiteTest(unittest.TestCase):
    def test_a_site_that_matches_reports_nothing(self):
        site = make_site()
        report = ic.check_core(site, catalogue(), version="6.4.2")
        self.assertTrue(report["complete"])
        self.assertEqual(report["modified"], [])
        self.assertEqual(report["extra"], [])
        self.assertEqual(report["missing"], [])
        self.assertEqual(report["soft"], [])
        self.assertEqual(report["verified"], len(CORE))
        self.assertEqual(ic.summarize(report)["modified"], 0)

    def test_verified_paths_are_the_files_content_engines_may_skip(self):
        site = make_site()
        report = ic.check_core(site, catalogue())
        self.assertIn("wp-includes/version.php", report["verified_paths"])
        self.assertTrue(report["complete"], "a complete report may be used for skipping")

    def test_site_own_files_are_not_extra(self):
        site = make_site({
            "wp-config.php": "<?php\n// real credentials here\n",
            ".htaccess": "RewriteEngine On\n",
            "wp-content/plugins/akismet/akismet.php": "<?php\n// plugin\n",
            "wp-content/uploads/2026/11/pic.jpg": b"\xff\xd8\xff",
            "wp-content/themes/custom-child/style.css": "/* own theme */\n",
            "web.config": "<configuration/>\n",
        })
        report = ic.check_core(site, catalogue())
        self.assertEqual(report["extra"], [],
                         "a WordPress site is allowed to have its own files")


class DifferenceTest(unittest.TestCase):
    def test_a_modified_core_file_is_found(self):
        site = make_site({"wp-includes/version.php": "<?php\n$wp_version = '6.4.2';\n"
                                                      "// and a little something more\n"})
        report = ic.check_core(site, catalogue(), version="6.4.2")
        self.assertEqual([row["path"] for row in report["modified"]],
                         ["wp-includes/version.php"])
        self.assertNotIn("wp-includes/version.php", report["verified_paths"],
                         "a file that does not match may never be skipped as clean")
        self.assertTrue(report["complete"], "a definite answer about a file is complete, "
                                           "even when the answer is bad news")

    def test_an_extra_php_file_in_wp_admin_is_found(self):
        site = make_site({"wp-admin/network/about.php": "<?php system($_GET[0]);\n",
                          "wp-includes/images/blank2.gif": b"GIF89a\x00"})
        report = ic.check_core(site, catalogue())
        paths = {row["path"]: row["php"] for row in report["extra"]}
        self.assertEqual(sorted(paths), ["wp-admin/network/about.php",
                                         "wp-includes/images/blank2.gif"])
        self.assertTrue(paths["wp-admin/network/about.php"])
        self.assertFalse(paths["wp-includes/images/blank2.gif"],
                         "a gif is not code, but it is still not part of the release")

    def test_a_new_php_file_at_the_root_is_found_but_a_config_is_not(self):
        site = make_site({"wp-cache-backdoor.php": "<?php\n",
                          "wp-config.php": "<?php\n// real config\n",
                          "robots.txt": "User-agent: *\n"})
        report = ic.check_core(site, catalogue())
        self.assertEqual([row["path"] for row in report["extra"]], ["wp-cache-backdoor.php"])

    def test_a_missing_core_file_is_found(self):
        site = make_site()
        os.remove(os.path.join(site, "wp-login.php"))
        report = ic.check_core(site, catalogue())
        self.assertEqual(report["missing"], ["wp-login.php"])

    def test_a_language_file_difference_is_soft(self):
        site = make_site({"license.txt": "GPL, but translated by the hoster\n",
                          "readme.html": "<h1>WordPress</h1>\n<p>modified</p>\n"})
        report = ic.check_core(site, catalogue())
        self.assertEqual(report["modified"], [], "a translated licence is not a backdoor")
        self.assertEqual(sorted(row["path"] for row in report["soft"]),
                         ["license.txt", "readme.html"])

    def test_a_bundled_theme_family_is_watchable_but_another_theme_is_not(self):
        site = make_site({
            "wp-content/themes/twentytwentythree/js/backdoor.php": "<?php\n",
            "wp-content/themes/myown/inc/helper.php": "<?php\n",
        })
        report = ic.check_core(site, catalogue())
        self.assertEqual([row["path"] for row in report["extra"]],
                         ["wp-content/themes/twentytwentythree/js/backdoor.php"])

    def test_a_non_code_file_next_to_a_bundled_theme_is_not_reported(self):
        site = make_site({"wp-content/themes/twentytwentythree/screenshot-help.png": b"\x89PNG"})
        self.assertEqual(ic.check_core(site, catalogue())["extra"], [])


class LimitsTest(unittest.TestCase):
    def test_without_a_reference_nothing_is_verified(self):
        site = make_site()
        report = ic.check_core(site, {}, version="6.4.2")
        self.assertFalse(report["complete"])
        self.assertEqual(report["verified"], 0)
        self.assertEqual(report["extra"], [], "no reference means no verdict, not 'all extra'")
        self.assertEqual(report["missing"], [])

    def test_the_file_cap_makes_the_report_incomplete(self):
        site = make_site()
        report = ic.check_core(site, catalogue(), max_files=3)
        self.assertLessEqual(report["files_hashed"], 3)
        self.assertFalse(report["complete"])

    def test_an_oversized_file_is_unreadable_not_verified(self):
        site = make_site({"wp-includes/l10n.php": "<?php\n" + "//" + "x" * 5000 + "\n"})
        original = ic.MAX_FILE
        try:
            ic.MAX_FILE = 64
            report = ic.check_core(site, catalogue())
        finally:
            ic.MAX_FILE = original
        self.assertEqual(report["unreadable"], 1)
        self.assertFalse(report["complete"])
        self.assertNotIn("wp-includes/l10n.php", report["verified_paths"])

    def test_a_huge_extra_file_is_never_hashed(self):
        site = make_site({"wp-admin/tools/bomb.php": "<?php\n" + "x" * 20000 + "\n"})
        original = ic.MAX_FILE
        try:
            ic.MAX_FILE = 1024
            report = ic.check_core(site, catalogue())
        finally:
            ic.MAX_FILE = original
        self.assertEqual(report["unreadable"], 1)
        self.assertEqual(report["extra"], [])

    def test_a_symlink_inside_the_core_is_not_hashed(self):
        site = make_site()
        target = h.workdir("integ-outside-")
        with open(os.path.join(target, "secret.txt"), "w", encoding="utf-8") as fh:
            fh.write("not part of WordPress")
        link = os.path.join(site, "wp-includes", "passwd-link")
        try:
            os.symlink(os.path.join(target, "secret.txt"), link)
        except (OSError, AttributeError):
            self.skipTest("creating a symlink needs privileges here")
        report = ic.check_core(site, catalogue())
        self.assertNotIn("wp-includes/passwd-link",
                         [row["path"] for row in report["extra"]])

    def test_an_empty_site_is_not_an_error(self):
        report = ic.check_core(h.workdir("integ-empty-"), catalogue())
        expected = sorted(rel for rel in CORE if rel not in ic.SOFT_NAMES)
        self.assertEqual(report["missing"], expected)
        self.assertEqual(sorted(row["path"] for row in report["soft"]),
                         sorted(set(CORE) - set(expected)),
                         "a missing readme or licence is soft, not a finding")
        self.assertEqual(report["verified"], 0)


class FindingsTest(unittest.TestCase):
    def test_every_kind_of_difference_becomes_one_row_per_file(self):
        site = make_site({"wp-login.php": "<?php\n// trojan\n",
                          "wp-admin/mine.php": "<?php\n"})
        os.remove(os.path.join(site, "wp-cron.php"))
        catalogue_files = dict(CORE)
        catalogue_files["wp-cron.php"] = "<?php\n// cron\n"
        report = ic.check_core(site, catalogue(catalogue_files), version="6.4.2")
        rows = ic.findings(report)
        by_path = {rel: (label, detail) for rel, label, detail in rows}
        self.assertIn("wp-login.php", by_path)
        self.assertIn("checksum", by_path["wp-login.php"][0].lower())
        self.assertIn("official", by_path["wp-login.php"][1].lower(),
                      "'modified' without naming the reference is not evidence")
        self.assertTrue(any("does not ship" in label for _p, label, _d in rows))
        self.assertTrue(any("missing" in label for _p, label, _d in rows))
        self.assertIn("wp-admin/mine.php", by_path)

    def test_a_report_with_nothing_wrong_has_no_findings(self):
        site = make_site()
        self.assertEqual(ic.findings(ic.check_core(site, catalogue())), [])

    def test_summarize_of_no_check_at_all(self):
        self.assertEqual(ic.summarize(None), {"checked": False})


if __name__ == "__main__":
    unittest.main()
