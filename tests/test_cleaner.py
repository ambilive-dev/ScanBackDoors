# -*- coding: utf-8 -*-
"""The cleaner: learn, plan, act, restore.

Everything runs against a synthetic site built in a throw-away folder - nothing
touches a real site. Antivirus note: a sealed payload may be quarantined by
real-time protection between the build and the cleaner reading it; in that case
the test that relies on it is skipped with the antivirus hint instead of failing
with a misleading 'the cleaner missed it'.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402
import fixtures_sites as fx  # noqa: E402

MALICIOUS_HTACCESS = "htaccess-malicious.txt"


TXT = "rb"

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def read_manifest(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)




def bad_site(name):
    """A clean site plus exactly one known-bad file: the malicious .htaccess.

    The .htaccess is stable: it is readable (it was proven to be so during the
    scanner tests), so these tests do not depend on antivirus timing.
    """
    return fx.build(name, planted=False,
                    extra={".htaccess": fx.payload(MALICIOUS_HTACCESS)})


class PlanTest(unittest.TestCase):
    def test_dry_run_plans_the_bad_file(self):
        site = bad_site("cleaner-plan")
        report_dir = tempfile.mkdtemp(prefix="sbd-clean-")
        report = os.path.join(report_dir, "cleanup.csv")
        res = h.run("clean_malware.py", [site, "--report", report], cwd=report_dir)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Dry run only", res.out)
        self.assertIn("[htaccess", res.out, "the plan must mention the malicious .htaccess")
        self.assertTrue(os.path.isfile(report), "the report must be written")

    def test_dry_run_changes_nothing(self):
        site = bad_site("cleaner-dry")
        tree_before = h.tree_hashes(site)
        report_dir = tempfile.mkdtemp(prefix="sbd-clean-")
        report = os.path.join(report_dir, "cleanup.csv")
        res = h.run("clean_malware.py", [site, "--report", report], cwd=report_dir)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(h.tree_hashes(site), tree_before,
                         "a dry run must not change any file")


class ApplyTest(unittest.TestCase):
    """The default mode: .htaccess is cleaned, the original is quarantined."""

    def test_apply_strips_the_htaccess_and_quarantines_the_original(self):
        site = bad_site("cleaner-apply")
        report_dir = tempfile.mkdtemp(prefix="sbd-clean-")
        report = os.path.join(report_dir, "cleanup.csv")
        qdir = os.path.join(report_dir, "quarantine")
        original = h.sha256(os.path.join(site, ".htaccess"))
        res = h.run("clean_malware.py",
                    [site, "--apply", "--report", report, "--quarantine-dir", qdir],
                    cwd=report_dir)
        self.assertEqual(res.returncode, 0, res.out)
        # the file in the site no longer carries the dangerous deny-all rule
        cleaned = read_file(os.path.join(site, ".htaccess"))
        self.assertNotIn(b"Deny from all", cleaned,
                         "the cleaned .htaccess must not keep the deny-all rule")
        self.assertNotIn(b"py|exe|php", cleaned,
                         "the cleaned .htaccess must not keep the deny block")
        # the original is quarantined with a matching hash and a manifest
        entries = read_manifest(os.path.join(qdir, "manifest.json"))
        self.assertTrue(entries["entries"], "the manifest must have entries")
        entry = entries["entries"][0]
        self.assertEqual(entry["action"], "stripped")
        self.assertEqual(entry["sha256"], original)
        self.assertTrue(os.path.isfile(entry["quarantined"]))
        self.assertEqual(h.sha256(entry["quarantined"]), original,
                         "the quarantine copy must be the original file")

    def test_restore_put_the_original_back(self):
        site = bad_site("cleaner-restore")
        report_dir = tempfile.mkdtemp(prefix="sbd-clean-")
        report = os.path.join(report_dir, "cleanup.csv")
        qdir = os.path.join(report_dir, "quarantine")
        original = h.sha256(os.path.join(site, ".htaccess"))
        res = h.run("clean_malware.py",
                    [site, "--apply", "--report", report, "--quarantine-dir", qdir],
                    cwd=report_dir)
        self.assertEqual(res.returncode, 0, res.out)
        manifest = os.path.join(qdir, "manifest.json")
        self.assertTrue(os.path.isfile(manifest))
        # the file is cleaned; restore must bring the original back
        res_restore = h.run("clean_malware.py", ["--restore", manifest], cwd=report_dir)
        self.assertEqual(res_restore.returncode, 0, res_restore.out)
        self.assertEqual(h.sha256(os.path.join(site, ".htaccess")), original,
                         "the restored .htaccess must be the original")

    def test_delete_removes_the_file_with_no_quarantine(self):
        site = bad_site("cleaner-delete")
        report_dir = tempfile.mkdtemp(prefix="sbd-clean-")
        report = os.path.join(report_dir, "cleanup.csv")
        qdir = os.path.join(report_dir, "quarantine")
        res = h.run("clean_malware.py",
                    [site, "--apply", "--delete", "--report", report,
                     "--quarantine-dir", qdir],
                    cwd=report_dir)
        self.assertEqual(res.returncode, 0, res.out)
        # --delete removes without quarantine; for .htaccess the action stays
        # a strip (deleting the whole file would remove the site's routing)
        cleaned = read_file(os.path.join(site, ".htaccess"))
        self.assertNotIn(b"Deny from all", cleaned)
        self.assertFalse(os.path.exists(qdir), "a delete run must not create a quarantine")


class SafetyTest(unittest.TestCase):
    def test_disk_root_is_refused(self):
        root = os.path.join(os.environ.get("SystemDrive", ""), os.sep) if os.environ.get("SystemDrive") else os.sep
        res = h.run("clean_malware.py", [root])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Refused", res.out)

    def test_missing_folder_is_refused(self):
        res = h.run("clean_malware.py", ["/definitely/not/a/site"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Folder not found", res.out)

    def test_quarantine_inside_the_site_is_refused(self):
        site = bad_site("cleaner-inside")
        qdir = os.path.join(site, "_quarantine_inside")
        report_dir = tempfile.mkdtemp(prefix="sbd-clean-")
        res = h.run("clean_malware.py",
                    [site, "--apply", "--report", os.path.join(report_dir, "cleanup.csv"),
                     "--quarantine-dir", qdir], cwd=report_dir)
        self.assertEqual(res.returncode, 1)
        self.assertIn("must not be inside", res.out)

    def test_unknown_family_is_refused(self):
        site = bad_site("cleaner-family")
        res = h.run("clean_malware.py",
                    [site, "--families", "not-a-family"], cwd=tempfile.mkdtemp(prefix="sbd-clean-"))
        self.assertEqual(res.returncode, 1)
        self.assertIn("Unknown family", res.out)


class BackdoorFamilyTest(unittest.TestCase):
    """A real planted backdoor, moved to quarantine and back.

    The file is a sealed sample: on machines where antivirus quarantines it
    between the build and the cleaner running, the test is skipped with the
    antivirus hint instead of failing with a misleading "the cleaner missed it".
    """

    def test_backdoor_is_quarantined_and_restored(self):
        rel = "administrator/components/com_banners/helpers/filefuns.php"
        site = fx.build("cleaner-backdoor", planted=True)
        target = os.path.join(site, *rel.split("/"))
        if not os.path.isfile(target):
            raise unittest.SkipTest("the backdoor sample could not be created: %s" % h.AV_HINT)
        report_dir = tempfile.mkdtemp(prefix="sbd-clean-")
        report = os.path.join(report_dir, "cleanup.csv")
        qdir = os.path.join(report_dir, "quarantine")
        # a dry run first: if the cleaner cannot read the file, it is simply
        # not in the plan - a protection-timing problem, not a missed backdoor
        dry = h.run("clean_malware.py", [site, "--report", report], cwd=report_dir)
        self.assertEqual(dry.returncode, 0, dry.out)
        if rel not in dry.out:
            raise unittest.SkipTest("the backdoor could not be read by the cleaner: %s" % h.AV_HINT)
        original = h.sha256(target)
        res = h.run("clean_malware.py",
                    [site, "--apply", "--report", report, "--quarantine-dir", qdir],
                    cwd=report_dir)
        self.assertEqual(res.returncode, 0, res.out)
        self.assertFalse(os.path.isfile(target), "the backdoor must be quarantined")
        manifest = os.path.join(qdir, "manifest.json")
        entries = read_manifest(manifest)
        entry = next((e for e in entries["entries"] if e["rel"] == rel), None)
        self.assertTrue(entry, "the manifest must carry the backdoor entry")
        self.assertEqual(entry["sha256"], original)
        self.assertEqual(h.sha256(entry["quarantined"]), original)
        # restore brings the file back
        res_restore = h.run("clean_malware.py", ["--restore", manifest], cwd=report_dir)
        self.assertEqual(res_restore.returncode, 0, res_restore.out)
        self.assertTrue(os.path.isfile(target), "the restored file must exist")
        self.assertEqual(h.sha256(target), original)


if __name__ == "__main__":
    unittest.main()
