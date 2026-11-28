# -*- coding: utf-8 -*-
"""The baseline fetcher: the real CLI against a local stand-in for the GitHub API.

The harness runs tools as separate processes and never imports their internals,
so the network seam is the internal --release-url flag: a local release JSON
whose Full_Package asset points at a local zip (file:// URLs are plain urllib).
No test touches the network.
"""

import json
import os
import shutil
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

SCRIPT = "joomla_baseline.py"


def asset(name, url, digest=None, size=100):
    return {"name": name, "size": size, "digest": digest, "browser_download_url": url}


def fake_release(assets, tag="3.9.27"):
    """A local stand-in for the GitHub release API. Returns the JSON path."""
    fd, path = h.workfile("sbd-rel-", ".json")
    os.close(fd)
    with open(path, "w") as f:
        json.dump({"tag_name": tag, "assets": assets}, f)
    return path


class CliTest(unittest.TestCase):
    def test_version_output(self):
        res = h.run(SCRIPT, ["--version"])
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.out.strip(), "joomla_baseline %s" % h.bundle_version())

    def test_help_lists_the_user_flags(self):
        res = h.run(SCRIPT, ["--help"])
        self.assertEqual(res.returncode, 0)
        for flag in ("--out", "--force", "--keep-archive"):
            self.assertIn(flag, res.out)

    def test_valid_version_reaches_the_pipeline(self):
        z = fake_joomla_zip("cli1")
        p = release_for(z, "3.9.27")
        res = h.run(SCRIPT, ["3.9.27", "--out", h.workdir("sbd-bl-"),
                             "--release-url", Path(p).as_uri()])
        self.assertNotIn("Invalid version", res.out)
        self.assertIn("Done: clean Joomla 3.9.27", res.out)

    def test_bad_versions_are_rejected(self):
        for bad in ("3.9", "3.9.27.1", "latest", "..", "a b", "3.9.27/../../x"):
            res = h.run(SCRIPT, [bad, "--out", h.workdir("sbd-bl-")])
            self.assertEqual(res.returncode, 1, "%s: %s" % (bad, res.out))
            self.assertIn("Invalid version", res.out)


class SelectionTest(unittest.TestCase):
    def test_no_full_package_asset(self):
        p = fake_release([asset("Joomla_3.9.27-Stable-Update_Package.zip", "file:///nope")])
        res = h.run(SCRIPT, ["3.9.27", "--out", h.workdir("sbd-bl-"),
                             "--release-url", Path(p).as_uri()])
        self.assertEqual(res.returncode, 1, res.out)
        self.assertIn("No Full_Package.zip asset", res.out)
        self.assertIn("Update_Package", res.out)

    def test_ambiguous_selection(self):
        p = fake_release([asset("Joomla_3.9.27-Stable-Full_Package.zip", "file:///nope"),
                          asset("Joomla_3.9.27-Other-Full_Package.zip", "file:///nope")])
        res = h.run(SCRIPT, ["3.9.27", "--out", h.workdir("sbd-bl-"),
                             "--release-url", Path(p).as_uri()])
        self.assertEqual(res.returncode, 1, res.out)
        self.assertIn("Ambiguous release", res.out)


def fake_joomla_zip(name, version="3.9.27", style="j4", wrapper=False, slip=None):
    """A fake Joomla distribution as a real zip. Returns the zip path.

    style "j4": libraries/src/Version.php with const MAJOR/MINOR/PATCH_VERSION
    style "j3": libraries/cms/version/version.php with const RELEASE / DEV_LEVEL
    wrapper: every entry nested under a single top folder
    slip: an extra member (like "../evil.txt") for the zip-slip test
    """
    major, minor, patch = version.split(".")
    root = h.workdir("sbd-jz-%s-" % name)
    files = {"index.php": "<?php\ndefined('_JEXEC') or die;\n",
             "libraries/vendor/autoload.php": "<?php\n// fake vendor file\n"}
    if style == "j4":
        files["libraries/src/Version.php"] = (
            "<?php\n\nclass Version\n{\n"
            "\tconst MAJOR_VERSION = %s;\n"
            "\tconst MINOR_VERSION = %s;\n"
            "\tconst PATCH_VERSION = %s;\n"
            "\tconst RELEASE = '%s';\n"
            "\tconst DEV_LEVEL = '0';\n"
            "}\n" % (major, minor, patch, version))
    else:
        files["libraries/cms/version/version.php"] = (
            "<?php\n\nclass JVersion\n{\n"
            "\tconst RELEASE = '%s.%s';\n"
            "\tconst DEV_LEVEL = '%s';\n"
            "}\n" % (major, minor, patch))
    for rel, text in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
    fd, zip_path = h.workfile("sbd-jz-%s-" % name, ".zip")
    os.close(fd)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in files:
            arc = ("Joomla_%s-Stable/" % version + rel) if wrapper else rel
            z.write(os.path.join(root, *rel.split("/")), arc)
        if slip:
            z.writestr(slip, "pwned")
    shutil.rmtree(root, ignore_errors=True)
    return zip_path


def release_for(zip_path, version, digest=None, extra_assets=()):
    """Release JSON (via fake_release) whose Full_Package asset points at zip_path.

    digest: a string like "sha256:<hex>" becomes the JSON digest field verbatim
    (the zip's real hash for the match tier, a wrong hash for the mismatch test);
    digest=None makes the JSON digest field null (the self-check tier).
    """
    assets = [asset("Joomla_%s-Stable-Full_Package.zip" % version,
                    Path(zip_path).as_uri(), digest=digest,
                    size=os.path.getsize(zip_path))]
    assets.extend(extra_assets)
    return fake_release(assets, tag=version)


def run_fetch(version, out, json_path, *extra):
    return h.run(SCRIPT, [version, "--out", out,
                          "--release-url", Path(json_path).as_uri()] + list(extra))


class PipelineTest(unittest.TestCase):
    def test_happy_path_sha256_tier(self):
        z = fake_joomla_zip("ok1")
        p = release_for(z, "3.9.27", digest="sha256:" + h.sha256(z),
                        extra_assets=[asset("Joomla_3.9.27-Stable-Update_Package.zip", "file:///nope")])
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 0, res.out)
        tree = os.path.join(out, "Joomla_3.9.27")
        self.assertTrue(os.path.isfile(os.path.join(tree, "index.php")))
        man = h.read_json(os.path.join(out, "Joomla_3.9.27.baseline.json"))
        self.assertEqual(man["schema"], 1)
        self.assertEqual(man["version"], "3.9.27")
        self.assertEqual(man["verified_by"], "sha256")
        self.assertEqual(man["archive_sha256"], h.sha256(z))
        self.assertEqual(man["files"], h.tree_hashes(tree))
        self.assertFalse(os.path.exists(os.path.join(out, "Joomla_3.9.27.zip")),
                         "the zip must be removed by default")
        self.assertIn("--baseline-dir", res.out)
        self.assertIn("Done: clean Joomla 3.9.27", res.out)

    def test_happy_path_version_file_tier(self):
        z = fake_joomla_zip("ok2")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 0, res.out)
        man = h.read_json(os.path.join(out, "Joomla_3.9.27.baseline.json"))
        self.assertEqual(man["verified_by"], "version-file")

    def test_digest_mismatch_aborts(self):
        z = fake_joomla_zip("bad1")
        p = release_for(z, "3.9.27", digest="sha256:" + "0" * 64)
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 1, res.out)
        self.assertIn("sha256 mismatch", res.out)
        self.assertIn("0" * 64, res.out)
        self.assertIn(h.sha256(z), res.out)
        self.assertFalse(os.path.exists(os.path.join(out, "Joomla_3.9.27")))
        self.assertFalse(os.path.exists(os.path.join(out, "Joomla_3.9.27.baseline.json")))
        self.assertFalse(os.path.exists(os.path.join(out, "Joomla_3.9.27.zip")))

    def test_self_check_mismatch_aborts(self):
        z = fake_joomla_zip("bad2", version="3.9.26")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 1, res.out)
        self.assertIn("reports Joomla 3.9.26 but 3.9.27 was requested", res.out)
        self.assertFalse(os.path.exists(os.path.join(out, "Joomla_3.9.27")))

    def test_keeps_archive_with_flag(self):
        z = fake_joomla_zip("keep1")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.9.27", out, p, "--keep-archive")
        self.assertEqual(res.returncode, 0, res.out)
        self.assertTrue(os.path.isfile(os.path.join(out, "Joomla_3.9.27.zip")))

    def test_cache_hit_needs_no_release_url(self):
        z = fake_joomla_zip("cache1")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        self.assertEqual(run_fetch("3.9.27", out, p).returncode, 0)
        os.remove(p)                          # the stand-in for GitHub disappears
        res = run_fetch("3.9.27", out, p)     # the cache must be enough
        self.assertEqual(res.returncode, 0, res.out)
        self.assertIn("OK: baseline verified from cache", res.out)

    def test_force_bypasses_a_valid_cache(self):
        z = fake_joomla_zip("cache2")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        self.assertEqual(run_fetch("3.9.27", out, p).returncode, 0)
        os.remove(p)
        res = run_fetch("3.9.27", out, p, "--force")
        self.assertEqual(res.returncode, 1, res.out)   # the fetch is required and its URL is gone

    def test_corrupted_cache_refetches(self):
        z = fake_joomla_zip("cache3")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        self.assertEqual(run_fetch("3.9.27", out, p).returncode, 0)
        target = os.path.join(out, "Joomla_3.9.27", "libraries", "vendor", "autoload.php")
        with open(target, "a") as f:
            f.write("// tampered")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 0, res.out)
        with open(target) as f:
            self.assertEqual(f.read(), "<?php\n// fake vendor file\n")
        man = h.read_json(os.path.join(out, "Joomla_3.9.27.baseline.json"))
        self.assertEqual(man["files"], h.tree_hashes(os.path.join(out, "Joomla_3.9.27")))

    def test_missing_cache_file_refetches(self):
        z = fake_joomla_zip("cache4")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        self.assertEqual(run_fetch("3.9.27", out, p).returncode, 0)
        os.remove(os.path.join(out, "Joomla_3.9.27", "libraries", "src", "Version.php"))
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 0, res.out)
        self.assertTrue(os.path.isfile(
            os.path.join(out, "Joomla_3.9.27", "libraries", "src", "Version.php")))

    def test_zip_slip_is_refused(self):
        z = fake_joomla_zip("slip1", slip="../evil.txt")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 1, res.out)
        self.assertIn("Refusing an unsafe path", res.out)
        self.assertFalse(os.path.exists(os.path.join(out, "evil.txt")))
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(out), "evil.txt")))
        self.assertFalse(os.path.exists(os.path.join(out, "Joomla_3.9.27")))

    def test_wrapper_folder_is_stripped(self):
        z = fake_joomla_zip("wrap1", wrapper=True)
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 0, res.out)
        self.assertTrue(os.path.isfile(os.path.join(out, "Joomla_3.9.27", "index.php")))
        self.assertFalse(os.path.exists(
            os.path.join(out, "Joomla_3.9.27", "Joomla_3.9.27-Stable")))

    def test_stale_transients_are_cleaned(self):
        z = fake_joomla_zip("stale1")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        os.makedirs(os.path.join(out, ".tmp-3.9.27"))
        with open(os.path.join(out, "Joomla_3.9.27.zip.part"), "wb") as f:
            f.write(b"junk")
        with open(os.path.join(out, ".tmp-3.9.27", "junk.txt"), "w") as f:
            f.write("junk")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 0, res.out)
        self.assertFalse(os.path.exists(os.path.join(out, "Joomla_3.9.27.zip.part")))
        self.assertFalse(os.path.exists(os.path.join(out, ".tmp-3.9.27")))
        self.assertTrue(os.path.isfile(os.path.join(out, "Joomla_3.9.27", "index.php")))

    def test_j37_style_self_check(self):
        z = fake_joomla_zip("j37", version="3.7.5", style="j3")
        p = release_for(z, "3.7.5")
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.7.5", out, p)
        self.assertEqual(res.returncode, 0, res.out)
        man = h.read_json(os.path.join(out, "Joomla_3.7.5.baseline.json"))
        self.assertEqual(man["verified_by"], "version-file")
        self.assertEqual(man["version"], "3.7.5")

    def test_mixed_layout_archive_is_refused(self):
        # one wrapper folder plus a stray root-level file: the layout is
        # unsupported (not unsafe) and must say so
        fd, z = h.workfile("sbd-jz-mix-", ".zip")
        os.close(fd)
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Joomla_3.9.27-Stable/index.php", "<?php\necho 1;\n")
            zf.writestr("Joomla_3.9.27-Stable/libraries/src/Version.php", "x")
            zf.writestr("stray.txt", "stray")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 1, res.out)
        self.assertIn("mixes a top-level folder with root-level files", res.out)
        self.assertNotIn("Refusing an unsafe path", res.out)
        self.assertFalse(os.path.exists(os.path.join(out, "Joomla_3.9.27")))

    def test_malformed_release_object_is_rejected(self):
        # a mirror can answer with a JSON array; that is an error, not a traceback
        fd, p = h.workfile("sbd-rel-", ".json")
        os.close(fd)
        with open(p, "w") as f:
            json.dump([1, 2, 3], f)
        res = h.run(SCRIPT, ["3.9.27", "--out", h.workdir("sbd-bl-"),
                             "--release-url", Path(p).as_uri()])
        self.assertEqual(res.returncode, 1, res.out)
        self.assertIn("malformed object", res.out)
        self.assertNotIn("Traceback", res.out)

    def test_unverifiable_digest_warns_and_uses_self_check(self):
        # a digest in a form the tool does not verify (hypothetical sha512:)
        # must not be treated as verification; the self-check tier applies
        z = fake_joomla_zip("dg1")
        p = release_for(z, "3.9.27", digest="sha512:" + "0" * 128)
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 0, res.out)
        self.assertIn("we do not verify", res.out)
        man = h.read_json(os.path.join(out, "Joomla_3.9.27.baseline.json"))
        self.assertEqual(man["verified_by"], "version-file")

    def test_lost_manifest_refetches(self):
        # the tree is intact but its manifest was lost: the cache can no longer
        # be verified offline, so the tool re-downloads and restores it
        z = fake_joomla_zip("cache5")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        self.assertEqual(run_fetch("3.9.27", out, p).returncode, 0)
        os.remove(os.path.join(out, "Joomla_3.9.27.baseline.json"))
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 0, res.out)
        self.assertTrue(os.path.isfile(os.path.join(out, "Joomla_3.9.27.baseline.json")))
        self.assertTrue(os.path.isfile(os.path.join(out, "Joomla_3.9.27", "index.php")))

    def test_progress_never_reports_zero(self):
        # an archive over 1 MB produces progress lines, and the first is 1 MB
        # (or 10%), never "Downloaded 0"
        root = h.workdir("sbd-jz-big-")
        os.makedirs(os.path.join(root, "libraries", "src"))
        with open(os.path.join(root, "index.php"), "w") as f:
            f.write("<?php\necho 1;\n")
        with open(os.path.join(root, "libraries", "src", "Version.php"), "w") as f:
            f.write("<?php\n\nclass Version\n{\n\tconst MAJOR_VERSION = 3;\n"
                    "\tconst MINOR_VERSION = 9;\n\tconst PATCH_VERSION = 27;\n}\n")
        blob = os.path.join(root, "big.bin")
        with open(blob, "wb") as f:
            f.write(os.urandom(1536 * 1024))
        fd, z = h.workfile("sbd-jz-big-", ".zip")
        os.close(fd)
        with zipfile.ZipFile(z, "w") as zf:
            zf.write(os.path.join(root, "index.php"), "index.php")
            zf.write(os.path.join(root, "libraries", "src", "Version.php"),
                     "libraries/src/Version.php")
            zf.write(blob, "big.bin")
        shutil.rmtree(root, ignore_errors=True)
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        res = run_fetch("3.9.27", out, p)
        self.assertEqual(res.returncode, 0, res.out)
        self.assertIn("Downloaded", res.out)
        self.assertNotIn("Downloaded 0", res.out)


class ScannerManifestTest(unittest.TestCase):
    """The scanner's fast path: joomla_baseline.py writes the sha256 manifest right after
    the download, and build_baseline() reuses it instead of re-hashing thousands of files."""

    def _fetch(self):
        z = fake_joomla_zip("man1")
        p = release_for(z, "3.9.27")
        out = h.workdir("sbd-bl-")
        self.assertEqual(run_fetch("3.9.27", out, p).returncode, 0)
        return os.path.join(out, "Joomla_3.9.27"), os.path.join(out, "Joomla_3.9.27.baseline.json")

    def test_scanner_reuses_the_manifest_hashes(self):
        tree, _man = self._fetch()
        res, _report = h.scan(tree, "--baseline-dir", tree)
        self.assertIn("3 reused from the manifest, 0 hashed now", res.out)

    def test_without_a_manifest_everything_is_hashed_normally(self):
        tree, man = self._fetch()
        os.remove(man)
        res, _report = h.scan(tree, "--baseline-dir", tree)
        self.assertNotIn("reused from the manifest", res.out)
        self.assertNotIn("Traceback", res.out)

    def test_files_missing_from_the_manifest_are_hashed_now(self):
        tree, man = self._fetch()
        with open(os.path.join(tree, "cron.php"), "w") as f:
            f.write("<?php\ndefined('_JEXEC') or die;\n")      # added to the tree by hand
        res, _report = h.scan(tree, "--baseline-dir", tree)
        self.assertIn("3 reused from the manifest, 1 hashed now", res.out)


if __name__ == "__main__":
    unittest.main()
