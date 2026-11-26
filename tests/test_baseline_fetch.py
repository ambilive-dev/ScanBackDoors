# -*- coding: utf-8 -*-
"""The baseline fetcher: the real CLI against a local stand-in for the GitHub API.

The harness runs tools as separate processes and never imports their internals,
so the network seam is the internal --release-url flag: a local release JSON
whose Full_Package asset points at a local zip (file:// URLs are plain urllib).
No test touches the network.
"""

import json
import os
import sys
import unittest
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
        p = fake_release([asset("Joomla_3.9.27-Stable-Full_Package.zip", "file:///nope")])
        res = h.run(SCRIPT, ["3.9.27", "--out", h.workdir("sbd-bl-"),
                             "--release-url", Path(p).as_uri()])
        self.assertNotIn("Invalid version", res.out)
        self.assertIn("Download not wired yet", res.out)   # Task 2 placeholder; replaced by Task 3

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


if __name__ == "__main__":
    unittest.main()
