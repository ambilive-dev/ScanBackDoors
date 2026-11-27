# -*- coding: utf-8 -*-
"""data/whitelist-known-clean.txt is published as a dataset: it must stay clean, useful and private."""

import io
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
import harness as h  # noqa: E402
import scan_backdoors as sb  # noqa: E402

ALLOWLIST = h.WHITELIST
HEX64 = re.compile(r"^[0-9a-f]{64}$")
# absolute local paths, UNC shares, and e-mail addresses must never ship.
# A relative path inside a vendor folder (administrator/components/...) is
# legitimate documentation, so only genuinely absolute forms are forbidden.
LOCAL_PATH = re.compile(
    r"(?i)[a-z]:[\\/]"                                   # drive-letter paths
    r"|\\\\[A-Za-z0-9_.-]+\\\\"                          # UNC share
    r"|(?:^|[\s#;])/(?:users|home|var|web|www|inetpub|opt|srv|etc|tmp)/"  # absolute unix
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def entries():
    """[(kind, value, comment)] of the allowlist; kind is 'hash', 'path' or 'comment'."""
    out = []
    with io.open(ALLOWLIST, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n").rstrip("\r")
            body, _, comment = line.partition("#")
            body, comment = body.strip(), comment.strip()
            if not body:
                if comment:
                    out.append(("comment", "", comment))
                continue
            out.append(("hash" if HEX64.match(body) else "path", body, comment))
    return out


class ShippedAllowlistTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(ALLOWLIST):
            raise unittest.SkipTest("data/whitelist-known-clean.txt is missing")
        cls.rows = entries()
        cls.hashes = [v for k, v, _ in cls.rows if k == "hash"]
        cls.paths = [v for k, v, _ in cls.rows if k == "path"]

    def test_it_is_a_dataset_not_a_scratch_file(self):
        self.assertGreaterEqual(len(self.hashes), 3000,
                                "the published allowlist shrank: it is the reason the tool has no noise")
        self.assertEqual(len(self.hashes), len(set(self.hashes)), "duplicate hashes")
        for value in self.hashes:
            self.assertTrue(HEX64.match(value), "%r is not a lower-case SHA-256" % value)

    def test_every_hash_has_a_comment(self):
        """Most entries must explain themselves; the bare ones are inherited.

        27 bare hashes come straight from the original WhiteList.txt (where they
        had no comment); that is documented here instead of inventing reasons.
        The bar is deliberately high and only falls when the gap grows.
        """
        commented = sum(1 for k, _v, c in self.rows if k == "hash" and c)
        bare = len(self.hashes) - commented
        self.assertGreaterEqual(commented / float(len(self.hashes)), 0.95,
                                "fewer than 95%% of hashes carry a comment")
        self.assertLessEqual(bare, 35,
                             "the set of unexplained inherited hashes grew beyond the known 27")

    def test_it_holds_nothing_about_a_particular_customer(self):
        """Local paths, e-mails and absolute filesystem paths must never ship."""
        bad = []
        for kind, value, comment in self.rows:
            for field in (value, comment):
                if LOCAL_PATH.search(field):
                    bad.append("local path: %s" % field[:80])
                if EMAIL.search(field):
                    bad.append("e-mail: %s" % field[:80])
        self.assertFalse(bad, "the allowlist leaks something:\n  " + "\n  ".join(sorted(set(bad))[:10]))

    def test_the_scanner_reads_it_without_complaining(self):
        hashes, paths, problems = sb.load_whitelist(ALLOWLIST)
        self.assertEqual(len(hashes), len(set(self.hashes)))
        self.assertEqual(sorted(paths), sorted(self.paths))
        self.assertEqual(problems, [], "the shipped allowlist must parse without malformed lines")


class AllowlistFormatTest(unittest.TestCase):
    """--whitelist format: hashes, folders, masks; '#' starts a comment."""

    def parse(self, text):
        fd, path = h.workfile("sbd-wl-", ".txt")
        os.close(fd)
        try:
            with io.open(path, "w", encoding="utf-8") as f:
                f.write(text)
            return sb.load_whitelist(path)
        finally:
            os.remove(path)

    def test_comments_blank_lines_and_case(self):
        hashes, paths, problems = self.parse("# a comment\n\n  AA00" + "0" * 60 + "  # why it is clean\n")
        self.assertEqual(hashes, {"aa00" + "0" * 60})
        self.assertEqual(paths, [])
        self.assertEqual(problems, [])

    def test_paths_masks_and_normalisation(self):
        _hashes, paths, problems = self.parse("./components/com_x/\n\\media\\com_y\\\n*.min.js\n/templates/foo.php\n")
        self.assertEqual(paths, ["components/com_x/", "media/com_y/", "*.min.js", "templates/foo.php"])
        self.assertEqual(problems, [])

    def test_a_broken_line_is_reported_not_silently_a_path(self):
        hashes, paths, problems = self.parse("deadbeef\n")
        self.assertEqual(hashes, set())
        self.assertEqual(paths, [])
        self.assertEqual(problems, [(1, "hex string with 8 chars (a SHA-256 needs 64)", "deadbeef")])

    def test_path_matching_is_by_folder_or_mask(self):
        self.assertTrue(sb.path_whitelisted("media/com_x/anything.js", ["media/com_x/"]))
        # a mask never spans folders: "*.js" is a top-level file, not any .js anywhere;
        # an in-folder mask keeps working
        self.assertFalse(sb.path_whitelisted("media/com_x/anything.js", ["*.js"]))
        self.assertTrue(sb.path_whitelisted("anything.js", ["*.js"]))
        self.assertTrue(sb.path_whitelisted("media/com_x/anything.js", ["media/com_x/*.js"]))
        self.assertFalse(sb.path_whitelisted("media/com_x/anything.js", ["media/com_y/"]))
        self.assertFalse(sb.path_whitelisted("media/com_xextra/a.js", ["media/com_x/"]))


if __name__ == "__main__":
    unittest.main()
