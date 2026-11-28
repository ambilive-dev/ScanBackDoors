# -*- coding: utf-8 -*-
"""TZ v2 Sprint 2: the signature updater.

Two layers, like the YARA engine tests:
  * CLI level through the harness (a real subprocess, a private --data-dir):
    install a bundle, status, rollback, the exit-code contract (0/1/4), the
    refusal of an unverified package and of every tampering trick;
  * unit level through direct imports: the URL allowlist, the strict redirect
    handler, log masking (a token must never reach the log), safe unpacking
    (zip slip, symlink, bomb) and the upstream channel with a FAKE downloader -
    no test in this file ever opens a socket.

The rules used here are trivial local files; the compile check runs the real
engines/yara_check.py, so the tests that install a release need yara-python
(they are skipped without it, like the engine tests).
"""

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

sys.path.insert(0, h.REPO)
sys.path.insert(0, h.SRC)

import updater as up  # noqa: E402

# the channels log their per-source failures; in-process tests do not need that on stderr
up.logging.getLogger("updater").addHandler(up.logging.NullHandler())

try:
    import yara as _yara                              # noqa: F401
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

MARK = "SBD_UPD_PROBE_MARKER_4417"
MARK_B = "SBD_UPD_PROBE_MARKER_4418"
MARK_2 = "SBD_UPD_PROBE_MARKER_4419"
RULE = 'rule SbUpdProbe {\n    strings:\n        $a = "%s" ascii wide\n    condition:\n        $a\n}\n' % MARK


def rule_with(marker):
    return RULE.replace(MARK, marker)


def make_bundle(path, rules=None, package_name="sbd-test-sig-1", manifest_entries="auto",
                extra=None):
    """Build a rule package: {name.yar: text} + the manifest.json that declares it.

    manifest_entries="auto" hashes what is really inside; pass a list to declare
    something else (that is how a tampered package is simulated). `extra` adds
    arbitrary {archive name: bytes} members.
    """
    rules = rules if rules is not None else {"rules/a.yar": RULE}
    entries = manifest_entries
    if entries == "auto":
        entries = [{"path": rel, "sha256": hashlib.sha256(rules[rel].encode("utf-8")).hexdigest()}
                   for rel in sorted(rules)]
    manifest = {"schema": 2,
                "package": {"name": package_name, "license": "CC0-1.0"},
                "files": entries}
    with zipfile.ZipFile(path, "w") as z:
        for rel, text in rules.items():
            z.writestr(rel, text)
        z.writestr("manifest.json", json.dumps(manifest))
        for name, blob in (extra or {}).items():
            z.writestr(name, blob)
    return path


def data_dir(prefix="upd-data-"):
    return h.workdir(prefix)


def upd(data, *args):
    return h.run("updater.py", list(args) + ["--data-dir", data])


def active_name(data):
    p = os.path.join(data, "signatures", "ACTIVE")
    try:
        with io.open(p, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def read_manifest(data):
    try:
        with io.open(os.path.join(data, "signatures", "manifest.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def store_manifest(store):
    with io.open(store.manifest, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# URL policy
# ---------------------------------------------------------------------------

class UrlPolicyTest(unittest.TestCase):
    def test_https_on_the_allowlist_passes(self):
        up.check_url("https://github.com/o/r/archive/%s.zip" % ("a" * 40))

    def test_plain_http_is_refused(self):
        with self.assertRaises(up.UpdateError):
            up.check_url("http://github.com/o/r.zip")

    def test_foreign_host_is_refused(self):
        with self.assertRaises(up.UpdateError) as cm:
            up.check_url("https://evil.example.com/rules.zip")
        self.assertIn("allowlist", str(cm.exception))

    def test_credentials_in_the_url_are_refused(self):
        with self.assertRaises(up.UpdateError):
            up.check_url("https://user:pw@github.com/o/r.zip")

    def test_odd_port_is_refused(self):
        with self.assertRaises(up.UpdateError):
            up.check_url("https://github.com:8443/o/r.zip")

    def test_a_redirect_off_the_allowlist_is_not_followed(self):
        # redirect_request() returns None: urllib then reports the 30x as an
        # HTTPError instead of silently fetching the foreign URL.
        handler = up.StrictRedirect({"github.com"})
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {},
                                                   "https://evil.example.com/x.zip"))
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {},
                                                   "http://github.com/x.zip"))

    def test_masking_hides_secrets_from_the_log(self):
        m = up.mask_url("https://user:pw@github.com/x?access_token=SECRET&keep=1")
        self.assertNotIn("SECRET", m)
        self.assertNotIn("pw", m)
        self.assertIn("keep=1", m)

    def test_sanitize_strips_log_injection(self):
        self.assertEqual(up.sanitize("a\r\nEVIL [INFO] fake line"), "a EVIL [INFO] fake line")


# ---------------------------------------------------------------------------
# safe unpacking
# ---------------------------------------------------------------------------

class SafeZipTest(unittest.TestCase):
    def extract(self, zip_path, **kw):
        dest = h.workdir("upd-x-")
        return up.safe_extract_zip(zip_path, dest, **kw), dest

    def zip_of(self, members):
        p = os.path.join(h.workdir("upd-z-"), "x.zip")
        with zipfile.ZipFile(p, "w") as z:
            for name, blob in members.items():
                z.writestr(name, blob)
        return p

    def test_rule_and_license_files_are_taken(self):
        p = self.zip_of({"rules/a.yar": RULE, "LICENSE": "CC0", "README.md": "noise"})
        written, dest = self.extract(p)
        self.assertIn("rules/a.yar", written)
        self.assertTrue(os.path.isfile(os.path.join(dest, "rules", "a.yar")))
        self.assertFalse(os.path.exists(os.path.join(dest, "README.md")),
                         "anything that is not a rule or a license must not be installed")

    def test_zip_slip_is_refused(self):
        p = self.zip_of({"../escaped.yar": RULE})
        with self.assertRaises(up.UpdateError) as cm:
            self.extract(p)
        self.assertIn("unsafe path", str(cm.exception))

    def test_absolute_path_is_refused(self):
        p = self.zip_of({"/etc/evil.yar": RULE})
        with self.assertRaises(up.UpdateError):
            self.extract(p)

    def test_symlink_member_is_refused(self):
        p = os.path.join(h.workdir("upd-z-"), "sym.zip")
        with zipfile.ZipFile(p, "w") as z:
            info = zipfile.ZipInfo("link.yar")
            info.create_system = 3                       # unix, so external_attr means st_mode
            info.external_attr = (0o120777 << 16)
            z.writestr(info, "not really a rule file")
        with self.assertRaises(up.UpdateError) as cm:
            self.extract(p)
        self.assertIn("symlink", str(cm.exception))

    def test_compression_ratio_is_refused(self):
        p = os.path.join(h.workdir("upd-z-"), "bomb.zip")
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("big.yar", "A" * 200000)
        with self.assertRaises(up.UpdateError) as cm:
            self.extract(p, max_ratio=2)
        self.assertIn("ratio", str(cm.exception))

    def test_unpacked_size_is_capped(self):
        p = self.zip_of({"a.yar": RULE, "b.yar": RULE})
        with self.assertRaises(up.UpdateError):
            self.extract(p, max_total=10)

    def test_file_count_is_capped(self):
        p = self.zip_of({"a.yar": RULE, "b.yar": RULE})
        with self.assertRaises(up.UpdateError):
            self.extract(p, max_files=1)

    def test_a_non_zip_is_refused(self):
        p = os.path.join(h.workdir("upd-z-"), "not.zip")
        with io.open(p, "w", encoding="utf-8") as f:
            f.write("hello")
        with self.assertRaises(up.UpdateError):
            self.extract(p)


# ---------------------------------------------------------------------------
# download() with a fake opener - no sockets in this file
# ---------------------------------------------------------------------------

class _FakeResp(object):
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def read(self, n):
        out = self.chunks[:1]
        del self.chunks[:1]
        return out[0] if out else b""

    def close(self):
        pass


class _FakeOpener(object):
    def __init__(self, chunks):
        self.chunks = chunks

    def open(self, req, timeout=None):
        return _FakeResp(self.chunks)


class DownloadTest(unittest.TestCase):
    def setUp(self):
        self._dest = os.path.join(h.workdir("upd-d-"), "out.bin")

    def dest(self):
        return self._dest

    def test_digest_and_bytes(self):
        got = up.download("https://github.com/o/r.zip", self.dest(),
                          _opener=_FakeOpener([b"abc", b"def"]))
        self.assertEqual(got, hashlib.sha256(b"abcdef").hexdigest())
        with io.open(self.dest(), "rb") as f:
            self.assertEqual(f.read(), b"abcdef")

    def test_pinned_sha_mismatch_is_refused(self):
        with self.assertRaises(up.UpdateError) as cm:
            up.download("https://github.com/o/r.zip", self.dest(), expected_sha256="0" * 64,
                        _opener=_FakeOpener([b"abc"]))
        self.assertIn("sha256 mismatch", str(cm.exception))

    def test_size_limit_stops_a_runaway_response(self):
        with self.assertRaises(up.UpdateError) as cm:
            up.download("https://github.com/o/r.zip", self.dest(), max_bytes=4,
                        _opener=_FakeOpener([b"1234", b"5678"]))
        self.assertIn("size limit", str(cm.exception))

    def test_the_url_policy_runs_before_any_request(self):
        with self.assertRaises(up.UpdateError):
            up.download("https://evil.example.com/x.zip", self.dest(), _opener=_FakeOpener([b"x"]))


# ---------------------------------------------------------------------------
# the CLI contract (subprocess, like a user)
# ---------------------------------------------------------------------------

class BundleCliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HAVE_YARA:
            raise unittest.SkipTest("installing a release runs the real compile check")

    def bundle(self, **kw):
        p = os.path.join(h.workdir("upd-b-"), "signatures.zip")
        return make_bundle(p, **kw)

    def test_install_status_rules_path_and_rollback(self):
        data = data_dir()
        b1 = self.bundle(package_name="sbd-test-sig-1")
        r = upd(data, "--update-from-bundle", b1, "--package-sha256", up.sha256_file(b1))
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("Installed and activated release 'sbd-test-sig-1'", r.out)
        self.assertEqual(active_name(data), "sbd-test-sig-1")

        st = json.loads(upd(data, "--status").out)
        self.assertEqual(st["active"], "sbd-test-sig-1")
        self.assertEqual(st["rules"], 1)
        self.assertTrue(st["verified"])

        rp = upd(data, "--rules-path")
        self.assertEqual(rp.returncode, 0, rp.out)
        self.assertTrue(os.path.isfile(os.path.join(rp.out.strip(), "a.yar")),
                        "--rules-path must point at the rule files")

        b2 = self.bundle(package_name="sbd-test-sig-2")
        r = upd(data, "--update-from-bundle", b2, "--package-sha256", up.sha256_file(b2))
        self.assertEqual(r.returncode, 0, r.out)
        self.assertEqual(active_name(data), "sbd-test-sig-2")

        r = upd(data, "--rollback-signatures")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertEqual(active_name(data), "sbd-test-sig-1")
        self.assertEqual(read_manifest(data)["active"], "sbd-test-sig-1")
        self.assertEqual(read_manifest(data)["failed"], [])

    def test_reinstalling_the_same_bundle_is_a_no_op(self):
        data = data_dir()
        b = self.bundle()
        sha = up.sha256_file(b)
        self.assertEqual(upd(data, "--update-from-bundle", b, "--package-sha256", sha).returncode, 0)
        r = upd(data, "--update-from-bundle", b, "--package-sha256", sha)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertEqual(active_name(data), "sbd-test-sig-1")

    def test_an_unverified_bundle_is_refused_without_the_flag(self):
        data = data_dir()
        b = self.bundle()
        r = upd(data, "--update-from-bundle", b)
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("--allow-unverified", r.out)
        self.assertIsNone(active_name(data), "nothing may become active from a refused package")

    def test_allow_unverified_installs_but_records_the_fact(self):
        data = data_dir()
        b = self.bundle()
        r = upd(data, "--update-from-bundle", b, "--allow-unverified")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("UNVERIFIED", r.out)
        self.assertFalse(read_manifest(data)["package"]["verified"])

    def test_a_wrong_pinned_sha_refuses_the_package(self):
        data = data_dir()
        b = self.bundle()
        r = upd(data, "--update-from-bundle", b, "--package-sha256", "f" * 64)
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("REFUSED", r.out)
        self.assertIsNone(active_name(data))

    def test_a_rule_file_undeclared_in_the_manifest_refuses_the_package(self):
        data = data_dir()
        extra = {"rules/undeclared.yar": RULE.replace(MARK, MARK + "_EXTRA")}
        b = self.bundle(extra=extra)
        r = upd(data, "--update-from-bundle", b, "--package-sha256", up.sha256_file(b))
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("not declared", r.out)
        self.assertIsNone(active_name(data))

    def test_a_hash_that_does_not_match_the_content_refuses_the_package(self):
        data = data_dir()
        b = self.bundle(manifest_entries=[{"path": "rules/a.yar", "sha256": "0" * 64}])
        r = upd(data, "--update-from-bundle", b, "--package-sha256", up.sha256_file(b))
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("does not match", r.out)
        self.assertIsNone(active_name(data))

    def test_a_package_without_a_manifest_is_refused(self):
        data = data_dir()
        p = os.path.join(h.workdir("upd-b-"), "bare.zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("rules/a.yar", RULE)
        r = upd(data, "--update-from-bundle", p, "--package-sha256", up.sha256_file(p))
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("manifest.json", r.out)

    def test_a_broken_rule_file_never_becomes_active(self):
        data = data_dir()
        b = self.bundle(rules={"rules/a.yar": RULE,
                               "rules/broken.yar": "rule Broken {\n condition: not yara\n}\n"})
        r = upd(data, "--update-from-bundle", b, "--package-sha256", up.sha256_file(b))
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("does not compile", r.out)
        self.assertIsNone(active_name(data))
        self.assertEqual(os.listdir(os.path.join(data, "signatures", "releases")), [],
                         "a refused package must leave no release behind")

    def test_a_zip_slip_inside_a_bundle_is_refused(self):
        data = data_dir()
        b = make_bundle(os.path.join(h.workdir("upd-b-"), "slip.zip"),
                        rules={"rules/a.yar": RULE})
        # append a member with a traversal path to a well-formed package
        with zipfile.ZipFile(b, "a") as z:
            z.writestr("../outright.yar", RULE)
        r = upd(data, "--update-from-bundle", b, "--package-sha256", up.sha256_file(b))
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIsNone(active_name(data))

    def test_the_previous_release_survives_a_failed_update(self):
        data = data_dir()
        good = self.bundle(package_name="sbd-test-sig-1")
        upd(data, "--update-from-bundle", good, "--package-sha256", up.sha256_file(good))
        bad = self.bundle(package_name="sbd-test-sig-2",
                          rules={"rules/a.yar": "rule Broken {\n condition: not yara\n}\n"})
        r = upd(data, "--update-from-bundle", bad, "--package-sha256", up.sha256_file(bad))
        self.assertEqual(r.returncode, 4, r.out)
        self.assertEqual(active_name(data), "sbd-test-sig-1")
        self.assertIn("unchanged", r.out)

    def test_exactly_one_action_is_required(self):
        data = data_dir()
        r = upd(data)
        self.assertEqual(r.returncode, 1, r.out)
        r = upd(data, "--status", "--rollback-signatures")
        self.assertEqual(r.returncode, 1, r.out)

    def test_rules_path_without_anything_installed_is_exit_1(self):
        data = data_dir()
        self.assertEqual(upd(data, "--rules-path").returncode, 1)

    def test_project_channel_is_not_configured_yet(self):
        data = data_dir()
        r = upd(data, "--update-signatures")
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("package_source", r.out)
        # the template that ensure() writes must be explicit about being empty
        with io.open(os.path.join(data, "signatures", "sources.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        self.assertEqual(cfg["upstream"], [])
        self.assertEqual(cfg["package_source"], {})

    def test_status_without_anything_installed(self):
        data = data_dir()
        r = upd(data, "--status")
        self.assertEqual(r.returncode, 0, r.out)
        st = json.loads(r.out)
        self.assertFalse(st["present"])
        self.assertIsNone(st["active"])

    def test_a_bad_package_sha_is_a_usage_error(self):
        data = data_dir()
        r = upd(data, "--update-from-bundle", self.bundle(), "--package-sha256", "nothex")
        self.assertEqual(r.returncode, 1, r.out)

    def test_the_version_flag_reports_the_bundle_version(self):
        r = h.run("updater.py", ["--version"])
        self.assertIn(h.bundle_version(), r.out)

    def test_a_data_dir_that_is_not_a_folder_refuses_without_a_traceback(self):
        # a mistaken or hostile --data-dir takes the same clean path as any file
        # system problem: a refusal with code 4, never a stack trace
        bad = os.path.join(h.workdir("upd-bd-"), "not-a-dir")
        with io.open(bad, "w", encoding="utf-8") as f:
            f.write("this is a file, not a data folder")
        r = h.run("updater.py", ["--status", "--data-dir", bad])
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("file system error", r.out.lower())
        self.assertNotIn("Traceback", r.out)


# ---------------------------------------------------------------------------
# the upstream channel with a fake downloader
# ---------------------------------------------------------------------------

class FakeNetwork(object):
    """Stands in for updater.download(): copies a prepared zip to dest and returns
    its sha256 - so the pinned-hash check of the channel still runs for real.
    No test in this file opens a socket."""

    def __init__(self, by_repo, failing=()):
        self.by_repo = by_repo              # {"owner/name": (zip path, sha256)}
        self.failing = set(failing)
        self.urls = []

    def __call__(self, url, dest, max_bytes, allowed_hosts, expected_sha256, timeout):
        self.urls.append(url)
        repo = url[len("https://github.com/"):].split("/archive/")[0]
        if not url.endswith(".zip") or "/" not in repo:
            raise up.UpdateError("unexpected request: %s" % url)
        if repo in self.failing:
            raise up.UpdateError("simulated network failure for %s" % repo)
        path, sha = self.by_repo[repo]
        if expected_sha256 and expected_sha256 != sha:
            raise up.UpdateError("simulated sha256 mismatch for %s" % repo)
        with open(path, "rb") as src, open(dest, "wb") as out:
            out.write(src.read())
        return sha


class UpstreamTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HAVE_YARA:
            raise unittest.SkipTest("installing a release runs the real compile check")

    COMMIT = "0123456789abcdef0123456789abcdef01234567"

    def setUp(self):
        self.archives = h.workdir("upd-uparc-")

    def archive(self, repo, rules, tag="v1"):
        """A GitHub-style commit zip (everything wrapped in one top folder)."""
        path = os.path.join(self.archives, repo.replace("/", "_") + "-" + tag + ".zip")
        top = repo.split("/")[1] + "-" + self.COMMIT[:8]
        with zipfile.ZipFile(path, "w") as z:
            for rel, text in rules.items():
                z.writestr("%s/%s" % (top, rel), text)
        return path, up.sha256_file(path)

    def repin(self, store, name, sha):
        """What a human does after reviewing a new upstream commit: point the pin at it."""
        with io.open(store.sources, encoding="utf-8") as f:
            cfg = json.load(f)
        for src in cfg["upstream"]:
            if src["name"] == name:
                src["archive_sha256"] = sha
        with io.open(store.sources, "w", encoding="utf-8") as f:
            json.dump(cfg, f)

    def source(self, name, commit=None, sha="a" * 64):
        return {"name": name, "repo": "acme/%s" % name, "commit": commit or self.COMMIT,
                "archive_sha256": sha, "license": "CC0-1.0"}

    def store_with(self, upstream, net_by_repo=None):
        root = data_dir()
        store = up.Store(root)
        store.ensure()
        cfg = []
        for src in upstream:
            entry = dict(src)
            if net_by_repo and entry["repo"] in net_by_repo:
                entry["archive_sha256"] = net_by_repo[entry["repo"]][1]
            cfg.append(entry)
        with io.open(store.sources, "w", encoding="utf-8") as f:
            json.dump({"upstream": cfg, "allowed_hosts": []}, f)
        return store

    def installed(self, store):
        rules = os.path.join(store.releases, store.active(), "rules")
        out = {}
        for name in sorted(os.listdir(rules)):
            with io.open(os.path.join(rules, name), encoding="utf-8") as f:
                out[name] = f.read()
        return out

    def test_a_branch_reference_is_refused_before_any_request(self):
        store = self.store_with([self.source("ruleset", commit="main")])
        net = FakeNetwork({"acme/ruleset": self.archive("acme/ruleset", {"a.yar": RULE})})
        with self.assertRaises(up.UpdateError) as cm:
            up.channel_upstream(store, "", False, [], _download=net)
        self.assertIn("commit SHA", str(cm.exception))
        self.assertEqual(net.urls, [], "no request may be made for a source that is not pinned")

    def test_a_missing_pinned_archive_hash_is_refused(self):
        store = self.store_with([self.source("ruleset", sha="")])
        net = FakeNetwork({})
        with self.assertRaises(up.UpdateError):
            up.channel_upstream(store, "", False, [], _download=net)
        self.assertEqual(net.urls, [])

    def test_an_empty_upstream_list_is_refused(self):
        store = self.store_with([])
        with self.assertRaises(up.UpdateError):
            up.channel_upstream(store, "", False, [], _download=FakeNetwork({}))

    def test_two_sources_merge_into_one_release(self):
        by_repo = {"acme/alpha": self.archive("acme/alpha", {"a.yar": RULE}),
                   "acme/beta": self.archive("acme/beta", {"b.yar": rule_with(MARK_B)})}
        store = self.store_with([self.source("alpha"), self.source("beta")], by_repo)
        updated, failed = up.channel_upstream(store, "", False, [], _download=FakeNetwork(by_repo))
        self.assertEqual(sorted(updated), ["alpha", "beta"])
        self.assertEqual(failed, [])
        got = self.installed(store)
        self.assertEqual(sorted(got), ["alpha_a.yar", "beta_b.yar"],
                         "every rule keeps the name of the source it came from")
        self.assertIn(MARK, got["alpha_a.yar"])
        self.assertIn(MARK_B, got["beta_b.yar"])

    def test_the_pinned_hash_is_rechecked_on_every_sync(self):
        by_repo = {"acme/alpha": self.archive("acme/alpha", {"a.yar": RULE})}
        store = self.store_with([self.source("alpha")], by_repo)     # pins the real sha256
        other = self.archive("acme/alpha", {"a.yar": rule_with(MARK_2)}, tag="v2")
        net = FakeNetwork({"acme/alpha": other})
        with self.assertRaises(up.UpdateError) as cm:
            up.channel_upstream(store, "", False, [], _download=net)
        self.assertIn("mismatch", str(cm.exception))
        self.assertIsNone(store.active())

    def test_a_failing_source_keeps_the_rules_it_had(self):
        by_repo = {"acme/alpha": self.archive("acme/alpha", {"a.yar": RULE}),
                   "acme/beta": self.archive("acme/beta", {"b.yar": rule_with(MARK_B)})}
        store = self.store_with([self.source("alpha"), self.source("beta")], by_repo)
        up.channel_upstream(store, "", False, [], _download=FakeNetwork(by_repo))
        # the next sync: alpha was re-pinned to a new commit, beta's server is down
        new_alpha = self.archive("acme/alpha", {"a.yar": rule_with(MARK_2)}, tag="v2")
        self.repin(store, "alpha", new_alpha[1])
        net2 = FakeNetwork({"acme/alpha": new_alpha}, failing={"acme/beta"})
        updated, failed = up.channel_upstream(store, "", False, [], _download=net2)
        self.assertEqual(updated, ["alpha"])
        self.assertEqual([f["source"] for f in failed], ["beta"])
        got = self.installed(store)
        self.assertIn(MARK_2, got["alpha_a.yar"])
        self.assertIn(MARK_B, got["beta_b.yar"], "a falling source must carry over, not vanish")
        self.assertEqual(store_manifest(store)["active"], store.active())
        self.assertEqual([f["source"] for f in store_manifest(store)["failed"]], ["beta"])

    def test_every_source_failing_refuses_the_update(self):
        by_repo = {"acme/alpha": self.archive("acme/alpha", {"a.yar": RULE})}
        store = self.store_with([self.source("alpha"), self.source("beta")], by_repo)
        net = FakeNetwork(by_repo, failing={"acme/alpha", "acme/beta"})
        with self.assertRaises(up.UpdateError) as cm:
            up.channel_upstream(store, "", False, [], _download=net)
        self.assertIn("network failure", str(cm.exception))
        self.assertIsNone(store.active())

    def test_only_one_source_can_be_synced_and_the_others_carry_over(self):
        by_repo = {"acme/alpha": self.archive("acme/alpha", {"a.yar": RULE}),
                   "acme/beta": self.archive("acme/beta", {"b.yar": rule_with(MARK_B)})}
        store = self.store_with([self.source("alpha"), self.source("beta")], by_repo)
        up.channel_upstream(store, "", False, [], _download=FakeNetwork(by_repo))
        new_beta = self.archive("acme/beta", {"b.yar": rule_with(MARK_2)}, tag="v2")
        self.repin(store, "beta", new_beta[1])
        net = FakeNetwork({"acme/beta": new_beta})
        updated, failed = up.channel_upstream(store, "beta", False, [], _download=net)
        self.assertEqual(updated, ["beta"])
        self.assertEqual(failed, [])
        self.assertEqual(len(net.urls), 1, "only the requested source may be fetched")
        got = self.installed(store)
        self.assertIn(MARK, got["alpha_a.yar"], "a source that was not synced carries over")
        self.assertIn(MARK_2, got["beta_b.yar"])


class ConstantSyncTest(unittest.TestCase):
    """The updater, the engine and the compile checker must agree on what a rule file is."""

    def test_the_updater_accepts_exactly_the_rule_extensions_of_the_engine(self):
        from engines import yara_engine as ye
        self.assertEqual(up.RULE_EXTS, ye.YARA_EXTS)


class RuleCheckerTest(unittest.TestCase):
    """engines/yara_check.py is both the updater's gate before activation and a CI linter."""

    @classmethod
    def setUpClass(cls):
        if not HAVE_YARA:
            raise unittest.SkipTest("the checker needs yara-python")

    def run_checker(self, rules):
        d = h.workdir("upd-chk-")
        for name, text in rules.items():
            with io.open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write(text)
        return self.spawn(d)

    def spawn(self, folder):
        proc = subprocess.Popen([sys.executable, "-u", os.path.join(h.REPO, "engines", "yara_check.py"), folder],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True, encoding="utf-8", errors="replace")
        out = proc.communicate()[0]
        return proc.returncode, out

    def test_a_good_folder_compiles_with_exit_0(self):
        code, out = self.run_checker({"a.yar": RULE})
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads(out)["ok"], ["a.yar"])

    def test_a_broken_file_is_reported_and_exit_is_1(self):
        code, out = self.run_checker({"a.yar": RULE, "broken.yar": "rule Broken {\n condition: ~~~\n}\n"})
        self.assertEqual(code, 1, out)
        report = json.loads(out)
        self.assertEqual(report["ok"], ["a.yar"])
        self.assertEqual([b["file"] for b in report["bad"]], ["broken.yar"])
        self.assertTrue(report["bad"][0]["error"], "the reason must be reported, not swallowed")

    def test_the_checker_refuses_include_too(self):
        code, out = self.run_checker({"a.yar": 'include "b.yar"\nrule SbA { condition: false }\n'})
        self.assertEqual(code, 1, out)
        self.assertIn("include", json.loads(out)["bad"][0]["error"].lower())

    def test_a_missing_folder_is_a_usage_error(self):
        code, out = self.spawn(os.path.join(h.workdir("upd-chk-"), "nope"))
        self.assertEqual(code, 2, out)


# ---------------------------------------------------------------------------
# minisign signatures (OPEN_QUESTIONS #13)
# ---------------------------------------------------------------------------
# The fixtures below are real: minisign produced them, and the author's own reference
# port (https://github.com/jedisct1/go-minisign, MIT - its LICENSE says so, read 2026-11-28)
# verifies both over the message "test". Committing them is what keeps the format
# handling honest - this file checks updater against minisign's output, not against a
# copy of updater's own writer.
# The optional cryptography library is absent on many machines, so the policy around
# it (what is refused, what falls back to the pinned hash, what --require-signature
# forbids) is tested with a stand-in, and the real Ed25519 maths runs when present.

MINISIGN_PUB = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
MINISIGN_SIGNED_TEXT = b"test"
MINISIGN_LEGACY = (
    "untrusted comment: signature from minisign secret key\n"
    "RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi"
    "+dP9eKL8OC351vwIasSSbXxwA=\n"
    "trusted comment: timestamp:1635442742\tfile:test\n"
    "0YteLgV960ia80vnA/fHbvkyjl/IoP/HNOCaZfrF0CdhAlp7ok+Tpkya+VpWPX5C/Is3q8a/kED"
    "SY7fBmmgJCg==\n")
MINISIGN_PREHASHED = (
    "untrusted comment: signature from minisign secret key\n"
    "RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8"
    "ofjb7bNJJylDOocrCo8KLzZwo=\n"
    "trusted comment: timestamp:1635443258\tfile:test\thashed\n"
    "/cj37GK60vryibFn+ftOgbCvW9NKhKYgjVpFFQUcWPAnjO23wrvVDTt7cloNC06maoBli9q6qw"
    "ZDXXoaxweICQ==\n")

TEST_KEY_ID = b"\x11\x22\x33\x44\x55\x66\x77\x88"
TEST_PUBLIC = b"\x01" * 32


def pinned_key(key_id=TEST_KEY_ID, public=TEST_PUBLIC):
    """A minisign public key record: 'Ed' + key id + 32-byte key, base64."""
    return base64.b64encode(b"Ed" + key_id + public).decode("ascii")


def signature_file(key_id=TEST_KEY_ID, signature=b"\xaa" * 64, global_sig=b"\xbb" * 64,
                   alg=b"Ed", trusted="timestamp:1700000000\tfile:rules.zip"):
    """A .minisig in minisign's layout: comment, key id + signature, trusted comment,
    global signature. The bytes inside mean nothing to these tests - FakeCrypto below
    decides what is valid, the fixtures above are what the real minisign produced."""
    return ("untrusted comment: signature from a test key\n%s\ntrusted comment: %s\n%s\n"
            % (base64.b64encode(alg + key_id + signature).decode("ascii"), trusted,
               base64.b64encode(global_sig).decode("ascii")))


def signature_key_id(text=MINISIGN_LEGACY):
    return base64.b64decode(text.split("\n")[1])[2:10]


class FakeCrypto(object):
    """A stand-in for the optional 'cryptography' package.

    `accepts` maps signature bytes to the one message they are valid for, so a test
    can say exactly what the library would have agreed to; `missing=True` behaves like
    an uninstalled package (updater.minisign_verifier raises)."""

    def __init__(self, accepts=None, missing=False):
        self.accepts = accepts or {}
        self.missing = missing
        self.consulted = []

    def __enter__(self):
        self._saved = up.minisign_verifier
        up.minisign_verifier = self._verifier
        return self

    def __exit__(self, *_exc):
        up.minisign_verifier = self._saved
        return False

    def _verifier(self):
        if self.missing:
            raise up.UpdateError(up.NO_CRYPTO)

        def verify(public, message, signature):
            self.consulted.append((public, message, signature))
            return self.accepts.get(signature) == message
        return verify


class BrokenDownload(object):
    """A downloader that fails the way a 404 does: with an UpdateError."""

    def __init__(self, reason="404 Not Found"):
        self.reason = reason
        self.urls = []

    def __call__(self, url, dest, max_bytes, allowed_hosts, expected_sha256, timeout):
        self.urls.append(url)
        raise up.UpdateError(self.reason)


class WritingDownload(object):
    """Serves prepared bytes per URL suffix (for signature files that exist but are junk)."""

    def __init__(self, blob=b"not a minisign file at all\n"):
        self.blob = blob
        self.urls = []

    def __call__(self, url, dest, max_bytes, allowed_hosts, expected_sha256, timeout):
        self.urls.append(url)
        if len(self.blob) > max_bytes:
            raise up.UpdateError("response exceeds the size limit (%d bytes)" % max_bytes)
        with open(dest, "wb") as f:
            f.write(self.blob)
        return hashlib.sha256(self.blob).hexdigest()


class MinisignFormatTest(unittest.TestCase):
    """The four lines and the two base64 records, checked against real minisign output."""

    def test_the_pinned_key_is_the_record_minisign_writes(self):
        key_id, public = up.parse_minisign_pub(MINISIGN_PUB)
        raw = base64.b64decode(MINISIGN_PUB)
        self.assertEqual(raw[:2], b"Ed")
        self.assertEqual(key_id, raw[2:10].hex())
        self.assertEqual(len(public), 32)

    def test_a_public_key_file_with_its_comment_parses_too(self):
        key_id, _public = up.parse_minisign_pub("untrusted comment: minisign public key: 0DE8\n"
                                                + MINISIGN_PUB + "\n")
        self.assertEqual(key_id, base64.b64decode(MINISIGN_PUB)[2:10].hex())

    def test_a_key_that_is_not_an_ed25519_record_is_refused(self):
        for bad, why in (("not base64 at all!", "base64"),
                         (base64.b64encode(b"Ed" + b"\x01" * 20).decode(), "42 bytes"),
                         (base64.b64encode(b"BC" + b"\x01" * 40).decode(), "algorithm"),
                         ("untrusted comment: a\n" + MINISIGN_PUB + "\n" + MINISIGN_PUB, "one base64")):
            with self.assertRaises(up.UpdateError) as cm:
                up.parse_minisign_pub(bad)
            self.assertIn(why, str(cm.exception).lower())

    def test_a_signature_file_is_read_the_way_minisign_writes_it(self):
        sig = up.parse_minisign_sig(MINISIGN_LEGACY)
        self.assertEqual(sig["alg"], b"Ed")
        self.assertEqual(sig["key_id"], signature_key_id().hex())
        self.assertEqual(len(sig["signature"]), 64)
        self.assertEqual(len(sig["global"]), 64)
        self.assertEqual(sig["trusted"], "timestamp:1635442742\tfile:test")

    def test_a_prehashed_signature_announces_itself(self):
        self.assertEqual(up.parse_minisign_sig(MINISIGN_PREHASHED)["alg"], b"ED")

    def test_windows_line_endings_parse_the_same(self):
        self.assertEqual(up.parse_minisign_sig(MINISIGN_LEGACY.replace("\n", "\r\n"))["key_id"],
                         up.parse_minisign_sig(MINISIGN_LEGACY)["key_id"])

    def test_a_malformed_signature_is_refused_not_guessed(self):
        three = "\n".join(MINISIGN_LEGACY.split("\n")[:3])
        for bad in (three,                                       # the global signature is gone
                    MINISIGN_LEGACY + MINISIGN_LEGACY,           # a fifth line, whatever it is
                    MINISIGN_LEGACY.split("\n")[0] + "\n!!!!\n" +
                    MINISIGN_LEGACY.split("\n")[2] + "\n" + MINISIGN_LEGACY.split("\n")[3],
                    signature_file(signature=b"\xaa" * 63)):     # right shape, wrong length
            with self.assertRaises(up.UpdateError):
                up.parse_minisign_sig(bad)

    def test_a_comment_that_is_not_a_trusted_comment_is_refused(self):
        with self.assertRaises(up.UpdateError) as cm:
            up.parse_minisign_sig(MINISIGN_LEGACY.replace("trusted comment: ", "comment: "))
        self.assertIn("trusted comment", str(cm.exception).lower())

    def test_an_unknown_signature_algorithm_is_refused(self):
        with self.assertRaises(up.UpdateError) as cm:
            up.parse_minisign_sig(signature_file(alg=b"Xx"))
        self.assertIn("algorithm", str(cm.exception).lower())


class SignatureCheckTest(unittest.TestCase):
    """check_signature: the decisions around the maths, testable without the maths."""

    def setUp(self):
        self.archive = os.path.join(h.workdir("upd-sig-"), "rules.zip")
        with open(self.archive, "wb") as f:
            f.write(b"the package bytes")
        self.bytes = b"the package bytes"

    def check(self, cfg=None, sig_text=None, sha_pinned=True, require=False, lines=None,
              download=None, url=None):
        return up.check_signature("the package", cfg if cfg is not None
                                  else {"minisign_pub": pinned_key()},
                                  "", self.archive, url, None, sha_pinned,
                                  lines if lines is not None else [], require=require,
                                  sig_text=sig_text, _download=download or BrokenDownload())

    def test_a_source_that_pins_no_key_is_checked_exactly_as_before(self):
        got = self.check(cfg={})
        self.assertEqual(got, {"verification": "none", "signature": "none", "key_id": None})

    def test_the_key_that_signed_the_bytes_makes_it_verified(self):
        sig, glob = b"\xaa" * 64, b"\xbb" * 64
        with FakeCrypto({sig: self.bytes,
                         glob: sig + b"timestamp:1700000000\tfile:rules.zip"}):
            got = self.check(sig_text=signature_file(signature=sig, global_sig=glob))
        self.assertEqual(got["verification"], "minisign-ed25519")
        self.assertEqual(got["signature"], "verified")
        self.assertEqual(got["key_id"], TEST_KEY_ID.hex())

    def test_a_signature_the_key_did_not_produce_is_refused(self):
        with FakeCrypto({}):                          # the library would say no
            with self.assertRaises(up.UpdateError) as cm:
                self.check(sig_text=signature_file())
        self.assertIn("does not verify", str(cm.exception))

    def test_a_signature_by_another_key_is_refused_before_any_crypto(self):
        crypto = FakeCrypto({b"\xaa" * 64: self.bytes})
        with crypto:
            with self.assertRaises(up.UpdateError) as cm:
                self.check(cfg={"minisign_pub": pinned_key(key_id=b"\x99" * 8)},
                           sig_text=signature_file())
        self.assertIn("signed by key", str(cm.exception))
        self.assertEqual(crypto.consulted, [], "a key mismatch must not even reach the library")

    def test_a_prehashed_signature_covers_the_hash_not_the_file(self):
        sig, glob = b"\xcc" * 64, b"\xdd" * 64
        digest = hashlib.blake2b(self.bytes, digest_size=64).digest()
        with FakeCrypto({sig: digest, glob: sig + b"timestamp:1700000000\tfile:rules.zip"}):
            got = self.check(sig_text=signature_file(signature=sig, global_sig=glob, alg=b"ED"))
        self.assertEqual(got["verification"], "minisign-ed25519-prehashed")
        with FakeCrypto({sig: self.bytes, glob: sig}):   # the file itself, as if unhashed
            with self.assertRaises(up.UpdateError):
                self.check(sig_text=signature_file(signature=sig, global_sig=glob, alg=b"ED"))

    def test_a_broken_global_signature_is_refused(self):
        sig, glob = b"\xaa" * 64, b"\xbb" * 64
        with FakeCrypto({sig: self.bytes}):             # the global one is unknown: False
            with self.assertRaises(up.UpdateError) as cm:
                self.check(sig_text=signature_file(signature=sig, global_sig=glob))
        self.assertIn("global signature", str(cm.exception))

    def test_without_the_library_a_pinned_hash_still_works_and_says_so(self):
        lines = []
        with FakeCrypto(missing=True):
            got = self.check(sha_pinned=True, lines=lines)
        self.assertEqual(got["verification"], "sha256-pinned")
        self.assertEqual(got["signature"], "not-checked")
        self.assertIn("Signature NOT checked", "\n".join(lines))

    def test_without_the_library_and_without_a_pinned_hash_it_is_refused(self):
        with FakeCrypto(missing=True):
            with self.assertRaises(up.UpdateError) as cm:
                self.check(sha_pinned=False)
        self.assertIn("no pinned sha256", str(cm.exception))

    def test_require_signature_forsakes_the_hash_only_fallback(self):
        with FakeCrypto(missing=True):
            for sha_pinned in (True, False):
                with self.assertRaises(up.UpdateError) as cm:
                    self.check(sha_pinned=sha_pinned, require=True)
                self.assertIn("--require-signature", str(cm.exception))

    def test_require_signature_refuses_a_source_that_pins_no_key(self):
        with self.assertRaises(up.UpdateError) as cm:
            self.check(cfg={}, require=True)
        self.assertIn("minisign_pub", str(cm.exception))

    def test_a_signature_that_cannot_be_fetched_falls_back_to_the_hash(self):
        net = BrokenDownload()
        with FakeCrypto(missing=False):
            got = self.check(sha_pinned=True, download=net, lines=[])
        self.assertEqual(got["signature"], "not-checked")
        self.assertEqual(net.urls, [], "the URL is refused before any request: no https, no host")

    def test_a_signature_junk_next_to_a_pinned_key_is_never_a_fallback(self):
        # the file exists but is not a signature: with a pinned key this is suspicious,
        # and quietly going back to the hash is what an attacker would hope for
        with FakeCrypto({}):
            with self.assertRaises(up.UpdateError):
                up.check_signature("the package", {"minisign_pub": pinned_key()}, "", self.archive,
                                   "https://github.com/o/r.zip", {"github.com"}, True, [],
                                   _download=WritingDownload())

    def test_the_signature_is_sought_next_to_the_archive_by_default(self):
        net = BrokenDownload()
        with FakeCrypto(missing=True):
            up.check_signature("the package", {"minisign_pub": pinned_key()}, "", self.archive,
                               "https://github.com/o/r.zip", {"github.com"}, True, [],
                               _download=net)
        self.assertEqual(net.urls, ["https://github.com/o/r.zip.minisig"])

    def test_a_source_can_point_the_signature_somewhere_else(self):
        net = BrokenDownload()
        with FakeCrypto(missing=True):
            up.check_signature("the package", {"minisign_pub": pinned_key(),
                                               "signature_url": "https://github.com/o/keys/rules.sig"},
                               "", self.archive, "https://github.com/o/r.zip", {"github.com"},
                               True, [], _download=net)
        self.assertEqual(net.urls, ["https://github.com/o/keys/rules.sig"])

    def test_the_key_may_live_in_a_pub_file_next_to_the_config(self):
        base = h.workdir("upd-pub-")
        os.makedirs(os.path.join(base, "keys"))
        with io.open(os.path.join(base, "keys", "rules.pub"), "w", encoding="utf-8") as f:
            f.write("untrusted comment: minisign public key: DEADBEAF\n" + MINISIGN_PUB + "\n")
        signed = os.path.join(base, "message")          # the fixture signs exactly "test"
        with open(signed, "wb") as f:
            f.write(MINISIGN_SIGNED_TEXT)
        got = up.check_signature("the package", {"minisign_pub_file": "keys/rules.pub"}, base,
                                 signed, None, None, True, [])
        # the pinned key id already matches the fixture's: with the library installed the
        # real signature verifies, without it the honest answer is "could not check"
        self.assertIn(got["verification"], ("sha256-pinned", "minisign-ed25519"))
        self.assertEqual(got["key_id"], signature_key_id().hex())

    def test_an_unreadable_pinned_key_file_is_refused(self):
        with self.assertRaises(up.UpdateError) as cm:
            self.check(cfg={"minisign_pub_file": "no-such-key.pub"})
        self.assertIn("public key", str(cm.exception))


@unittest.skipUnless(h.have_cryptography(), "real Ed25519 needs the optional cryptography package")
class RealMinisignTest(unittest.TestCase):
    """The maths, with the fixtures the real minisign tool produced."""

    def check(self, blob, sig_text, cfg=None):
        archive = os.path.join(h.workdir("upd-real-"), "message")
        with open(archive, "wb") as f:
            f.write(blob)
        return up.check_signature("fixture", cfg or {"minisign_pub": MINISIGN_PUB}, "", archive,
                                  None, None, False, [], sig_text=sig_text)

    def test_a_real_signature_verifies(self):
        got = self.check(MINISIGN_SIGNED_TEXT, MINISIGN_LEGACY)
        self.assertEqual(got["verification"], "minisign-ed25519")
        self.assertEqual(got["signature"], "verified")

    def test_a_real_prehashed_signature_verifies(self):
        got = self.check(MINISIGN_SIGNED_TEXT, MINISIGN_PREHASHED)
        self.assertEqual(got["verification"], "minisign-ed25519-prehashed")

    def test_one_different_byte_breaks_the_signature(self):
        with self.assertRaises(up.UpdateError) as cm:
            self.check(b"tesu", MINISIGN_LEGACY)
        self.assertIn("does not verify", str(cm.exception))

    def test_the_signature_of_another_file_does_not_transfer(self):
        with self.assertRaises(up.UpdateError):
            self.check(b"testtest", MINISIGN_LEGACY)

    def test_a_tampered_global_signature_is_refused(self):
        lines = MINISIGN_LEGACY.split("\n")
        raw = bytearray(base64.b64decode(lines[3]))
        raw[0] ^= 0x01
        lines[3] = base64.b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(up.UpdateError) as cm:
            self.check(MINISIGN_SIGNED_TEXT, "\n".join(lines))
        self.assertIn("global signature", str(cm.exception))

    def test_a_different_key_is_refused_even_though_the_signature_is_real(self):
        other = base64.b64encode(b"Ed" + b"\x01" * 8 + base64.b64decode(MINISIGN_PUB)[10:]).decode()
        with self.assertRaises(up.UpdateError) as cm:
            self.check(MINISIGN_SIGNED_TEXT, MINISIGN_LEGACY, cfg={"minisign_pub": other})
        self.assertIn("signed by key", str(cm.exception))

    def test_the_verifier_the_channels_use_agrees(self):
        verify = up.minisign_verifier()
        self.assertTrue(verify(base64.b64decode(MINISIGN_PUB)[10:], MINISIGN_SIGNED_TEXT,
                               up.parse_minisign_sig(MINISIGN_LEGACY)["signature"]))


@unittest.skipUnless(HAVE_YARA, "installing a release runs the real compile check")
class SignatureBundleTest(unittest.TestCase):
    """--update-from-bundle plus --signature: the offline verified install.

    The channel runs in-process here (the compile check is still a real subprocess),
    because a test key only means something when the optional cryptography library is
    replaced inside this process. The CLI wiring that needs no crypto at all is in
    SignatureCliTest, and what really happens on a machine without the library is in
    NoSignatureLibraryTest."""

    def setUp(self):
        self.root = data_dir()
        self.store = up.Store(self.root)
        self.store.ensure()
        self.bundle = make_bundle(os.path.join(h.workdir("upd-sb-"), "rules.zip"))
        with open(self.bundle, "rb") as f:
            self.blob = f.read()
        self.sig, self.glob = b"\xaa" * 64, b"\xbb" * 64
        self.signature = os.path.join(os.path.dirname(self.bundle), "rules.zip.minisig")
        self.write_signature(signature_file(signature=self.sig, global_sig=self.glob))
        self.accepts = {self.sig: self.blob,
                        self.glob: self.sig + b"timestamp:1700000000\tfile:rules.zip"}

    def write_signature(self, text):
        with io.open(self.signature, "w", encoding="utf-8") as f:
            f.write(text)

    def pin_key(self, key_id=TEST_KEY_ID):
        with io.open(self.store.sources, encoding="utf-8") as f:
            cfg = json.load(f)
        cfg["package_source"] = {"minisign_pub": pinned_key(key_id=key_id)}
        with io.open(self.store.sources, "w", encoding="utf-8") as f:
            json.dump(cfg, f)

    def install(self, sha=None, sig=True, require=False, crypto=None):
        self.lines = []
        with (crypto if crypto is not None else FakeCrypto(self.accepts)):
            return up.channel_bundle(self.store, self.bundle, sha, False, self.lines,
                                     sig_path=self.signature if sig else None,
                                     require=require)

    def doc(self):
        with io.open(os.path.join(self.store.releases, self.store.active(), "RELEASE.json"),
                     encoding="utf-8") as f:
            return json.load(f)

    def test_a_signed_bundle_is_installed_as_signed(self):
        self.pin_key()
        name = self.install()
        self.assertEqual(name, "sbd-test-sig-1")
        doc = self.doc()
        self.assertEqual(doc["verification"], "minisign-ed25519")
        self.assertEqual(doc["signature"], "verified")
        self.assertEqual(doc["signature_key_id"], TEST_KEY_ID.hex())
        self.assertTrue(doc["verified"])
        self.assertIn("signed by the pinned minisign key", "\n".join(self.lines))

    def test_the_status_reports_who_signed_the_active_release(self):
        self.pin_key()
        self.install()
        st = up.status(self.store)
        self.assertEqual(st["signature"], "verified")
        self.assertEqual(st["key_id"], TEST_KEY_ID.hex())
        self.assertEqual(st["verification"], "minisign-ed25519")
        self.assertIn(st["signature_library"], (True, False))     # reported, whatever it is

    def test_a_prehashed_signature_is_recorded_as_prehashed(self):
        self.pin_key()
        digest = hashlib.blake2b(self.blob, digest_size=64).digest()
        self.write_signature(signature_file(signature=self.sig, global_sig=self.glob, alg=b"ED"))
        accepts = {self.sig: digest, self.glob: self.sig + b"timestamp:1700000000\tfile:rules.zip"}
        self.install(crypto=FakeCrypto(accepts))
        self.assertEqual(self.doc()["verification"], "minisign-ed25519-prehashed")
        self.assertEqual(up.status(self.store)["signature"], "verified")

    def test_a_bundle_signed_by_another_key_installs_nothing(self):
        self.pin_key(key_id=b"\x99" * 8)
        with self.assertRaises(up.UpdateError) as cm:
            self.install()
        self.assertIn("signed by key", str(cm.exception))
        self.assertIsNone(self.store.active())
        self.assertEqual(os.listdir(self.store.releases), [])

    def test_a_signature_that_does_not_verify_installs_nothing(self):
        self.pin_key()
        with self.assertRaises(up.UpdateError) as cm:
            self.install(crypto=FakeCrypto({}))
        self.assertIn("does not verify", str(cm.exception))
        self.assertEqual(os.listdir(self.store.releases), [])

    def test_a_signature_without_a_pinned_key_proves_nothing(self):
        with self.assertRaises(up.UpdateError) as cm:          # no key pinned at all
            self.install()
        self.assertIn("minisign_pub", str(cm.exception))

    def test_without_the_library_a_pinned_hash_still_installs_and_says_so(self):
        self.pin_key()
        sha = up.sha256_file(self.bundle)
        self.install(sha=sha, sig=False, crypto=FakeCrypto(missing=True))
        doc = self.doc()
        self.assertEqual(doc["signature"], "not-checked")
        self.assertEqual(doc["verification"], "sha256-pinned")
        self.assertTrue(doc["verified"])                        # the pinned hash is an anchor
        self.assertIn("Signature NOT checked", "\n".join(self.lines))

    def test_without_the_library_and_without_a_pinned_hash_it_is_refused(self):
        self.pin_key()
        with self.assertRaises(up.UpdateError) as cm:
            self.install(sig=False, crypto=FakeCrypto(missing=True))
        self.assertIn("no pinned sha256", str(cm.exception))

    def test_require_signature_forsakes_the_hash_only_fallback(self):
        self.pin_key()
        with self.assertRaises(up.UpdateError) as cm:
            self.install(sha=up.sha256_file(self.bundle), crypto=FakeCrypto(missing=True),
                         require=True)
        self.assertIn("--require-signature", str(cm.exception))
        self.assertEqual(os.listdir(self.store.releases), [])

    def test_require_signature_refuses_a_package_from_an_unpinned_channel(self):
        with self.assertRaises(up.UpdateError) as cm:
            self.install(sig=False, require=True)               # package_source pins no key
        self.assertIn("minisign_pub", str(cm.exception))


class SignatureCliTest(unittest.TestCase):
    """The flag contract: refusals that happen before any crypto or unpacking, so
    they run everywhere."""

    def setUp(self):
        self.data = data_dir()
        up.Store(self.data).ensure()            # sources.json appears on the first run
        self.bundle = make_bundle(os.path.join(h.workdir("upd-cli-"), "rules.zip"))
        self.signature = os.path.join(os.path.dirname(self.bundle), "rules.zip.minisig")
        with io.open(self.signature, "w", encoding="utf-8") as f:
            f.write(signature_file())

    def test_a_signature_file_belongs_with_a_bundle(self):
        r = upd(self.data, "--update-signatures", "--signature", self.signature)
        self.assertEqual(r.returncode, 1, r.out)
        self.assertIn("--update-from-bundle", r.out)

    def test_require_signature_needs_the_signature_itself(self):
        r = upd(self.data, "--update-from-bundle", self.bundle, "--require-signature")
        self.assertEqual(r.returncode, 1, r.out)
        self.assertIn("--signature", r.out)

    def test_require_signature_and_allow_unverified_cannot_both_be_on(self):
        r = upd(self.data, "--update-from-bundle", self.bundle, "--require-signature",
                "--allow-unverified")
        self.assertEqual(r.returncode, 1, r.out)

    def test_a_signature_with_nothing_pinned_proves_nothing(self):
        r = upd(self.data, "--update-from-bundle", self.bundle, "--signature", self.signature)
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("minisign_pub", r.out)
        self.assertIn("The previously active release is unchanged.", r.out)

    def test_the_pinned_hash_is_checked_before_the_signature_is_read(self):
        with io.open(os.path.join(self.data, "signatures", "sources.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        cfg["package_source"] = {"minisign_pub": pinned_key()}
        with io.open(os.path.join(self.data, "signatures", "sources.json"), "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        r = upd(self.data, "--update-from-bundle", self.bundle, "--signature", self.signature,
                "--package-sha256", "0" * 64)
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("sha256", r.out)

    def test_the_help_explains_both_new_flags(self):
        r = h.run("updater.py", ["--help"])
        self.assertIn("--require-signature", r.out)
        self.assertIn("--signature", r.out)


@unittest.skipIf(h.have_cryptography(), "this is what a machine without the library does")
@unittest.skipUnless(HAVE_YARA, "installing a release runs the real compile check")
class NoSignatureLibraryTest(unittest.TestCase):
    """Without 'cryptography' the updater keeps updating by pinned sha256 - and has to
    say out loud, in the output and in the manifest, that the signature went unchecked."""

    def setUp(self):
        self.data = data_dir()
        up.Store(self.data).ensure()            # sources.json appears on the first run
        self.bundle = make_bundle(os.path.join(h.workdir("upd-noc-"), "rules.zip"))
        self.sha = up.sha256_file(self.bundle)
        self.signature = os.path.join(os.path.dirname(self.bundle), "rules.zip.minisig")
        with io.open(self.signature, "w", encoding="utf-8") as f:
            f.write(signature_file())
        with io.open(os.path.join(self.data, "signatures", "sources.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        cfg["package_source"] = {"minisign_pub": pinned_key()}
        with io.open(os.path.join(self.data, "signatures", "sources.json"), "w", encoding="utf-8") as f:
            json.dump(cfg, f)

    def test_a_pinned_hash_carries_the_update_and_the_warning(self):
        r = upd(self.data, "--update-from-bundle", self.bundle, "--package-sha256", self.sha)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("Signature NOT checked", r.out)
        with io.open(os.path.join(self.data, "signatures", "manifest.json"), encoding="utf-8") as f:
            pkg = json.load(f)["package"]
        self.assertEqual(pkg["signature"], "not-checked")
        self.assertEqual(pkg["verification"], "sha256-pinned")
        st = json.loads(upd(self.data, "--status").out)
        self.assertEqual(st["signature_library"], False)
        self.assertEqual(st["signature"], "not-checked")

    def test_require_signature_refuses_to_work_without_the_library(self):
        r = upd(self.data, "--update-from-bundle", self.bundle, "--package-sha256", self.sha,
                "--require-signature", "--signature", self.signature)
        self.assertEqual(r.returncode, 4, r.out)
        self.assertIn("cryptography", r.out)
        self.assertIsNone(active_name(self.data))


if __name__ == "__main__":
    unittest.main()


