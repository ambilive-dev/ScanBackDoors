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


if __name__ == "__main__":
    unittest.main()
