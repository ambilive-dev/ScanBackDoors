#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
signature updater - safe download, verification and activation of YARA rule
packages for scan_backdoors (TZ v2, section 7). Standard library only (Python 3.6+).

Trust model (v2): nothing is fetched "from a branch". A rule set is installed only as
a whole, atomically activated release, after integrity checks; a release is either
fully verified or explicitly accepted with --allow-unverified (loudly, and the
manifest records "verified": false). A failed source never erases what already works.

Channels:
    python3 updater.py --update-from-bundle signatures.zip    # offline package (same checks)
    python3 updater.py --update-from-upstream                 # only sources pinned by commit SHA
    python3 updater.py --update-signatures                    # the project's own package (sources.json)
    python3 updater.py --rollback-signatures                  # back to the previous release
    python3 updater.py --status                               # what is active now (JSON)

Data lives in $SBD_DATA_DIR (or ~/.scan_backdoors): signatures/{releases/, ACTIVE,
manifest.json, sources.json} and logs/updater.log. The scanner reads the rules with
--yara-rules pointing at the active release's rules folder; `updater.py --rules-path`
prints that path (empty output and exit 1 when nothing is active).

Exit codes: 0 - everything updated, 1 - usage/config error,
            3 - PARTIAL update (at least one source failed - see the manifest),
            4 - verification or network failure (the previous release stays active).
"""

import argparse
import hashlib
import io
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from logging.handlers import RotatingFileHandler
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request

try:                                        # single source of truth: version.py next to this file
    from version import VERSION
except ImportError:                         # a single uploaded file still has to start
    VERSION = "3.3.1"                       # keep in sync with src/version.py (tests/test_release.py checks it)

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

ALLOWED_HOSTS = {"github.com", "codeload.github.com", "objects.githubusercontent.com"}
USER_AGENT = "ScanBackDoors-updater/" + VERSION
MAX_DOWNLOAD = 300 * 1024 * 1024            # hard cap for one archive, bytes
MAX_FILES = 20000                           # rule files in one archive
MAX_TOTAL = 300 * 1024 * 1024               # unpacked size, bytes
MAX_RATIO = 200                             # per-file compression ratio (zip-bomb guard)
COMPILE_TIMEOUT = 120                       # yara_check subprocess, seconds
KEEP_RELEASES = 3                           # how many releases stay for rollback
RULE_EXTS = (".yar", ".yara")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
SECRET_QUERY_RE = re.compile(r"(?i)(^|[?&])(access_token|api_?key|token|key|auth|secret)=([^&]*)")

EXIT_OK, EXIT_CONFIG, EXIT_PARTIAL, EXIT_VERIFY = 0, 1, 3, 4

SOURCES_TEMPLATE = {
    "_readme": "Pinned rule channels. Nothing here is trusted because it is popular: review "
               "each source, its licence and both hashes by hand before adding it.",
    "package_source": {},          # {"url": "https://…/v1/rules.zip", "sha256": "<64 hex>"}
    "allowed_hosts": [],           # extra https hosts the pinned URLs may live on
    "upstream": [],                # [{"name": "…", "repo": "owner/name", "commit": "<40 hex>",
                                   #   "archive_sha256": "<64 hex>", "license": "…"}]
}


class UpdateError(Exception):
    """A refusal that keeps the previous release active."""


# ---------------------------------------------------------------------------
# logging (rotating, sanitized: external strings never reach the log raw)
# ---------------------------------------------------------------------------

log = logging.getLogger("updater")


def sanitize(text):
    """One line, printable ASCII only: an external string must never inject a fake
    log line (CRLF) or control characters. Runs of spaces are collapsed."""
    text = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in str(text))
    return re.sub(r" {2,}", " ", text).strip()


def mask_url(url):
    """A URL that may carry a key in the query - safe for logs and messages."""
    u = urlsplit(str(url))
    netloc = ("***@" + u.hostname) if (u.username or u.password) else (u.netloc or "")
    query = SECRET_QUERY_RE.sub(r"\1\2=***", u.query or "")
    path = re.sub(r"/(exports|files)/[0-9A-Za-z._-]{12,}/", r"/\1/***", u.path or "")
    return "%s://%s%s%s" % (u.scheme, netloc, path, ("?" + query) if query else "")


def setup_logging(data_dir):
    log.setLevel(logging.INFO)
    try:
        d = os.path.join(data_dir, "logs")
        if not os.path.isdir(d):
            os.makedirs(d)
        h = RotatingFileHandler(os.path.join(d, "updater.log"), maxBytes=10 * 1024 * 1024,
                                backupCount=5, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(h)
    except OSError:
        pass                                # the console still gets everything (see main)


# ---------------------------------------------------------------------------
# network primitives (TZ 7.3): https-only, allowlisted, strict redirects, streaming
# ---------------------------------------------------------------------------

def check_url(url, allowed_hosts=None):
    u = urlsplit(str(url))
    allowed = ALLOWED_HOSTS if allowed_hosts is None else allowed_hosts
    if u.scheme != "https":
        raise UpdateError("only https is allowed, got %r" % (u.scheme or "no scheme"))
    if u.username or u.password:
        raise UpdateError("credentials in the URL are forbidden")
    if u.port not in (None, 443):
        raise UpdateError("unexpected port %s" % u.port)
    if (u.hostname or "").lower() not in allowed:
        raise UpdateError("host is not on the allowlist: %s" % u.hostname)


class StrictRedirect(HTTPRedirectHandler):
    """Every redirect is re-checked against the same rules (GitHub answers archives
    through codeload.github.com; a hop to http:// or to a foreign host refuses)."""

    def __init__(self, allowed=None):
        HTTPRedirectHandler.__init__(self)
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            check_url(newurl, self.allowed)
        except UpdateError as exc:
            log.warning("redirect refused (%s): %s", exc, mask_url(newurl))
            return None                      # urllib turns the un-followed 30x into an HTTPError
        r = HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)
        log.info("redirect -> %s", mask_url(newurl))
        return r


def download(url, dest, max_bytes=MAX_DOWNLOAD, allowed_hosts=None,
             expected_sha256=None, timeout=30, _opener=None):
    """Stream to disk (never resp.read() at once); sha256 is computed on the fly."""
    check_url(url, allowed_hosts)
    opener = _opener or build_opener(StrictRedirect(allowed_hosts))
    req = Request(str(url), headers={"User-Agent": USER_AGENT})
    h, total = hashlib.sha256(), 0
    try:
        resp = opener.open(req, timeout=timeout)
    except Exception as exc:
        raise UpdateError("network failure for %s: %s" % (mask_url(url), exc))
    try:
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise UpdateError("response exceeds the size limit (%d bytes)" % max_bytes)
                h.update(chunk)
                f.write(chunk)
    finally:
        resp.close()
    if expected_sha256 and h.hexdigest() != expected_sha256.lower():
        raise UpdateError("sha256 mismatch for %s: expected %s, got %s"
                          % (mask_url(url), expected_sha256.lower(), h.hexdigest()))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# safe unpacking (TZ 7.3): no extractall; zip slip, symlinks, bombs refused
# ---------------------------------------------------------------------------

def safe_extract_zip(zpath, dest, max_files=MAX_FILES, max_total=MAX_TOTAL, max_ratio=MAX_RATIO):
    """Extract ONLY *.yar/*.yara and license/copying/manifest files, safely.

    Sizes are counted from what is actually written, the declared header sizes
    are used only for the early ratio test. Returns the list of extracted names.
    """
    dest_real = os.path.realpath(dest)
    total = n = 0
    written = []
    try:
        z = zipfile.ZipFile(zpath)
    except zipfile.BadZipFile:
        raise UpdateError("not a valid zip archive: %s" % os.path.basename(zpath))
    with z:
        for info in z.infolist():
            name = info.filename
            if info.is_dir():
                continue
            parts = name.replace("\\", "/").split("/")
            if name.startswith(("/", "\\")) or ".." in parts or ":" in parts[0]:
                raise UpdateError("unsafe path in the archive: %r" % name)
            if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                raise UpdateError("symlink in the archive: %r" % name)
            low = name.lower()
            base = os.path.basename(low)
            allowed = (low.endswith(RULE_EXTS) or base.startswith(("license", "copying", "notice"))
                       or base == "manifest.json" or base.endswith(".license"))
            if not allowed:
                continue                    # anything else in the archive is simply not installed
            n += 1
            if n > max_files:
                raise UpdateError("too many files in the archive")
            if info.compress_size and info.file_size / float(info.compress_size) > max_ratio:
                raise UpdateError("suspicious compression ratio: %r" % name)
            target = os.path.realpath(os.path.join(dest_real, name))
            if not (target == dest_real or target.startswith(dest_real + os.sep)):
                raise UpdateError("path escapes the destination: %r" % name)
            out_dir = os.path.dirname(target)
            if out_dir and not os.path.isdir(out_dir):
                os.makedirs(out_dir)
            with z.open(info) as src, open(target, "wb") as out:
                while True:
                    buf = src.read(65536)
                    if not buf:
                        break
                    total += len(buf)
                    if total > max_total:
                        raise UpdateError("the archive is too large when unpacked")
                    out.write(buf)
            written.append(name.replace("\\", "/"))
    return written


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# the data directory layout
# ---------------------------------------------------------------------------

def data_dir(cli_value=None):
    d = cli_value or os.environ.get("SBD_DATA_DIR") or os.path.join(os.path.expanduser("~"), ".scan_backdoors")
    return os.path.abspath(os.path.expanduser(d))


class Store(object):
    """signatures/{releases/<name>/rules, ACTIVE, manifest.json, sources.json}"""

    def __init__(self, root):
        self.root = os.path.join(root, "signatures")
        self.releases = os.path.join(self.root, "releases")
        self.active_ptr = os.path.join(self.root, "ACTIVE")
        self.manifest = os.path.join(self.root, "manifest.json")
        self.sources = os.path.join(self.root, "sources.json")

    def ensure(self):
        if not os.path.isdir(self.releases):
            os.makedirs(self.releases)
        if not os.path.exists(self.sources):
            # a template, not a config: every channel starts empty on purpose - a human
            # must review a source, its licence and its hashes before pinning them here
            atomic_write(self.sources, json.dumps(SOURCES_TEMPLATE, indent=2, sort_keys=True) + "\n")

    # -- ACTIVE pointer: one short name, replaced atomically -----------------
    def active(self):
        try:
            with io.open(self.active_ptr, encoding="utf-8") as f:
                name = f.read().strip()
        except OSError:
            return None
        if not NAME_RE.match(name):
            return None
        d = os.path.join(self.releases, name)
        return name if os.path.isdir(os.path.join(d, "rules")) else None

    def set_active(self, name):
        """The activation step itself: tmp + fsync + os.replace (atomic on all
        supported platforms, including a replace of an existing file on Windows)."""
        atomic_write(self.active_ptr, name + "\n")

    # -- manifest: the source of truth for the GUI ---------------------------
    def read_manifest(self):
        try:
            with io.open(self.manifest, encoding="utf-8") as f:
                m = json.load(f)
            return m if isinstance(m, dict) else None
        except (OSError, ValueError):
            return None

    def write_manifest(self, manifest):
        manifest["generated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        atomic_write(self.manifest, json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    def load_sources_config(self):
        try:
            with io.open(self.sources, encoding="utf-8") as f:
                cfg = json.load(f)
            return cfg if isinstance(cfg, dict) else {}
        except (OSError, ValueError):
            return {}


def atomic_write(path, text):
    d = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(d):
        os.makedirs(d)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix="")
    try:
        with io.open(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    if os.name != "nt":                     # durability of the rename itself, where possible
        try:
            dfd = os.open(d, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            os.chmod(path, 0o600)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# verification of a staged rule set
# ---------------------------------------------------------------------------

def collect_rules(root):
    """All *.yar/*.yara under the staging folder, names relative to root."""
    out = []
    for base, _dirs, files in os.walk(root):
        for n in files:
            if n.lower().endswith(RULE_EXTS):
                p = os.path.join(base, n)
                out.append((os.path.relpath(p, root).replace(os.sep, "/"), p))
    out.sort()
    return out


def common_top_prefix(rels):
    """'repo-sha/' when every path starts with the same first folder (a GitHub
    commit zip wraps everything in one), otherwise ''."""
    if not rels:
        return ""
    tops = {rel.split("/", 1)[0] + "/" for rel in rels if "/" in rel}
    if len(tops) == 1 and all("/" in rel for rel in rels):
        return tops.pop()
    return ""


def normalize_rules(staging, rules_out):
    """Move the found rule files into releases/<name>/rules/, stripping the single
    common top folder (GitHub zips wrap everything in 'repo-sha/')."""
    found = collect_rules(staging)
    if not found:
        raise UpdateError("the package contains no .yar/.yara rule files")
    prefix = common_top_prefix([rel for rel, _p in found])
    os.makedirs(rules_out)
    names = []
    for rel, path in found:
        short = rel[len(prefix):] if prefix else rel
        if os.path.basename(os.path.dirname(short)):
            short = short.replace("/", "_")       # keep a flat rules/ folder: the scanner reads it non-recursive
        dst = os.path.join(rules_out, os.path.basename(short))
        if os.path.exists(dst):
            raise UpdateError("duplicate rule file name in the package: %r" % os.path.basename(short))
        shutil.copy2(path, dst)
        names.append(os.path.basename(short))
    return sorted(names)


def compile_check(rules_dir):
    """The whole set must compile BEFORE activation: engines/yara_check.py runs in a
    separate process with its own timeout (one hostile file must not hang us)."""
    import subprocess
    checker = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "engines", "yara_check.py")
    if not os.path.isfile(checker):
        raise UpdateError("engines/yara_check.py is missing: the rule set cannot be compile-checked")
    try:
        proc = subprocess.Popen([sys.executable, "-u", checker, rules_dir],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, encoding="utf-8", errors="replace")
        out, err = proc.communicate(timeout=COMPILE_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise UpdateError("the compile check exceeded %d s: the package is refused" % COMPILE_TIMEOUT)
    except Exception as exc:
        raise UpdateError("the compile check could not run: %s" % exc)
    if proc.returncode == 2:                 # yara-python missing or the folder unreadable
        raise UpdateError("the rule set cannot be compile-checked here: %s"
                          % (err.strip().splitlines()[-1] if err.strip() else "checker error"))
    try:
        report = json.loads(out or "{}")
    except ValueError:
        raise UpdateError("the compile check answered with garbage: it is refused, not trusted")
    bad = report.get("bad") or []
    if bad:
        detail = "; ".join("%s: %s" % (b.get("file"), b.get("error")) for b in bad[:5])
        raise UpdateError("the package does not compile (%d bad file(s)): %s" % (len(bad), detail))
    return report.get("ok") or []


# ---------------------------------------------------------------------------
# release installation: staging -> verify -> activate (all or nothing)
# ---------------------------------------------------------------------------

def install_release(store, rules_src_dir, meta):
    """rules_src_dir contains the extracted rules to install. meta describes the
    source/verification. Returns the release name. The ACTIVE pointer is the last
    thing written; a crash before it changes nothing on disk."""
    store.ensure()
    name = meta["release"]
    if not NAME_RE.match(name):
        raise UpdateError("bad release name: %r" % name)
    final = os.path.join(store.releases, name)
    if os.path.isdir(final):
        # re-running the same package is a no-op, not an error: same archive = same release
        try:
            with io.open(os.path.join(final, "RELEASE.json"), encoding="utf-8") as f:
                same = json.load(f).get("archive_sha256") == meta.get("archive_sha256")
        except (OSError, ValueError):
            same = False
        if not same:
            raise UpdateError("release %r is already installed from different content" % name)
        store.set_active(name)
        m = store.read_manifest() or {"schema": 2, "releases": []}
        m["active"] = name
        hist = m.get("releases") or []
        if not any(r.get("name") == name for r in hist):
            hist.insert(0, {"name": name, "source": meta.get("source", ""),
                            "activated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "verified": bool(meta.get("verified"))})
            m["releases"] = hist
        store.write_manifest(m)
        log.info("release %s was already installed and is active again (no-op)", name)
        return name
    staging_parent = store.releases          # the same filesystem as the target: a hard move is possible
    tmp = tempfile.mkdtemp(prefix=".staging-", dir=staging_parent)
    try:
        rules_out = os.path.join(tmp, "rules")
        names = normalize_rules(rules_src_dir, rules_out)
        compile_check(rules_out)             # refuses on any bad file or missing yara-python
        manifest_files = [{"path": "rules/" + n, "sha256": sha256_file(os.path.join(rules_out, n))}
                          for n in names]
        release_doc = dict(meta)
        release_doc["rules"] = manifest_files
        release_doc["count"] = len(names)
        with io.open(os.path.join(tmp, "RELEASE.json"), "w", encoding="utf-8") as f:
            json.dump(release_doc, f, indent=2, sort_keys=True)
        if os.path.exists(final):
            raise UpdateError("release %r is already installed" % name)
        os.replace(tmp, final)               # the whole directory appears atomically
        tmp = None
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    old_active = store.active()
    store.set_active(name)                   # <- the activation point
    m = store.read_manifest() or {"schema": 2, "releases": []}
    m["schema"] = 2
    m["active"] = name
    m["package"] = {"name": name, "sha256": meta.get("archive_sha256") or "",
                    "signature": "unverified",
                    "verified": bool(meta.get("verified")),
                    "verification": meta.get("verification", "none")}
    m.setdefault("sources", {})
    m["sources"][meta.get("source", name)] = {k: meta[k] for k in
                                              ("count", "license", "commit", "archive_sha256")
                                              if k in meta}
    m["sources"][meta.get("source", name)]["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    hist = [r for r in (m.get("releases") or []) if r.get("name") != name]
    hist.insert(0, {"name": name, "source": meta.get("source", ""),
                    "activated": m["sources"][meta.get("source", name)]["updated"],
                    "verified": bool(meta.get("verified"))})
    m["releases"] = hist
    m["failed"] = meta.get("failed") or []
    store.write_manifest(m)
    prune(store, keep=KEEP_RELEASES)
    log.info("activated release %s (%d rule(s)%s)", name, len(names),
             "" if meta.get("verified") else " - UNVERIFIED")
    if old_active:
        log.info("previous release still available for rollback: %s", old_active)
    return name


def prune(store, keep=KEEP_RELEASES):
    m = store.read_manifest() or {}
    wanted = set(r.get("name") for r in (m.get("releases") or [])[:keep])
    wanted.add(store.active())
    try:
        present = sorted(os.listdir(store.releases))
    except OSError:
        return
    for n in present:
        if n.startswith("."):
            continue
        if n not in wanted:
            shutil.rmtree(os.path.join(store.releases, n), ignore_errors=True)


# ---------------------------------------------------------------------------
# channels
# ---------------------------------------------------------------------------

def channel_bundle(store, path, expected_sha256, allow_unverified, log_lines):
    """--update-from-bundle FILE: the same package the project publishes, offline."""
    if not os.path.isfile(path):
        raise UpdateError("the bundle file was not found: %s" % path)
    archive_sha = sha256_file(path)
    if expected_sha256 and archive_sha != expected_sha256.lower():
        raise UpdateError("the bundle's sha256 is %s but --package-sha256 says %s: refused"
                          % (archive_sha, expected_sha256.lower()))
    verified = bool(expected_sha256)
    if not verified:
        gate_unverified(allow_unverified, "a bare bundle file has no signature: only its own "
                                          "internal hashes are known")
    staging = tempfile.mkdtemp(prefix="bundle-")
    try:
        written = safe_extract_zip(path, staging)
        log_lines.append("unpacked %d allowed file(s) from the bundle" % len(written))
        pm = None
        pm_path = os.path.join(staging, "manifest.json")
        if os.path.isfile(pm_path):
            try:
                with io.open(pm_path, encoding="utf-8") as f:
                    pm = json.load(f)
            except ValueError:
                raise UpdateError("the package's manifest.json is not valid JSON")
        else:
            raise UpdateError("the package has no manifest.json: a rule package must declare "
                              "its files (downloaded upstreams get their manifest added at "
                              "packaging time)")
        files = pm.get("files")
        if not isinstance(files, list) or not files:
            raise UpdateError("the package manifest declares no files")
        listed = set()
        for entry in files:
            rel = str((entry or {}).get("path") or "").replace("\\", "/")
            want = str((entry or {}).get("sha256") or "").lower()
            target = os.path.realpath(os.path.join(staging, rel))
            if not (target == os.path.realpath(staging) or target.startswith(os.path.realpath(staging) + os.sep)):
                raise UpdateError("the manifest declares an unsafe path: %r" % rel)
            if not os.path.isfile(target):
                raise UpdateError("the manifest declares %r but the package does not contain it" % rel)
            if len(want) != 64 or sha256_file(target) != want:
                raise UpdateError("the manifest hash does not match the package content: %r" % rel)
            listed.add(rel)
        for rel, _p in collect_rules(staging):
            if rel != "manifest.json" and rel not in listed:
                raise UpdateError("a rule file is not declared in the package manifest: %r" % rel)
        names = [rel for rel, _p in collect_rules(staging) if rel != "manifest.json"]
        meta = {"release": "bundle-" + archive_sha[:12], "source": "bundle",
                "archive_sha256": archive_sha, "verified": verified,
                "verification": "sha256-pinned" if verified else "none", "count": len(names)}
        pkg = pm.get("package") if isinstance(pm.get("package"), dict) else {}
        nm = str(pkg.get("name") or "").strip()
        if NAME_RE.match(nm):
            meta["release"] = nm
        if pkg.get("license"):
            meta["license"] = str(pkg["license"])[:120]
        return install_release(store, staging, meta)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def gate_unverified(allow_unverified, why):
    if not allow_unverified:
        raise UpdateError("no way to verify authenticity (%s). Re-run with --allow-unverified "
                          "only if you trust where this package came from - it will be marked "
                          "\"verified\": false in the manifest." % why)


def channel_upstream(store, only, allow_unverified, log_lines, _download=download):
    """--update-from-upstream: sync the sources pinned in sources.json (full commit
    SHA + pinned archive sha256; a branch is refused before any request).

    ONE new release is built from ALL pinned sources: every healthy source brings its
    rules, a failed source carries over the rules it had in the previous release (so a
    falling source never erases the others), and one atomic activation switches the set.
    A source that was not synced with --only is carried over from the previous release.
    """
    cfg_all = store.load_sources_config()
    cfg = cfg_all.get("upstream") or []
    if not cfg:
        raise UpdateError("no upstream sources are pinned in %s: put {name, repo, commit, "
                          "archive_sha256, license} entries there (after a manual review of "
                          "the rules and their licence)" % store.sources)
    allowed = set(ALLOWED_HOSTS) | {str(h) for h in cfg_all.get("allowed_hosts") or []}
    active = store.active()
    prev_rules = os.path.join(store.releases, active, "rules") if active else None
    staging = tempfile.mkdtemp(prefix="upstream-")
    merge = os.path.join(staging, "merge")          # the only rule tree install_release sees
    rules_stage = os.path.join(merge, "rules")
    os.makedirs(rules_stage)
    failed, synced = [], []
    try:
        for src in cfg:
            name = str(src.get("name") or "").strip()
            try:
                if not NAME_RE.match(name):
                    raise UpdateError("bad source name: %r" % name)
            except UpdateError as exc:
                failed.append({"source": name or "?", "error": sanitize(exc)[:300]})
                continue
            if only and name != only:
                carried = carry_over(prev_rules, rules_stage, name)
                if carried:
                    log_lines.append("source %s kept from the previous release (%d file(s))"
                                     % (name, len(carried)))
                continue
            try:
                repo = str(src.get("repo") or "")
                commit = str(src.get("commit") or "").lower()
                want_sha = str(src.get("archive_sha256") or "").lower()
                if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repo):
                    raise UpdateError("bad repo: %r" % repo)
                if not COMMIT_RE.match(commit):
                    raise UpdateError("source %s is not pinned to a full 40-hex commit SHA "
                                      "(branches are refused)" % name)
                if len(want_sha) != 64 or any(c not in "0123456789abcdef" for c in want_sha):
                    raise UpdateError("source %s has no pinned archive sha256" % name)
                url = "https://github.com/%s/archive/%s.zip" % (repo, commit)
                got = _download(url, os.path.join(staging, name + ".zip"),
                                MAX_DOWNLOAD, allowed, want_sha, 30)
                inner = os.path.join(staging, name)
                written = safe_extract_zip(os.path.join(staging, name + ".zip"), inner)
                found = collect_rules(inner)
                if not found:
                    raise UpdateError("the archive of %s contains no rule files" % name)
                prefix = common_top_prefix([rel for rel, _p in found])
                for rel, path in found:
                    short = rel[len(prefix):] if prefix else rel
                    shutil.copy2(path, os.path.join(rules_stage,
                                                    "%s_%s" % (name, short.replace("/", "_"))))
                synced.append(name)
                log.info("source %s @ %s: %d rule(s), archive verified by the pinned sha256 %s",
                         name, commit[:12], len(found), got[:12])
            except UpdateError as exc:
                log.error("source %s failed: %s", name, sanitize(exc))
                failed.append({"source": name, "error": sanitize(exc)[:300]})
                carried = carry_over(prev_rules, rules_stage, name)
                if carried:
                    log_lines.append("source %s failed; its rules from the previous release "
                                     "are kept (%d file(s))" % (name, len(carried)))
        if not synced:
            detail = "; ".join("%s: %s" % (f["source"], f["error"]) for f in failed) or "nothing was configured"
            raise UpdateError("every requested source failed: %s" % detail)
        staged = collect_rules(merge)
        if not staged:
            raise UpdateError("nothing to install: every source failed and none had rules "
                              "in a previous release")
        fingerprint = hashlib.sha256()
        for rel, path in staged:
            fingerprint.update(rel.encode("utf-8"))
            fingerprint.update(sha256_file(path).encode("ascii"))
        meta = {"release": "upstream-%s-%s" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
                                               fingerprint.hexdigest()[:8]),
                "source": "upstream", "verified": True, "verification": "sha256-pinned",
                "count": len(staged), "synced": synced, "failed": failed}
        install_release(store, merge, meta)
        return synced, failed
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def carry_over(prev_rules, rules_stage, source):
    """Copy the rules one source contributed to the previous release (names start
    with '<source>_'), so a failed sync keeps working rules instead of erasing them."""
    out = []
    if not prev_rules or not os.path.isdir(prev_rules):
        return out
    prefix = source + "_"
    for n in sorted(os.listdir(prev_rules)):
        if n.startswith(prefix) and n.lower().endswith(RULE_EXTS):
            shutil.copy2(os.path.join(prev_rules, n), os.path.join(rules_stage, n))
            out.append(n)
    return out


def channel_project(store, allow_unverified, log_lines, _download=download):
    """--update-signatures: the project's own signed package, URL pinned in sources.json."""
    cfg = store.load_sources_config()
    pkg = cfg.get("package_source")
    if not isinstance(pkg, dict) or not pkg.get("url"):
        raise UpdateError("the project package channel is not configured yet: add package_source "
                          "{url, sha256} to %s once the signed package exists (OPEN_QUESTIONS #13)"
                          % store.sources)
    url = str(pkg["url"])
    want_sha = str(pkg.get("sha256") or "").lower()
    verified = bool(want_sha)
    if not verified:
        gate_unverified(allow_unverified, "package_source has no sha256 and the signature scheme "
                                          "is not implemented yet")
    staging = tempfile.mkdtemp(prefix="project-")
    try:
        dest = os.path.join(staging, "package.zip")
        got = _download(url, dest, MAX_DOWNLOAD, ALLOWED_HOSTS | set(cfg.get("allowed_hosts") or []),
                        want_sha or None, 30)
        written = safe_extract_zip(dest, staging)
        log_lines.append("package %s verified by the pinned sha256 %s"
                         % (os.path.basename(url), got[:12]))
        meta = {"release": "project-" + got[:12], "source": "project",
                "archive_sha256": got, "verified": verified,
                "verification": "sha256-pinned" if verified else "none"}
        return install_release(store, staging, meta)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def channel_rollback(store):
    active = store.active()
    m = store.read_manifest() or {}
    hist = [r.get("name") for r in (m.get("releases") or []) if r.get("name") and r.get("name") != active]
    target = None
    for cand in hist:
        if NAME_RE.match(cand) and os.path.isdir(os.path.join(store.releases, cand, "rules")):
            target = cand
            break
    if not target:
        raise UpdateError("there is no previous release to roll back to")
    store.set_active(target)
    m["active"] = target
    m["failed"] = []
    store.write_manifest(m)
    log.info("rolled back to release %s", target)
    return target


def status(store):
    active = store.active()
    m = store.read_manifest() or {}
    rel_doc = None
    if active:
        try:
            with io.open(os.path.join(store.releases, active, "RELEASE.json"), encoding="utf-8") as f:
                rel_doc = json.load(f)
        except (OSError, ValueError):
            rel_doc = None
    return {"present": bool(active), "active": active,
            "rules": (rel_doc or {}).get("count"),
            "verified": (rel_doc or {}).get("verified") if (rel_doc or {}).get("verified") is not None
                        else (m.get("package") or {}).get("verified"),
            "verification": (rel_doc or {}).get("verification") or
                            (m.get("package") or {}).get("verification"),
            "updated": ((m.get("sources") or {}).get((rel_doc or {}).get("source", ""), {}) or {}).get("updated"),
            "failed": m.get("failed") or [], "releases": [r.get("name") for r in (m.get("releases") or [])],
            "manifest_generated": m.get("generated")}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(description="safe signature updater for scan_backdoors, v" + VERSION)
    ch = ap.add_argument_group("channels")
    ch.add_argument("--update-signatures", action="store_true",
                    help="install the project's own rule package (package_source in sources.json)")
    ch.add_argument("--update-from-bundle", metavar="FILE",
                    help="install a rule package from a local zip (offline; the same checks)")
    ch.add_argument("--update-from-upstream", action="store_true",
                    help="sync the upstream sources pinned by commit SHA in sources.json")
    ch.add_argument("--rollback-signatures", action="store_true",
                    help="activate the previous release again")
    ch.add_argument("--status", action="store_true", help="print the active state as JSON and exit")
    ch.add_argument("--rules-path", action="store_true",
                    help="print the rules folder of the active release and exit (exit 1 when none)")
    ver = ap.add_argument_group("verification")
    ver.add_argument("--package-sha256", metavar="HEX",
                     help="out-of-band sha256 of the bundle/archive: what makes an update VERIFIED")
    ver.add_argument("--allow-unverified", action="store_true",
                     help="accept a package nothing can verify (loudly; the manifest records \"verified\": false)")
    ver.add_argument("--only", metavar="SOURCE", help="with --update-from-upstream: only this source")
    ap.add_argument("--data-dir", metavar="DIR",
                    help="data folder (default: %%SBD_DATA_DIR%% or ~/.scan_backdoors)")
    ap.add_argument("--version", action="version", version="updater " + VERSION)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    root = data_dir(args.data_dir)
    store = Store(root)
    setup_logging(root)
    log_lines = []
    actions = [args.update_signatures, bool(args.update_from_bundle), args.update_from_upstream,
               args.rollback_signatures, args.status, args.rules_path]
    if sum(1 for a in actions if a) != 1:
        print("Choose exactly one action: --update-signatures / --update-from-bundle FILE / "
              "--update-from-upstream / --rollback-signatures / --status / --rules-path")
        return EXIT_CONFIG
    if args.package_sha256 and not re.match(r"^[0-9a-fA-F]{64}$", args.package_sha256):
        print("--package-sha256 must be 64 hex characters")
        return EXIT_CONFIG
    try:
        store.ensure()
        if args.rules_path:
            active = store.active()
            if not active:
                return EXIT_CONFIG
            print(os.path.join(store.releases, active, "rules"))
            return EXIT_OK
        if args.status:
            print(json.dumps(status(store), indent=2, sort_keys=True))
            return EXIT_OK
        if args.update_from_bundle:
            name = channel_bundle(store, args.update_from_bundle,
                                  (args.package_sha256 or "").lower() or None,
                                  args.allow_unverified, log_lines)
            print("Installed and activated release '%s'." % name)
        elif args.update_signatures:
            name = channel_project(store, args.allow_unverified, log_lines)
            print("Installed and activated release '%s'." % name)
        elif args.update_from_upstream:
            updated, failed = channel_upstream(store, args.only, args.allow_unverified, log_lines)
            for u in updated:
                print("Updated: %s" % u)
            for fl in failed:
                print("FAILED source %s: %s" % (fl["source"], fl["error"]))
            if failed:
                print("The update is PARTIAL: the failed sources keep the rules they contributed "
                      "in the previous release. Fix sources.json (or the network) and run again.")
                return EXIT_PARTIAL
        else:
            name = channel_rollback(store)
            print("Rolled back: the active release is now '%s'." % name)
        if not (status(store).get("verified") or store.active() is None):
            print("WARNING: the active package is UNVERIFIED - it was accepted with "
                  "--allow-unverified and is recorded as \"verified\": false in the manifest.")
        for line in log_lines:
            print(line)
        return EXIT_OK
    except UpdateError as exc:
        log.error("%s", sanitize(exc))
        print("REFUSED: %s" % sanitize(exc))
        print("The previously active release is unchanged.")
        return EXIT_VERIFY
    except OSError as exc:
        # a hostile file name (a reserved device name on Windows), a full disk, a
        # --data-dir that is not a folder: a clear refusal, never a traceback
        log.error("file system error: %s", sanitize(exc))
        print("REFUSED: a file system error: %s" % sanitize(exc))
        print("The previously active release is unchanged.")
        return EXIT_VERIFY
    except KeyboardInterrupt:
        print("Interrupted - the previously active release is unchanged.")
        return EXIT_VERIFY


if __name__ == "__main__":
    sys.exit(main())
