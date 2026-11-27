#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Download a clean Joomla distribution (the official Full_Package) of a given
version, verify it, and cache it unpacked with a sha256 manifest.

The scanner (--baseline-dir) and the cleaner (--replace-core --baseline-dir)
both need a clean Joomla of the exact same version as the site they work on.
This tool fetches that distribution automatically:

    python3 joomla_baseline.py 3.9.27
        joomla-baselines/Joomla_3.9.27/                <- pass this folder as --baseline-dir
        joomla-baselines/Joomla_3.9.27.baseline.json   <- manifest: every file and its sha256

Source: the official releases of the joomla/joomla-cms GitHub repository
(HTTPS only; the API plus GitHub's download CDN). Integrity, two tiers:
when the API carries an official sha256 digest for the asset it is compared
mandatory; when it does not (older releases), the unpacked distribution must
report the requested version itself. A re-run verifies the cached baseline
offline and re-downloads only if a file changed.

The script is standalone: stdlib only (Python 3.6+), one file.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
import zipfile

try:
    from version import VERSION
except ImportError:
    VERSION = "3.2"  # single-file fallback; must equal src/version.py

RELEASE_URL_TEMPLATE = "https://api.github.com/repos/joomla/joomla-cms/releases/tags/%s"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def require_official_https(url):
    """The download URL taken from the release metadata must be HTTPS on GitHub's own hosts.
    (The module docstring promises HTTPS only; this makes it true. An explicit --release-url
    is the user's own choice and is not restricted.)"""
    from urllib.parse import urlparse
    u = urlparse(url or "")
    host = (u.hostname or "").lower()
    official = host in ("api.github.com", "github.com") or host.endswith(".githubusercontent.com")
    if u.scheme != "https" or not official:
        raise ValueError("Refusing a download URL that is not HTTPS on GitHub: %s" % (url or "(empty)"))


def validate_version(value):
    """True for a full stable version like 3.9.27 (nothing else passes)."""
    return bool(VERSION_RE.match(value))


def fetch_json(url):
    """GET a URL and parse the JSON body. HTTPError/URLError propagate."""
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def pick_full_package(assets):
    """The single Full_Package.zip asset of a release; a ValueError otherwise."""
    full = [a for a in assets if (a.get("name") or "").endswith("Full_Package.zip")]
    if not full:
        names = ", ".join((a.get("name") or "?") for a in assets) or "(none)"
        raise ValueError("No Full_Package.zip asset in the release; assets seen: %s" % names)
    if len(full) > 1:
        names = ", ".join(a["name"] for a in full)
        raise ValueError("Ambiguous release: several Full_Package.zip assets: %s" % names)
    return full[0]


def _remove(path):
    """Delete a file or a tree; a failure to clean up is not fatal."""
    try:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def http_download(url, dest_path):
    """Stream url to dest_path (through a .part side file); return bytes written.

    A finished download is moved into place atomically; when it does not finish
    the .part file is removed and the reason is a ValueError, never a traceback.
    """
    part = dest_path + ".part"
    try:
        try:
            resp = urllib.request.urlopen(url, timeout=60)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise ValueError("the asset is gone (HTTP 404): %s" % url)
            if exc.code in (403, 429):
                raise ValueError("GitHub API rate limit reached (60 requests/hour unauthenticated); try again later.")
            raise ValueError("download failed (HTTP %d)" % exc.code)
        except urllib.error.URLError as exc:
            raise ValueError("cannot reach the download URL: %s" % exc.reason)
        length = 0
        headers = getattr(resp, "headers", None)
        if headers is not None:
            try:
                length = int(headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                length = 0
        written = 0
        step = 0
        with resp:
            with open(part, "wb") as dst:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    written += len(chunk)
                    if length:
                        done = written * 100 // length
                        if done // 10 > step:
                            step = done // 10
                            print("Downloaded %d%% of the archive" % (step * 10))
                    elif written // (1 << 20) > step:
                        step = written // (1 << 20)
                        print("Downloaded %d MB of the archive" % step)
        if length and written != length:
            raise ValueError("the download is incomplete (%d of %d bytes)" % (written, length))
        os.replace(part, dest_path)
    except BaseException:
        _remove(part)
        raise
    return written


def sha256_file(path):
    """SHA-256 of a file, retrying briefly on a locked read.

    Real-time antivirus puts a short lock on freshly written files while it
    scans them. A freshly downloaded archive is read within the same second,
    so the read can collide with the lock. The lock releases by itself, so
    wait a little and try again before giving up.
    """
    for i in range(6):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            return h.hexdigest()
        except PermissionError:
            if i + 1 == 6:
                raise OSError("the file is locked while reading it (real-time antivirus keeps a short "
                              "lock on freshly written files): re-run, or exclude its folder from "
                              "the antivirus: %s" % path)
            time.sleep(0.5)


def _safe_member_path(dest_dir, name):
    """The destination of one archive member; a ValueError when it escapes dest_dir."""
    if os.path.isabs(name) or re.match(r"^[A-Za-z]:", name):
        raise ValueError("Refusing an unsafe path in the archive: %s" % name)
    parts = name.replace("\\", "/").split("/")
    if ".." in parts:
        raise ValueError("Refusing an unsafe path in the archive: %s" % name)
    full = os.path.realpath(os.path.join(dest_dir, *parts))
    root = os.path.realpath(dest_dir)
    if full != root and not full.startswith(root + os.sep):
        raise ValueError("Refusing an unsafe path in the archive: %s" % name)
    return full


def extract_zip(zip_path, dest_dir):
    """Unpack the archive into dest_dir (creating it), flat.

    Members that would escape the destination are refused (an absolute path,
    a drive prefix like C:/, a .. component). When index.php is not at the
    root of the archive and every member sits under one common top folder,
    that folder is stripped, so the tree ends up the way --baseline-dir
    expects it (index.php at its root).
    """
    with zipfile.ZipFile(zip_path) as z:
        members = [i.filename for i in z.infolist() if not i.is_dir()]
    prefix = ""
    if "index.php" not in members:
        roots = set(n.split("/", 1)[0] for n in members if "/" in n)
        if len(roots) == 1:
            prefix = roots.pop() + "/"
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if prefix:
                if not name.startswith(prefix):
                    raise ValueError("the archive mixes a top-level folder with root-level files; "
                                     "cannot determine its layout: %s" % name)
                name = name[len(prefix):]
            if not name:
                continue
            full = _safe_member_path(dest_dir, name)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with z.open(info) as src, open(full, "wb") as dst:
                shutil.copyfileobj(src, dst)


def parse_joomla_version(root):
    """The version the distribution reports itself, or None.

    Joomla 3.9+ / 4 / 5 / 6 keep it in libraries/src/Version.php as three
    integers; 3.7 and earlier in libraries/cms/version/version.php as
    RELEASE plus DEV_LEVEL (a const in 3.7, a plain $variable in older files).
    """
    try:
        with open(os.path.join(root, "libraries", "src", "Version.php"),
                  "r", encoding="utf-8", errors="ignore") as f:
            t = f.read()
        parts = [re.search(r"%s_VERSION\s*=\s*(\d+)" % k, t) for k in ("MAJOR", "MINOR", "PATCH")]
        if all(parts):
            return ".".join(m.group(1) for m in parts)
    except OSError:
        pass
    try:
        with open(os.path.join(root, "libraries", "cms", "version", "version.php"),
                  "r", encoding="utf-8", errors="ignore") as f:
            t = f.read()
        rel = re.search(r"(?:const\s+)?\$?RELEASE\s*=\s*'([\d.]+)'", t)
        dev = re.search(r"(?:const\s+)?\$?DEV_LEVEL\s*=\s*'(\d+)'", t)
        if rel and dev:
            return "%s.%s" % (rel.group(1), dev.group(1))
    except OSError:
        pass
    return None


def build_manifest(tree_root, version, asset, source, archive_sha256, verified_by):
    """The manifest of an unpacked tree: every file, relative POSIX path, sha256."""
    files = {}
    for base, _dirs, names in os.walk(tree_root):
        for n in names:
            p = os.path.join(base, n)
            files[os.path.relpath(p, tree_root).replace(os.sep, "/")] = sha256_file(p)
    return {
        "schema": 1,
        "version": version,
        "asset": asset,
        "source": source,
        "archive_sha256": archive_sha256,
        "verified_by": verified_by,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "files": files,
    }


def verify_cached_tree(tree_root, manifest):
    """True when the tree still matches its manifest (every file present and intact)."""
    if not isinstance(manifest, dict):
        return False
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        return False
    if not os.path.isfile(os.path.join(tree_root, "index.php")):
        return False
    for rel, digest in files.items():
        full = os.path.join(tree_root, *rel.split("/"))
        if not os.path.isfile(full):
            return False
        try:
            if sha256_file(full) != digest:
                return False
        except OSError:
            return False
    return True


def write_manifest(path, manifest):
    """Atomic write: a .tmp side file is replaced into place."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def read_manifest(path):
    """The manifest of a cached tree; None when it is missing or unreadable."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def run(version, out_dir, force=False, keep_archive=False, release_url=None):
    """The whole job. Returns the exit code (0 ok, 1 an explained failure).

    A ValueError or an OSError escaping here is a handled error: main() prints
    the message and returns 1.
    """
    if not validate_version(version):
        print("Invalid version '%s': use the full stable form N.N.N (for example, 3.9.27)." % version)
        return 1
    tree = os.path.join(out_dir, "Joomla_%s" % version)
    manifest_path = os.path.join(out_dir, "Joomla_%s.baseline.json" % version)
    if not force:
        manifest = read_manifest(manifest_path) if os.path.isfile(manifest_path) else None
        if manifest is not None and verify_cached_tree(tree, manifest):
            print("OK: baseline verified from cache: %s" % tree)
            return 0
    # a previous run may have died mid-flight; its leftovers must not confuse this one
    _remove(os.path.join(out_dir, "Joomla_%s.zip.part" % version))
    _remove(os.path.join(out_dir, ".tmp-%s" % version))
    url = release_url or (RELEASE_URL_TEMPLATE % version)
    try:
        release = fetch_json(url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print("No release found for Joomla %s on the official joomla/joomla-cms repository." % version)
        elif exc.code in (403, 429):
            print("GitHub API rate limit reached (60 requests/hour unauthenticated); try again later.")
        else:
            print("GitHub API error %d." % exc.code)
        return 1
    except urllib.error.URLError as exc:
        print("Cannot reach the Joomla release API: %s" % exc.reason)
        return 1
    if not isinstance(release, dict):
        print("The release API returned a malformed object for Joomla %s; nothing was done." % version)
        return 1
    assets = release.get("assets")
    if not isinstance(assets, list):
        assets = []
    chosen = pick_full_package(assets)
    if release_url is None:
        require_official_https(chosen.get("browser_download_url"))
    print("Selected %s" % chosen["name"])
    os.makedirs(out_dir, exist_ok=True)
    zip_path = os.path.join(out_dir, "Joomla_%s.zip" % version)
    http_download(chosen.get("browser_download_url") or "", zip_path)
    actual = sha256_file(zip_path)
    raw_digest = chosen.get("digest")
    if isinstance(raw_digest, str) and raw_digest.startswith("sha256:"):
        expected = raw_digest[len("sha256:"):]
    else:
        if isinstance(raw_digest, str) and raw_digest:
            print("Warning: the API carries a digest we do not verify (%s); the version self-check applies."
                  % raw_digest)
        expected = None
    if expected is not None and expected.lower() != actual.lower():
        print("sha256 mismatch: the API reports %s but the archive is %s." % (expected, actual))
        print("The download may be corrupted or tampered with; nothing was unpacked, the archive was removed.")
        _remove(zip_path)
        return 1
    verified_by = "sha256" if expected is not None else "version-file"
    tmp = os.path.join(out_dir, ".tmp-%s" % version)
    try:
        extract_zip(zip_path, tmp)
    except (ValueError, zipfile.BadZipFile) as exc:
        _remove(tmp)
        _remove(zip_path)
        if isinstance(exc, zipfile.BadZipFile):
            raise ValueError("the archive is not a valid zip file (truncated or corrupted download?): %s" % exc)
        raise
    detected = parse_joomla_version(tmp)
    if verified_by == "version-file":
        if detected is None:
            _remove(tmp)
            _remove(zip_path)
            print("could not determine the version of the distribution (%s expected); nothing was kept." % version)
            return 1
        if detected != version:
            _remove(tmp)
            _remove(zip_path)
            print("the distribution reports Joomla %s but %s was requested; nothing was kept." % (detected, version))
            return 1
    elif detected is not None and detected != version:
        # the sha256 proves the file is what the API listed, not that the release is the one asked for
        _remove(tmp)
        _remove(zip_path)
        print("the distribution reports Joomla %s but %s was requested; nothing was kept." % (detected, version))
        return 1
    _remove(tree)
    try:
        os.replace(tmp, tree)
    except OSError:
        _remove(tmp)
        raise
    manifest = build_manifest(tree, version, chosen["name"],
                              chosen.get("browser_download_url"), actual, verified_by)
    write_manifest(manifest_path, manifest)
    if not keep_archive:
        _remove(zip_path)
    print("Done: clean Joomla %s at %s" % (version, tree))
    if detected:
        print("Self-check: the distribution reports Joomla %s." % detected)
    print("Use it as: --baseline-dir %s" % tree)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="joomla_baseline.py",
        description="Download a clean Joomla (official Full_Package) of a given version, "
                    "verify it, and cache it unpacked with a sha256 manifest. Pass the "
                    "resulting folder as --baseline-dir to the scanner or the cleaner.")
    p.add_argument("version", help="the exact stable version, for example 3.9.27")
    p.add_argument("--out", default="joomla-baselines",
                   help="cache directory (default: joomla-baselines in the current directory)")
    p.add_argument("--force", action="store_true",
                   help="re-download even when the cached baseline is valid")
    p.add_argument("--keep-archive", action="store_true",
                   help="keep the downloaded zip")
    p.add_argument("--release-url", default=None,
                   help="release-metadata URL override (default: the official GitHub API); "
                        "for mirrors and testing, not a documented user option")
    p.add_argument("--version", action="version", version="joomla_baseline %s" % VERSION)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return run(args.version, args.out, args.force, args.keep_archive, args.release_url)
    except ValueError as exc:
        print(str(exc))
        return 1
    except (OSError, IOError) as exc:
        print("Error: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
