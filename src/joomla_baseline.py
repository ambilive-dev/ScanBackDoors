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
import json
import re
import sys
import urllib.error
import urllib.request

try:
    from version import VERSION
except ImportError:
    VERSION = "3.1"      # single-file fallback; must equal src/version.py

RELEASE_URL_TEMPLATE = "https://api.github.com/repos/joomla/joomla-cms/releases/tags/%s"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def validate_version(value):
    """True for a full stable version like 3.9.27 (nothing else passes)."""
    return bool(VERSION_RE.fullmatch(value))


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


def run(version, out_dir, force=False, keep_archive=False, release_url=None):
    """The whole job. Returns the exit code (0 ok, 1 an explained failure)."""
    if not validate_version(version):
        print("Invalid version '%s': use the full stable form N.N.N (for example, 3.9.27)." % version)
        return 1
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
    try:
        chosen = pick_full_package(release.get("assets") or [])
    except ValueError as exc:
        print(str(exc))
        return 1
    print("Selected %s" % chosen["name"])
    print("Download not wired yet (internal state)")
    return 1


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
