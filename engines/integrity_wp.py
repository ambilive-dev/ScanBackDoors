# -*- coding: utf-8 -*-
"""WordPress core integrity: does every core file match the official release?

For a backdoor scanner this matters more than a CVE list: a modified
`wp-includes/version.php` or a new PHP file inside `wp-admin/` is not a theory
about a vulnerability, it is a file that is not what WordPress published.

The reference is the official checksums service (engines/cms_api.py records what
was verified about it on 2026-11-28). Consequences this module lives by:

* the digests are MD5, because that is what WordPress uses internally. They are a
  lookup key into the official catalogue, not an authenticity proof - what is
  trusted here is the https connection to a pinned host, nothing else;
* a modified file, an extra file and a missing file are three different facts and
  stay separate: "missing" is usually a deleted file, "modified" is a patched
  core, "extra" inside `wp-admin/` or `wp-includes/` is the classic home of a
  dropped shell;
* what the release simply does not ship (`wp-config.php`, `.htaccess`, and all of
  `wp-content` except the bundled themes) is not "extra" - that is the site's own
  content, and reporting it would bury the finding that matters;
* `readme.html` and `license.txt` differ by language and by habit: their
  difference is recorded as soft and never counts as suspicious;
* no file content is parsed or executed here, only hashed with a size cap, and
  symlinks are never followed. The worst a hostile core file can do is not match.

The result also carries `verified_paths`: the files proven identical to the
release. The scanner may use that to skip content engines on them (the way a
clean Joomla baseline works) - but only when the report says `complete`, because
"we did not look" and "it matched" are different answers.
"""

import hashlib
import os
import stat

MAX_FILE = 8 * 1024 * 1024         # the largest WordPress core file is a few hundred KB
MAX_FILES = 20000                  # files hashed in one run
CORE_DIRS = ("wp-admin", "wp-includes")
CODE_EXTS = (".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht",
             ".phar", ".inc")
# A difference in these is ordinary (translations, hand-edited licences).
SOFT_NAMES = {"readme.html", "license.txt", "wp-config-sample.php", "readme.txt"}
# Root-level files a real WordPress site has and the release does not ship.
ROOT_ALLOW = {"wp-config.php", ".htaccess", ".user.ini", "web.config", "index.html",
              "composer.json", "composer.lock", "robots.txt", "favicon.ico",
              "sitemap.xml", "crossdomain.xml"}
ROOT_LITTER = ("._", ".")          # editor/OS litter at the root is not a finding


def _md5_sum(path, max_size=None):
    """MD5 of a regular file within the caps, or None when it cannot be hashed.

    `max_size` defaults to the module's MAX_FILE at call time, so a test (or a
    caller with a smaller site) can lower it without re-importing the module.
    `usedforsecurity=False` is passed where the interpreter knows the argument: on
    a FIPS-hardened Python an MD5 without that flag is refused outright, and this
    really is a catalogue key rather than a defence.
    """
    if max_size is None:
        max_size = MAX_FILE
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > max_size:
        return None
    try:
        hasher = hashlib.md5(usedforsecurity=False)         # Python 3.9+
    except TypeError:
        hasher = hashlib.md5()
    except ValueError:
        return None                                         # FIPS build, no flag support
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError:
        return None
    return hasher.hexdigest()


def _rel(site_root, path):
    return os.path.relpath(path, site_root).replace(os.sep, "/")


def _families(checksums):
    """The component folders the release itself ships files in, e.g.
    `wp-content/themes/twentytwentythree/`. A new file in one of those is as
    notable as a new file in wp-includes; a new file anywhere else in wp-content
    is the site's own business."""
    out = set()
    for rel in checksums:
        parts = rel.split("/")
        if len(parts) >= 3:
            out.add("/".join(parts[:3]) + "/")
    return out


def _is_extra(rel, families):
    """Is a file the release does not list suspicious where it sits?"""
    if rel in SOFT_NAMES or rel in ROOT_ALLOW:
        return False
    if "/" not in rel:                                   # the site root
        if rel.startswith(ROOT_LITTER):
            return False
        return rel.lower().endswith(CODE_EXTS)           # only code at the root
    top = rel.split("/", 1)[0]
    if top in CORE_DIRS:
        return True                                      # anything new inside the core
    family = "/".join(rel.split("/")[:3]) + "/"
    return family in families and rel.lower().endswith(CODE_EXTS)


def _walk_folder(site_root, base, seen):
    """Every regular file under `base`, symlinks and linked folders skipped."""
    for root, dirs, files in os.walk(base, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for name in files:
            full = os.path.join(root, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            rel = _rel(site_root, full)
            if rel not in seen:
                seen.add(rel)
                yield rel, full


def _iter_candidates(site_root, checksums, families):
    """The files worth comparing: the core folders, the component folders the
    release itself ships files in, the site root, and every file the release
    lists. Symlinks and non-regular files are skipped."""
    seen = set()
    for folder in CORE_DIRS:
        base = os.path.join(site_root, folder)
        if os.path.isdir(base) and not os.path.islink(base):
            for item in _walk_folder(site_root, base, seen):
                yield item
    for family in sorted(families):
        base = os.path.join(site_root, *family.split("/"))
        if os.path.isdir(base) and not os.path.islink(base):
            for item in _walk_folder(site_root, base, seen):
                yield item
    try:
        names = sorted(os.listdir(site_root))
    except OSError:
        names = []
    for name in names:
        full = os.path.join(site_root, name)
        if os.path.islink(full) or not os.path.isfile(full) or name in seen:
            continue
        seen.add(name)
        yield name, full
    for rel in checksums:
        if rel in seen:
            continue
        full = os.path.join(site_root, *rel.split("/"))
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        seen.add(rel)
        yield rel, full


def check_core(site_root, checksums, version="", max_files=MAX_FILES):
    """Compare a WordPress site with the official checksums of one release.

    -> {"version", "complete", "reference", "files_hashed", "verified",
        "verified_paths", "modified", "extra", "missing", "soft", "unreadable"}

    `complete` is False when there was no reference, the caps were hit, or files
    could not be read. A caller must not treat an incomplete report as clean.
    """
    result = {"version": version or "", "complete": True, "reference": len(checksums or {}),
              "files_hashed": 0, "verified": 0, "verified_paths": set(),
              "modified": [], "extra": [], "missing": [], "soft": [], "unreadable": 0}
    if not checksums:
        result["complete"] = False                  # no reference: nothing was verified
        return result
    families = _families(checksums)
    compared = set()
    attempted = set()
    for rel, full in _iter_candidates(site_root, checksums, families):
        if result["files_hashed"] >= max_files:
            result["complete"] = False
            break
        listed = rel in checksums
        if not listed and not _is_extra(rel, families):
            continue
        attempted.add(rel)
        digest = _md5_sum(full)
        result["files_hashed"] += 1
        if digest is None:
            result["unreadable"] += 1
            result["complete"] = False
            continue
        compared.add(rel)
        if not listed:
            result["extra"].append({"path": rel,
                                    "php": rel.lower().endswith(CODE_EXTS)})
            continue
        if digest == checksums[rel]:
            result["verified"] += 1
            result["verified_paths"].add(rel)
        elif rel in SOFT_NAMES:
            result["soft"].append({"path": rel, "expected": checksums[rel],
                                   "actual": digest})
        else:
            result["modified"].append({"path": rel, "expected": checksums[rel],
                                       "actual": digest})
    for rel in sorted(checksums):
        if rel in compared or rel in attempted:
            continue                     # hashed, or already counted as unreadable
        if os.path.exists(os.path.join(site_root, *rel.split("/"))):
            result["unreadable"] += 1               # there, but never hashed: unknown
            result["complete"] = False
            continue
        if rel in SOFT_NAMES:
            result["soft"].append({"path": rel, "expected": checksums[rel], "actual": ""})
        else:
            result["missing"].append(rel)
    return result


def summarize(report):
    """The integrity answer as one small JSON-safe dict for console, report, GUI."""
    if not report:
        return {"checked": False}
    return {"checked": True,
            "version": report.get("version", ""),
            "complete": bool(report.get("complete")),
            "reference_files": report.get("reference", 0),
            "files_hashed": report.get("files_hashed", 0),
            "verified": report.get("verified", 0),
            "modified": len(report.get("modified") or []),
            "extra": len(report.get("extra") or []),
            "missing": len(report.get("missing") or []),
            "soft": len(report.get("soft") or []),
            "unreadable": report.get("unreadable", 0)}


def findings(report, limit=50):
    """The integrity problems as rows of (site-relative path, label, detail).

    The scanner turns each row into an ordinary finding on that file, so a
    modified core file gets a score, appears in the table and can be quarantined
    like anything else. The detail always names what was compared: "modified"
    without a reference is not evidence.
    """
    out = []
    for row in (report.get("modified") or [])[:limit]:
        out.append((row["path"], "modified WordPress core file (official checksum differs)",
                    "official %s, on the site %s" % (row["expected"][:12], row["actual"][:12])))
    for row in (report.get("extra") or [])[:limit]:
        where = row["path"].split("/")[0] + "/" if "/" in row["path"] else "the site root"
        out.append((row["path"],
                    "file the official WordPress release does not ship (new file in %s)" % where,
                    "checksum catalogue of WordPress %s" % (report.get("version") or "?")))
    for rel in (report.get("missing") or [])[:limit]:
        out.append((rel, "WordPress core file is missing",
                    "the official release of %s ships it" % (report.get("version") or "?")))
    return out
