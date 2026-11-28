# -*- coding: utf-8 -*-
"""What is installed on the scanned site: CMS, version, components (TZ v2, 8.1).

The inventory is the input of the vulnerability audit and of the WordPress
integrity check, and it is read entirely from files a compromised site controls.
Every rule below follows from that one fact:

* PHP is never executed and never imported. The version of WordPress lives in
  `wp-includes/version.php`, which is PHP source: it is read as bytes and matched
  with a regular expression inside a size-capped slice. A file whose "version"
  line contains code therefore yields no version, not a side effect.
* XML is the classic billion-laughs target and `xml.etree` in the standard
  library has no protection against it (and `defusedxml` is not an option: no
  third-party packages). Any XML containing a `<!DOCTYPE` or `<!ENTITY`
  declaration is refused before the parser ever sees it, whatever the CMS.
* Values are hygiene-checked (`engines/versions.clean_version`, `_clean_text`):
  a version or a name from a manifest later travels into a URL and into a
  report, so the alphabet is closed instead of "trusted, then escaped".
* Paths are kept relative to the site root and never absolute: the inventory ends
  up in a report the user may publish.
* A symlink is never followed, and a path that resolves outside the site is not
  read - the site may contain a link to /etc/passwd or to a share.

Nothing here decides whether a version is dangerous; it only states what was
found, and how the statement was obtained (`source`: "declared" - whatever the
file says - versus "verified" - confirmed against an official reference).
"""

import os
import re

from engines.versions import clean_version, compare_version

# How much of a file is read for a header. Plugin/theme headers are at the very
# top of a file; reading more would mean reading the malware too.
HEADER_LIMIT = 16 * 1024
# Joomla manifests are small; a bigger one is not a manifest but a payload.
XML_LIMIT = 1024 * 1024
# A site with more components than this is either a monster or an attack; either
# way the scan must not spend unbounded time on the inventory.
MAX_COMPONENTS = 2000
MAX_HEADER_FILES = 12         # .php files examined in one plugin folder
TEXT_LIMIT = 120              # length of a name kept in the report

# The names of the two CMSs, and what counts as a component of each.
WP = "wordpress"
JOOMLA = "joomla"

# A version string in a file's text, hostile-input shaped: at most 32 characters
# of a closed alphabet, which is also what clean_version() enforces.
_WP_VERSION_RE = re.compile(r"""\$\s*wp_version\s*=\s*'([^']{1,32})'""")
_JVERSION_CONST_RE = re.compile(
    r"const\s+(MAJOR|MINOR|PATCH|EXTRA_VERSION)\s*=\s*['\"]?([^'\";\r\n]{1,32})['\"]?\s*;")

# An XML declaration of entities is enough to refuse the file: a legitimate CMS
# manifest does not need one, and without this test a 1 KB file can expand to
# gigabytes inside the parser.
_XML_REFUSAL_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.I)

# "Version: 1.2.3" inside a plugin/theme header block. WordPress accepts both the
# doc-comment spelling (` * Version: 1.2`) and the plain one a theme's style.css
# uses (`Version: 1.2`), so the bullet is optional - and the line is anchored,
# because a `Version:` inside the code body is not a header.
_HEADER_VERSION_RE = re.compile(r"^\s*(?:\*\s*)?Version\s*:\s*([^\r\n*]{1,48})\s*$",
                                re.I | re.M)
_HEADER_NAME_RE = re.compile(
    r"^\s*(?:\*\s*)?(?:Plugin|Theme)\s*Name\s*:\s*([^\r\n]{1,120})\s*$", re.I | re.M)
_README_STABLE_RE = re.compile(r"^\s*Stable tag\s*:\s*(\S{1,48})\s*$", re.I | re.M)
_README_TAG_RE = re.compile(r"^\s*=+\s*(\d[^=\r\n]{0,30})=+\s*$", re.I | re.M)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069\ufeff]")
_WS_RE = re.compile(r"\s+")


class InventoryAborted(Exception):
    """A file refused for safety reasons. Carried as a note, never as a crash."""


def _open_read(path, limit):
    """Up to `limit` bytes of one regular file inside the site, or None.

    A symlink, a device, a FIFO or anything that is not a regular file is None:
    reading those is how a scanner hangs or reads something the site does not
    own. The size is checked before reading, and at most `limit` bytes are taken
    even when the file is smaller than the check suggests.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return None
    import stat as _stat
    if not _stat.S_ISREG(st.st_mode):
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read(min(max(0, int(st.st_size)), limit) + 1)
    except OSError:
        return None
    return data[:limit]


def _text(data):
    """Bytes -> text for regexing. Never decoded as anything but UTF-8 with
    replacements: a manifest in another encoding loses characters, not the scan."""
    if data is None:
        return ""
    return data.decode("utf-8", "replace")


def _clean_text(value, limit=TEXT_LIMIT):
    """A name from a manifest: printable, single-spaced, bounded.

    Angle brackets are removed on purpose. No CMS extension is named with them,
    so a name that carries them is not a name but an attempt at whatever reads
    the report (a browser, a spreadsheet), and a scanner should not be the
    component that faithfully forwards it.
    """
    if not isinstance(value, str):
        return ""
    value = _CONTROL_RE.sub("", value).replace("\r", " ").replace("\n", " ")
    value = value.replace("<", "").replace(">", "")
    value = _WS_RE.sub(" ", value).strip()
    return value[:limit]


def _inside(root, candidate):
    """Is `candidate` a real path under `root` (symlinks resolved, root included)?"""
    try:
        base = os.path.realpath(root)
        real = os.path.realpath(candidate)
    except OSError:
        return False
    if real == base:
        return True
    return real.startswith(base + os.sep)


def _safe_xml_root(path):
    """Parse a manifest's XML, or raise InventoryAborted.

    Refuses anything that declares a DOCTYPE or an ENTITY (see the module
    docstring) and anything bigger than XML_LIMIT.
    """
    from xml.etree import ElementTree
    data = _open_read(path, XML_LIMIT)
    if data is None:
        raise InventoryAborted("unreadable")
    if len(data) > XML_LIMIT:
        raise InventoryAborted("XML larger than %d bytes" % XML_LIMIT)
    if _XML_REFUSAL_RE.search(data.decode("latin-1")):
        raise InventoryAborted("XML declares DOCTYPE/ENTITY: refused")
    try:
        return ElementTree.fromstring(data)
    except Exception as exc:                      # not well-formed, not XML at all
        raise InventoryAborted("XML is not parseable: %s" % type(exc).__name__)


def _element_text(root, *path):
    node = root
    for part in path:
        if node is None:
            return ""
        node = node.find(part)
    if node is None or node.text is None:
        return ""
    return node.text.strip()


# ---------------------------------------------------------------------------
# WordPress
# ---------------------------------------------------------------------------

def wp_core_version(site_root):
    """-> {"version", "source", "file"} for WordPress core, version "" if unknown.

    Only the `$wp_version` assignment is looked for, in a capped slice of a file
    that is PHP source and is never executed.
    """
    rel = "wp-includes/version.php"
    info = {"version": "", "source": "declared", "file": rel}
    text = _text(_open_read(os.path.join(site_root, "wp-includes", "version.php"),
                            HEADER_LIMIT))
    m = _WP_VERSION_RE.search(text)
    if m:
        info["version"] = clean_version(m.group(1))
    return info


def _header_info(path):
    """{"version", "name"} from a WordPress plugin/theme header, "" when absent.

    Only the first comment block is searched, the way WordPress itself reads
    headers: a `Version:` line inside the code body is not a header.
    """
    text = _text(_open_read(path, HEADER_LIMIT))
    if not text:
        return {"version": "", "name": ""}
    block = text
    start = text.find("/*")
    if start >= 0:
        end = text.find("*/", start + 2)
        if end > start:
            block = text[start:end]
    info = {"version": "", "name": ""}
    m = _HEADER_VERSION_RE.search(block)
    if m:
        info["version"] = clean_version(m.group(1))
    m = _HEADER_NAME_RE.search(block)
    if m:
        info["name"] = _clean_text(m.group(1))
    return info


def _readme_version(plugin_dir):
    """The version a readme.txt claims: the newest `== Changelog ==` heading,
    which is a second, weaker statement than the header. Used only when the
    plugin header says nothing."""
    text = _text(_open_read(os.path.join(plugin_dir, "readme.txt"), HEADER_LIMIT))
    if not text:
        return ""
    m = _README_STABLE_RE.search(text)
    if m:
        got = clean_version(m.group(1))
        if got:
            return got
    versions = [clean_version(x) for x in _README_TAG_RE.findall(text)]
    versions = [v for v in versions if v]
    if not versions:
        return ""
    best = versions[0]
    for cand in versions[1:]:
        if (compare_version(cand, best) or 0) > 0:
            best = cand
    return best


def _component_dirs(parent):
    """The immediate sub-folder names of `parent`, symlinks and outsiders skipped."""
    out = []
    try:
        names = sorted(os.listdir(parent))
    except OSError:
        return out
    for name in names:
        full = os.path.join(parent, name)
        try:
            if os.path.islink(full) or not os.path.isdir(full):
                continue
        except OSError:
            continue
        out.append((name, full))
    if len(out) > MAX_COMPONENTS:
        del out[MAX_COMPONENTS:]
    return out


def _candidate_headers(folder, folder_name):
    """The .php files that can be a plugin's main file, in WordPress' own order."""
    own = os.path.join(folder, folder_name + ".php")
    if os.path.isfile(own) and not os.path.islink(own):
        return [own]
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return []
    out = []
    for name in names:
        if not name.lower().endswith(".php"):
            continue
        full = os.path.join(folder, name)
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        out.append(full)
        if len(out) >= MAX_HEADER_FILES:
            break
    return out


def wp_components(site_root):
    """Plugins, mu-plugins and themes of a WordPress site, versions as declared."""
    out = []
    content = os.path.join(site_root, "wp-content")
    for kind, subdir in (("plugin", "plugins"), ("theme", "themes"),
                         ("mu-plugin", "mu-plugins")):
        base = os.path.join(content, subdir)
        if not os.path.isdir(base) or not _inside(site_root, base):
            continue
        if kind == "mu-plugin":
            try:
                names = sorted(n for n in os.listdir(base) if n.lower().endswith(".php"))
            except OSError:
                names = []
            for name in names[:MAX_COMPONENTS]:
                full = os.path.join(base, name)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                info = _header_info(full)
                out.append(_component(WP, kind, os.path.splitext(name)[0],
                                      info["name"], info["version"], "declared",
                                      "wp-content/%s/%s" % (subdir, name)))
            continue
        for name, folder in _component_dirs(base):
            info = {"version": "", "name": ""}
            if kind == "theme":
                style = os.path.join(folder, "style.css")
                if os.path.isfile(style) and not os.path.islink(style):
                    info = _header_info(style)
            else:
                for candidate in _candidate_headers(folder, name):
                    got = _header_info(candidate)
                    if got["version"] or got["name"]:
                        info = got
                        break
                if not info["version"]:
                    claimed = _readme_version(folder)
                    if claimed:
                        info["version"] = claimed
                        info["source_note"] = "readme"
            out.append(_component(WP, kind, name, info["name"], info["version"],
                                  info.get("source_note") or "declared",
                                  "wp-content/%s/%s" % (subdir, name)))
            if len(out) >= MAX_COMPONENTS:
                return out
    return out


# ---------------------------------------------------------------------------
# Joomla
# ---------------------------------------------------------------------------

JOOMLA_MANIFEST = os.path.join("administrator", "manifests", "files", "joomla.xml")
JOOMLA_VERSION_PHP = ("libraries", "src", "Version.php")
JOOMLA_LEGACY_PHP = ("libraries", "cms", "version", "version.php")   # Joomla 1.x/2.x


def joomla_core_version(site_root):
    """-> {"version", "source", "file"} for Joomla itself.

    First the official distribution manifest (safe XML), then the version
    constants of Version.php, then the legacy path. [ПРОВЕРИТЬ] which of the two
    PHP paths a given major version uses: trying both is cheap and harmless, and
    a wrong guess only means version "".
    """
    manifest = os.path.join(site_root, JOOMLA_MANIFEST)
    if os.path.isfile(manifest) and not os.path.islink(manifest):
        try:
            root = _safe_xml_root(manifest)
            got = clean_version(_element_text(root, "version"))
            if got:
                return {"version": got, "source": "declared",
                        "file": JOOMLA_MANIFEST.replace(os.sep, "/")}
        except InventoryAborted:
            pass                              # refused manifest: fall back, report it
    for parts in (JOOMLA_VERSION_PHP, JOOMLA_LEGACY_PHP):
        rel = "/".join(parts)
        text = _text(_open_read(os.path.join(site_root, *parts), HEADER_LIMIT))
        found = dict(_JVERSION_CONST_RE.findall(text))
        if not found:
            continue
        major = clean_version(found.get("MAJOR", ""))
        minor = clean_version(found.get("MINOR", ""))
        patch = clean_version(found.get("PATCH", ""))
        extra = clean_version(found.get("EXTRA_VERSION", ""))
        if major and minor and patch:
            version = "%s.%s.%s%s" % (major, minor, patch, extra)
        else:
            version = clean_version(extra or major or "")
        if version:
            return {"version": version, "source": "declared", "file": rel}
    return {"version": "", "source": "declared", "file": ""}


def _manifest_version(folder, preferred_name):
    """The <version> of a Joomla extension manifest, or ("", "", reason).

    Joomla names the manifest after the extension (`mod_example/mod_example.xml`),
    with `templateDetails.xml` and `<name>.xml` as the other shapes.
    """
    candidates = []
    for name in (preferred_name + ".xml", "templateDetails.xml"):
        p = os.path.join(folder, name)
        if os.path.isfile(p) and not os.path.islink(p):
            candidates.append(p)
    if not candidates:
        try:
            for name in sorted(os.listdir(folder))[:MAX_HEADER_FILES]:
                if name.lower().endswith(".xml") and not name.lower().startswith("script"):
                    p = os.path.join(folder, name)
                    if os.path.isfile(p) and not os.path.islink(p):
                        candidates.append(p)
        except OSError:
            pass
    for path in candidates:
        try:
            root = _safe_xml_root(path)
        except InventoryAborted as exc:
            return "", "", str(exc)
        version = clean_version(_element_text(root, "version"))
        name = _clean_text(_element_text(root, "name"))
        if version or name:
            return version, name, ""
    return "", "", "no manifest"


def joomla_components(site_root):
    """Components, modules, plugins and templates of a Joomla site."""
    out = []
    groups = (("component", os.path.join("administrator", "components"), ""),
              ("component", os.path.join("components"), ""),
              ("module", os.path.join("modules"), ""),
              ("plugin", os.path.join("plugins"), "grouped"),
              ("template", os.path.join("templates"), ""))
    for kind, rel_dir, shape in groups:
        base = os.path.join(site_root, *rel_dir.split("/"))
        if not os.path.isdir(base) or not _inside(site_root, base):
            continue
        rel_base = rel_dir.replace(os.sep, "/")
        # (name, folder, site-relative path) - built once, so a report never has
        # to guess which folder a name came from.
        entries = []
        if shape == "grouped":                       # plugins/<group>/<plugin>
            for group_name, group_dir in _component_dirs(base):
                for name, folder in _component_dirs(group_dir):
                    entries.append((name, folder,
                                    "%s/%s/%s" % (rel_base, group_name, name)))
        else:
            for name, folder in _component_dirs(base):
                entries.append((name, folder, "%s/%s" % (rel_base, name)))
        for name, folder, rel in entries:
            version, cname, note = _manifest_version(folder, name)
            out.append(_component(JOOMLA, kind, name, cname, version,
                                  "declared" if version else "unknown", rel, note))
            if len(out) >= MAX_COMPONENTS:
                return out
    # The same name can exist twice (a component in administrator/ and in the site
    # folder is two installations), so the identity of a row is its path, and
    # duplicate paths - only possible if the tree was walked twice - are dropped.
    seen = set()
    unique = []
    for comp in out:
        key = (comp["type"], comp["path"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(comp)
    return unique


# ---------------------------------------------------------------------------
# the inventory as a whole
# ---------------------------------------------------------------------------

def _component(cms, ctype, slug, name, version, source, path, note=""):
    """One component. `path` is site-relative with forward slashes, always."""
    return {"cms": cms, "type": ctype, "slug": _clean_text(slug, 100),
            "name": name or "", "version": clean_version(version),
            "version_source": source, "path": path.replace(os.sep, "/").lstrip("/"),
            "note": note}


def detect_cms(site_root):
    """WP / Joomla / None from the root markers, the same rule the scanner uses.

    Deliberately not a copy of the scanner's heuristic in spirit: a single planted
    file must not relabel the site, so WordPress needs a marker file AND both core
    folders, and contradictory evidence says "unknown" (which suppresses nothing).
    """
    try:
        entries = {e.lower() for e in os.listdir(site_root)}
    except OSError:
        return None
    wp = bool(entries & {"wp-config.php", "wp-load.php", "wp-settings.php"}) \
        and {"wp-includes", "wp-admin"} <= entries
    joomla = "configuration.php" in entries or "administrator" in entries
    if wp and joomla:
        return None
    if wp:
        return WP
    if joomla:
        return JOOMLA
    return None


def build_inventory(site_root):
    """The whole site as data: {"cms", "cms_version", "components", "problems"}.

    Never raises: a site that cannot be read yields an empty inventory plus a
    note, because an inventory that fails is a reason to keep scanning, not to
    stop - the heuristics and YARA still look at every file.
    """
    result = {"cms": "unknown", "cms_version": {"version": "", "source": "", "file": ""},
              "components": [], "problems": []}
    if not site_root or not os.path.isdir(site_root):
        result["problems"].append("site folder not readable")
        return result
    cms = detect_cms(site_root)
    if cms is None:
        result["problems"].append("CMS not identified (or ambiguous): no inventory")
        return result
    result["cms"] = cms
    if cms == WP:
        result["cms_version"] = wp_core_version(site_root)
        result["components"] = wp_components(site_root)
    else:
        result["cms_version"] = joomla_core_version(site_root)
        result["components"] = joomla_components(site_root)
    if not result["cms_version"]["version"]:
        result["problems"].append("CMS version unknown: audit of the core is impossible")
    return result


def summarize(inventory):
    """A small JSON-safe dict for the console, the report and the GUI."""
    counts = {}
    for comp in inventory.get("components") or []:
        counts[comp["type"]] = counts.get(comp["type"], 0) + 1
    return {"cms": inventory.get("cms", "unknown"),
            "cms_version": (inventory.get("cms_version") or {}).get("version", ""),
            "version_source": (inventory.get("cms_version") or {}).get("source", ""),
            "version_file": (inventory.get("cms_version") or {}).get("file", ""),
            "components": counts,
            "unknown_versions": sum(1 for c in inventory.get("components") or []
                                    if not c.get("version")),
            "problems": list(inventory.get("problems") or [])}
