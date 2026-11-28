# -*- coding: utf-8 -*-
"""Which known vulnerabilities the inventoried components have (TZ v2, 8.4).

Two sources, one result type:

* a local database (`vulnerabilities.json` in the data folder, schema 2) - the
  only source in an offline run, and the one that keeps Joomla extensions covered
  at all (there is no free machine-readable feed for them [ПРОВЕРИТЬ:
  vel.joomla.org]);
* the WPVulnerability service through engines/cms_api.py, one request per
  component slug, only when the user asked for it with ``--online``. That request
  tells a third party which CMS, plugins and themes this site runs: the caller
  must say so before doing it, which is why it is never the default.

The result is NOT a ``Finding`` of the scanner: a CVE has no file and no line, and
pretending otherwise would put a version number into a table of malicious files
and make the quarantine buttons offer to delete a plugin because it is outdated.
So a vulnerability is its own record (see `VULN_FIELDS`), it is reported in its
own section, and no action in the GUI is offered for it.

The one judgement this module makes is `confidence`:

* "high"   - the component's version was read and a range of the database covers
             it (or the service answered about exactly that version);
* "medium" - the version is known but the entry is open-ended (no fix published),
             or the site's own version file does not match the official release;
* "low"    - the version could not be read at all. Then this module reports ONE
             record for the component ("N vulnerabilities are known, the version
             is unknown"), not N records: an unauditable component is a question
             for the owner, and flooding the report with every CVE ever filed
             against a slug would hide the findings that matter.
"""

import io
import json
import os
import re
import time

from engines import cms_api
from engines.versions import (cvss_severity, best_cvss, compare_version, is_affected,
                              affected_by_operator, severity_sort_key, parse_version)

DB_MAX_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 200000
CVE_RE = re.compile(r"\A(CVE-\d{4}-\d{4,19}|[A-Za-z0-9][A-Za-z0-9._-]{1,63})\Z")
COMPONENT_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._+-]{0,99}\Z")
KINDS = ("core", "plugin", "theme", "mu-plugin", "component", "module", "template")

# The record type. `path` is site-relative (where the component lives), never a
# line number: an outdated plugin is not a file to quarantine.
VULN_FIELDS = ("cve", "cms", "type", "component", "component_version", "version_source",
               "severity", "cvss", "cvss_vector", "kev", "fixed_in", "confidence",
               "source", "summary", "path")

_STALE_DAYS = 90


# ---------------------------------------------------------------------------
# the local database
# ---------------------------------------------------------------------------

def db_template():
    """What an empty local database looks like (written as a starting point)."""
    return {"schema": 2, "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "_readme": "Vulnerabilities of CMS components, matched locally against the "
                       "inventory. Entries are data a human reviewed: 'cms' is wordpress "
                       "or joomla, 'type' is core|plugin|theme|mu-plugin|component|module|"
                       "template, 'component' is the slug or directory name, 'affected' is "
                       "a list of {introduced, fixed, last_affected} ranges (introduced is "
                       "inclusive, fixed is the first version that is no longer affected). "
                       "Nothing is fetched automatically: an entry here is a claim.",
            "entries": []}


def load_database(path):
    """Read a local database -> (entries, problems). Never raises.

    The file is data someone else maintained, so every entry is shape-checked on
    the way in: a half-wrong entry is reported and dropped, because a database
    that silently matches nothing looks exactly like a site that is safe.
    """
    if not path:
        return [], ["no local database configured"]
    try:
        if os.path.getsize(path) > DB_MAX_BYTES:
            return [], ["the local database is larger than %d bytes: refused" % DB_MAX_BYTES]
        with io.open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        return [], ["cannot read the local database: %s" % type(exc).__name__]
    except ValueError:
        return [], ["the local database is not JSON"]
    if not isinstance(doc, dict) or doc.get("schema") != 2:
        return [], ["the local database is not schema 2 (found %r)"
                    % (doc.get("schema") if isinstance(doc, dict) else "not an object",)]
    raw = doc.get("entries")
    if not isinstance(raw, list):
        return [], ["the local database has no list of entries"]
    problems = []
    generated = doc.get("generated") or ""
    if generated:
        try:
            when = time.mktime(time.strptime(generated[:19], "%Y-%m-%dT%H:%M:%S"))
            age_days = int((time.time() - when) / 86400)
            if age_days > _STALE_DAYS:
                problems.append("the local database is %d days old" % age_days)
        except (ValueError, OverflowError):
            problems.append("the local database does not say when it was generated")
    else:
        problems.append("the local database does not say when it was generated")
    entries = []
    for i, item in enumerate(raw[:MAX_ENTRIES + 1]):
        if len(entries) > MAX_ENTRIES:
            problems.append("more than %d entries: the rest was ignored" % MAX_ENTRIES)
            break
        clean = _clean_entry(item)
        if clean is None:
            problems.append("entry %d is not usable: %r" % (i, _brief(item)))
            continue
        entries.append(clean)
    return entries, problems


def _brief(item):
    text = repr(item)
    return text[:80] + ("..." if len(text) > 80 else "")


def _clean_entry(item):
    """One database entry, or None when it cannot be trusted."""
    if not isinstance(item, dict):
        return None
    cve = item.get("cve")
    cms = item.get("cms")
    ctype = item.get("type")
    component = item.get("component")
    if not isinstance(cve, str) or not CVE_RE.match(cve):
        return None
    if cms not in ("wordpress", "joomla") or ctype not in KINDS:
        return None
    if not isinstance(component, str) or not COMPONENT_RE.match(component):
        return None
    ranges = item.get("affected")
    if not isinstance(ranges, list) or not ranges:
        return None
    clean_ranges = []
    for rng in ranges[:20]:
        if not isinstance(rng, dict):
            return None
        clean = {}
        for key in ("introduced", "fixed", "last_affected"):
            value = rng.get(key)
            if value in (None, ""):
                continue
            if not isinstance(value, str) or parse_version(value) is None:
                return None                  # an unreadable bound makes the range a lie
            clean[key] = value
        if not clean:
            return None
        clean_ranges.append(clean)
    cvss = item.get("cvss")
    if cvss not in (None, ""):
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            return None
        if not 0.0 <= cvss <= 10.0:
            return None
    return {"cve": cve, "cms": cms, "type": ctype, "component": component,
            "affected": clean_ranges, "cvss": cvss,
            "cvss_vector": item.get("cvss_vector") if isinstance(item.get("cvss_vector"), str) else "",
            "kev": bool(item.get("kev")), "source": _text(item.get("source") or "local"),
            "summary": _text(item.get("summary") or "", 300)}


def _text(value, limit=120):
    if not isinstance(value, str):
        return ""
    keep = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in value)
    return " ".join(keep.split())[:limit]


def index_of(entries):
    """{(cms, type, component): [entry]} - the join key of the whole audit."""
    out = {}
    for entry in entries:
        out.setdefault((entry["cms"], entry["type"], entry["component"].lower()), []).append(entry)
    return out


# ---------------------------------------------------------------------------
# matching one component
# ---------------------------------------------------------------------------

def _vuln(finding):
    """Fill the record with what the report needs even when nothing matched."""
    record = dict(finding)
    for field in VULN_FIELDS:
        record.setdefault(field, None)
    record["cve"] = record.get("cve") or ""
    record["summary"] = _text(record.get("summary") or "", 300)
    return record


def audit_local(component, entries, version_trusted=True):
    """Match one inventoried component against already-indexed local entries."""
    cms = component.get("cms")
    ctype = component.get("type")
    slug = (component.get("slug") or "").lower()
    matches = entries.get((cms, ctype, slug)) or []
    if not matches:
        return []
    version = component.get("version") or ""
    if not version or parse_version(version) is None:
        return [_unknown_version(component, matches, "local")]
    out = []
    for entry in matches:
        verdict = is_affected(version, entry["affected"])
        if verdict is not True:
            if verdict is None:
                out.append(_undecidable(component, entry))
            continue
        open_ended = any("fixed" not in r and "last_affected" not in r
                         for r in entry["affected"])
        confidence = "medium" if (open_ended or not version_trusted) else "high"
        out.append(_vuln({
            "cve": entry["cve"], "cms": cms, "type": ctype, "component": component.get("slug"),
            "component_version": version, "version_source": component.get("version_source"),
            "cvss": entry.get("cvss"), "cvss_vector": entry.get("cvss_vector") or "",
            "severity": cvss_severity(entry.get("cvss")), "kev": bool(entry.get("kev")),
            "fixed_in": _fixed_in(entry["affected"]), "confidence": confidence,
            "source": entry.get("source") or "local", "summary": entry.get("summary") or "",
            "path": component.get("path") or "",
        }))
    return out


def _fixed_in(ranges):
    """The first version that is no longer affected, when the ranges say so."""
    best = None
    for rng in ranges:
        fixed = rng.get("fixed") or rng.get("last_affected")
        if not fixed:
            return None                      # one open range: there is no fix yet
        if best is None or (compare_version(fixed, best) or 0) < 0:
            best = fixed
    return best


def _unknown_version(component, matches, source):
    """One honest record for a component whose version cannot be read."""
    worst = None
    kev = False
    for entry in matches:
        score = entry.get("cvss") if isinstance(entry, dict) else None
        if isinstance(entry, dict) and entry.get("kev"):
            kev = True
        item = worst
        if score is not None and (worst is None or (score or 0) > (worst.get("cvss") or 0)):
            worst = entry
    cve = (worst or {}).get("cve") or (matches[0].get("cve") if isinstance(matches[0], dict) else "")
    cvss = (worst or {}).get("cvss")
    return _vuln({
        "cve": cve, "cms": component.get("cms"), "type": component.get("type"),
        "component": component.get("slug"), "component_version": component.get("version") or "",
        "version_source": component.get("version_source") or "unknown",
        "cvss": cvss, "severity": cvss_severity(cvss), "kev": kev, "fixed_in": None,
        "confidence": "low", "source": source,
        "summary": "the version of this component could not be read: %d vulnerability record(s) "
                   "exist for it and none could be decided - update it or identify it manually"
                   % len(matches),
        "path": component.get("path") or "",
    })


def _undecidable(component, entry):
    return _vuln({
        "cve": entry.get("cve"), "cms": component.get("cms"), "type": component.get("type"),
        "component": component.get("slug"), "component_version": component.get("version") or "",
        "version_source": component.get("version_source"), "cvss": entry.get("cvss"),
        "severity": cvss_severity(entry.get("cvss")), "kev": bool(entry.get("kev")),
        "fixed_in": _fixed_in(entry.get("affected") or []), "confidence": "low",
        "source": entry.get("source") or "local",
        "summary": "the version range of the entry could not be compared with the version "
                   "of the component: it is neither affected nor clean",
        "path": component.get("path") or "",
    })


# ---------------------------------------------------------------------------
# the online audit (WordPress only: nothing equivalent exists for Joomla)
# ---------------------------------------------------------------------------

def _cve_of(sources):
    """The identifier to print for one service entry: a CVE when it has one."""
    ids = []
    for src in sources or []:
        if isinstance(src, dict) and isinstance(src.get("id"), str):
            ids.append(src["id"])
    for one in ids:
        if one.upper().startswith("CVE-"):
            return one
    return ids[0] if ids else ""


def _summary_of(sources):
    for src in sources or []:
        if isinstance(src, dict) and isinstance(src.get("description"), str):
            return _text(src["description"], 300)
    return ""


def _kev_of(impact):
    if not isinstance(impact, dict):
        return False
    ssvc = impact.get("ssvc")
    return bool(isinstance(ssvc, dict) and ssvc.get("kev"))


def audit_online_component(component, entries, client, version_trusted=True):
    """Ask WPVulnerability about one component and decide for ourselves.

    For a plugin/theme the service returns every vulnerability of the slug with a
    version range, and the comparison is ours (`affected_by_operator`). For the
    core the service returns what applies to the version asked about - so the
    version that was asked about must be the one on the site, which is why a core
    whose version file does not match the official release is reported as low
    confidence instead of as a verdict.
    """
    ctype = component.get("type")
    kind = {"core": "core", "plugin": "plugin", "theme": "theme",
            "mu-plugin": "plugin"}.get(ctype)
    if kind is None or component.get("cms") != "wordpress":
        return []
    slug = component.get("slug") or ""
    version = component.get("version") or ""
    if kind == "core":
        if not cms_api.valid_wp_version(version):
            return [_no_version(component, "core")]
        identifier = version
    else:
        if not cms_api.valid_slug(slug):
            return []                        # not a catalogue slug: nothing to ask
        identifier = slug
    payload = client.get_json(cms_api.wpvuln_url(kind, identifier), "%s %s" % (kind, slug or version))
    entries_seen = cms_api.parse_wpvuln(payload)
    out = []
    for entry in entries_seen:
        operator = entry.get("operator")
        if kind == "core":
            affected = True                  # the service answered about this version
        else:
            affected = affected_by_operator(version, operator)
        if affected is None:
            out.append(_vuln({
                "cve": _cve_of(entry.get("source")), "cms": "wordpress", "type": ctype,
                "component": slug or "core", "component_version": version,
                "version_source": component.get("version_source"),
                "cvss": best_cvss(entry.get("impact")),
                "severity": cvss_severity(best_cvss(entry.get("impact"))),
                "kev": _kev_of(entry.get("impact")), "fixed_in": None,
                "confidence": "low", "source": "wpvulnerability",
                "summary": "the version range in the service answer could not be compared "
                           "with the version of the component",
                "path": component.get("path") or "",
            }))
            continue
        if not affected:
            continue
        score = best_cvss(entry.get("impact"))
        fixed = _operator_fixed(operator)
        out.append(_vuln({
            "cve": _cve_of(entry.get("source")), "cms": "wordpress", "type": ctype,
            "component": slug or "core", "component_version": version,
            "version_source": component.get("version_source"),
            "cvss": score, "cvss_vector": _vector_of(entry.get("impact")),
            "severity": cvss_severity(score), "kev": _kev_of(entry.get("impact")),
            "fixed_in": fixed,
            "confidence": "high" if (version_trusted and fixed) else "medium",
            "source": "wpvulnerability", "summary": _summary_of(entry.get("source")),
            "path": component.get("path") or "",
        }))
    return out


def _vector_of(impact):
    if not isinstance(impact, dict):
        return ""
    for key in ("cvss4", "cvss3", "cvss2", "cvss"):
        block = impact.get(key)
        if isinstance(block, dict) and isinstance(block.get("vector"), str):
            return block["vector"][:120]
    return ""


def _operator_fixed(operator):
    """`max_operator: lt` means that version already fixed it; `le` means it is
    the last affected one, so there is no known fix yet."""
    if not isinstance(operator, dict):
        return None
    if operator.get("max_operator") == "lt" and operator.get("max_version"):
        return str(operator["max_version"])[:32]
    return None


def _no_version(component, kind):
    return _vuln({
        "cve": "", "cms": component.get("cms"), "type": component.get("type"),
        "component": component.get("slug") or kind,
        "component_version": component.get("version") or "",
        "version_source": component.get("version_source") or "unknown",
        "cvss": None, "severity": "unknown", "kev": False, "fixed_in": None,
        "confidence": "low", "source": "wpvulnerability",
        "summary": "the %s version could not be read, so no audit was possible" % kind,
        "path": component.get("path") or "",
    })


# ---------------------------------------------------------------------------
# the audit as a whole
# ---------------------------------------------------------------------------

def version_is_trusted(inventory, integrity=None):
    """Is the CMS version this inventory claims worth believing?

    A version read from `wp-includes/version.php` is a claim by a file on a
    possibly compromised site. When the integrity check says that very file does
    not match the official release, every CVE verdict built on that version is a
    guess, and has to be labelled as one.
    """
    if not integrity:
        return True
    version_file = (inventory.get("cms_version") or {}).get("file") or ""
    if not version_file:
        return True
    bad = {row["path"] for row in (integrity.get("modified") or [])}
    bad |= {row["path"] for row in (integrity.get("extra") or [])}
    bad |= set(integrity.get("missing") or [])
    return version_file.replace(os.sep, "/") not in bad


def audit(inventory, entries=(), client=None, integrity=None):
    """The whole inventory -> a sorted list of vulnerability records + notes."""
    index = index_of(entries)
    trusted = version_is_trusted(inventory, integrity)
    findings = []
    notes = []
    not_asked = 0
    components = list(inventory.get("components") or [])
    cms_version = inventory.get("cms_version") or {}
    if inventory.get("cms") == "wordpress" and (cms_version.get("version") or client):
        components = [{"cms": "wordpress", "type": "core", "slug": "core",
                       "name": "WordPress", "version": cms_version.get("version", ""),
                       "version_source": cms_version.get("source", ""),
                       "path": "wp-includes/"}] + components
    if not trusted:
        notes.append("the CMS version file does not match the official release: "
                     "every version-based verdict below is a guess")
    for component in components:
        # the local verdicts go in whatever happens next: a component whose online
        # lookup fails must still be reported from the local database
        findings.extend(audit_local(component, index, trusted))
        if client is None:
            continue
        try:
            findings.extend(audit_online_component(component, entries, client, trusted))
        except cms_api.OfflineMode:
            not_asked += 1
            continue
        except cms_api.AuditError as exc:
            notes.append("%s %s: %s" % (component.get("type"), component.get("slug"), exc))
            continue
    if not_asked:
        notes.append("the online service was not asked (--online): %d component(s) were judged "
                     "from the local database and the cache only" % not_asked)
    findings.sort(key=lambda f: severity_sort_key(f.get("severity"), f.get("kev"),
                                                  f.get("cvss")))
    return findings, notes


def max_severity(findings):
    """The highest severity among actionable (not low-confidence) verdicts."""
    order = ["critical", "high", "medium", "low"]
    best = None
    for row in findings:
        if row.get("confidence") == "low":
            continue
        sev = row.get("severity")
        if sev in order and (best is None or order.index(sev) < order.index(best)):
            best = sev
    return best


def meets_threshold(findings, level):
    """Did any verdict reach --fail-on LEVEL?"""
    if not level:
        return False
    order = ["critical", "high", "medium", "low"]
    if level not in order:
        return False
    worst = max_severity(findings)
    return worst is not None and order.index(worst) <= order.index(level)


def summarize(findings, notes=()):
    """A small JSON-safe dict for the console, the report and the GUI."""
    counts = {}
    for row in findings:
        counts[row.get("severity") or "unknown"] = counts.get(row.get("severity") or "unknown", 0) + 1
    return {"total": len(findings),
            "kev": sum(1 for row in findings if row.get("kev")),
            "low_confidence": sum(1 for row in findings if row.get("confidence") == "low"),
            "by_severity": counts,
            "notes": list(notes)}
