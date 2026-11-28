# -*- coding: utf-8 -*-
"""Version strings: read them from a hostile file, compare them, decide ranges.

Used by the CMS inventory (engines/inventory.py), the WordPress integrity check
and the vulnerability audit (engines/vuln_engine.py). Standard library only,
compatible with Python 3.6.

Why this file exists at all: `packaging.version` is not in the standard library,
and a version string here is not a developer's PEP 440 string - it is whatever a
plugin header on a possibly compromised site says, or whatever a vulnerability
database claims about a release. Two consequences:

* the input is untrusted, so anything this module cannot understand it returns as
  `None` ("version unknown") instead of guessing; the caller must then report a
  low-confidence finding, never silently skip the component;
* the databases that describe CMS releases use PHP's `version_compare()`
  semantics, where `dev` < `alpha` < `beta` < `RC` < no suffix < `pl`, and where
  `1.2` and `1.2.0` are the same version. Comparing version strings as tuples of
  ints - or as strings - gets both of those wrong.

Everything here is pure: no files, no network, no state. That is what makes the
table-driven tests in tests/test_versions.py enough.
"""

import math
import re

# A version we understand: an optional "v", at least one dotted number, and at
# most ONE known pre-release suffix at the end ("6.4.2", "1.2.3.4", "2.0b1",
# "5.3-rc2", "4.5.0-dev", "6.5-alpha-57123"). The pattern is anchored at both
# ends on purpose: a half-matching suffix ("1.0-something-else") must come back
# as unknown, not as a version with a discarded tail.
# Each number is bounded too: nobody ships a "version" of 40 digits, and an
# unbounded run of digits is a way to make the tool compare integers of any size
# the site's file claims. 8 components x 6 digits is already beyond every CMS.
_VERSION_RE = re.compile(
    r"\Av?(\d{1,6}(?:\.\d{1,6}){0,7})(?:[\s._+-]?([A-Za-z]{1,10})[\s._+-]?(\d{0,6}))?\Z")

# Ordering of the suffixes inside one release, as PHP's version_compare() ranks
# them. 0 is "no suffix" (the final release). Unknown word -> not a version.
SUFFIX_RANK = {"dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2,
               "rc": -1, "pl": 1, "p": 1}

# What a version may be built of. A scanned file can put anything in a "Version:"
# header, and this string later travels into a URL and into a report, so the
# alphabet is closed rather than filtered by a denylist.
_ALLOWED_CHARS = re.compile(r"\A[A-Za-z0-9._+\- ]*\Z")

MAX_VERSION_LEN = 64          # a longer "version" is not a version, it is content
VERSION_FIELD_LEN = 32        # what a header/manifest value may reasonably be

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                  "none": 4, "unknown": 5}


def clean_version(value, limit=VERSION_FIELD_LEN):
    """A version as it was read from a scanned file, made safe to keep and print.

    Returns a stripped string of at most `limit` characters from a closed
    alphabet, or "" when the value is not a plausible version string at all.
    This is hygiene, not parsing: parse_version() still decides whether the
    result means anything. `limit` is never trusted below 8 characters, because
    a limit that small cannot hold a version and is a mistake, not a rule.
    """
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8", "replace")
        except Exception:
            return ""
    elif not isinstance(value, str):
        # A version that arrived as a number, a list or an object did not come out
        # of a text header the way this module's callers read them: not a version.
        return ""
    value = value.strip().strip("\"'")
    if not value or len(value) > max(8, min(limit, MAX_VERSION_LEN)):
        return ""
    if not _ALLOWED_CHARS.match(value):
        return ""
    return value


def parse_version(text):
    """A version string -> a comparable key, or None when we cannot read it.

    The key is (release_tuple, suffix_rank, suffix_number); compare_version() is
    the only function allowed to rely on its shape.
    """
    if isinstance(text, (bytes, bytearray)):
        try:
            text = text.decode("utf-8", "replace")
        except Exception:
            return None
    if not isinstance(text, str):
        return None
    text = text.strip()
    if not text or len(text) > MAX_VERSION_LEN:
        return None
    m = _VERSION_RE.match(text)
    if not m:
        return None
    words = m.group(2)
    rank = 0
    number = 0
    if words:
        rank = SUFFIX_RANK.get(words.lower())
        if rank is None:
            return None                      # an unknown scheme: not a guess
        number = int(m.group(3) or 0)
    release = tuple(int(x) for x in m.group(1).split("."))
    return (release, rank, number)


def compare_version(left, right):
    """-1 / 0 / 1, or None when either side is not a version we understand.

    `1.2` == `1.2.0` (shorter releases are padded with zeros, the way PHP reads
    them), and a pre-release sorts before the release it leads to.
    """
    a = parse_version(left)
    b = parse_version(right)
    if a is None or b is None:
        return None
    n = max(len(a[0]), len(b[0]))
    ra = a[0] + (0,) * (n - len(a[0]))
    rb = b[0] + (0,) * (n - len(b[0]))
    if ra != rb:
        return -1 if ra < rb else 1
    if (a[1], a[2]) != (b[1], b[2]):
        return -1 if (a[1], a[2]) < (b[1], b[2]) else 1
    return 0


# --- the six operators a vulnerability database expresses ranges with ---------
# WPVulnerability reports `lt`/`le`/`eq`/`ne`/`gt`/`ge` (PHP version_compare
# names). They are spelled out here so the reader of the mapping below never has
# to guess which side of the comparison is the version and which is the bound.
_OPERATORS = {
    "lt": lambda c: c < 0,
    "le": lambda c: c <= 0,
    "eq": lambda c: c == 0,
    "ne": lambda c: c != 0,
    "gt": lambda c: c > 0,
    "ge": lambda c: c >= 0,
}


def satisfies(version, operator, bound):
    """Does `version` stand in `operator` relation to `bound`? True/False/None.

    None means "cannot be decided": one of the two is not a version, or the
    operator is not one of the six. A caller must treat None as unknown, not as
    False - answering False here is what makes a vulnerability disappear.
    """
    cmp_ = compare_version(version, bound)
    if cmp_ is None:
        return None
    test = _OPERATORS.get((operator or "").strip().lower())
    if test is None:
        return None
    return bool(test(cmp_))


def affected_by_operator(version, operator):
    """Match one WPVulnerability `operator` block against a component version.

    The block carries a lower and an upper bound, each with its own operator;
    a missing lower bound means "all versions down to the first release", a
    missing upper bound means "no fix yet" (`unfixed`). Returns True/False/None
    (None = the version or a bound could not be read).
    """
    if not isinstance(operator, dict):
        return None
    low, low_op = operator.get("min_version"), operator.get("min_operator")
    high, high_op = operator.get("max_version"), operator.get("max_operator")
    if not low and not high:
        # No bounds at all: the database says the component is affected as such.
        return True
    unknown = False
    for bound, op in ((low, low_op), (high, high_op)):
        if not bound:
            continue
        verdict = satisfies(version, op or "le", bound)
        if verdict is None:
            unknown = True
        elif not verdict:
            return False
    return None if unknown else True


def is_affected(version, ranges):
    """OSV-style ranges for the local database: True / False / None.

    Each range is {"introduced": "5.0"|None, "fixed": "5.3"|None,
    "last_affected": "5.2.9"|None}: `introduced` is inclusive, `fixed` is
    exclusive (that version already contains the fix), `last_affected` is
    inclusive. Several ranges describe one CVE when a bug came back.
    """
    if parse_version(version) is None:
        return None
    if not ranges:
        return None
    malformed = False
    for rng in ranges:
        if not isinstance(rng, dict):
            malformed = True
            continue
        lo, hi, last = rng.get("introduced"), rng.get("fixed"), rng.get("last_affected")
        if not lo and not hi and not last:
            malformed = True                      # an empty range says nothing
            continue
        if lo and compare_version(version, lo) is None:
            malformed = True
            continue
        if lo and compare_version(version, lo) < 0:
            continue
        if hi:
            cmp_ = compare_version(version, hi)
            if cmp_ is None:
                malformed = True
                continue
            if cmp_ >= 0:
                continue
        if last:
            cmp_ = compare_version(version, last)
            if cmp_ is None:
                malformed = True
                continue
            if cmp_ > 0:
                continue
        return True
    return None if malformed else False


# --- severity -----------------------------------------------------------------

def cvss_severity(score, vector=None):
    """A CVSS base score -> the word the report and the GUI sort on.

    The bands are the standard CVSS v3 ones. A missing score is "unknown": a
    vulnerability database that has no score for an entry does not make the entry
    unimportant, it makes it unrankable, and `kev` then decides the order.
    """
    if score is None or score == "":
        return "unknown"
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if math.isnan(value):                   # NaN never compares usefully
        return "unknown"
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0.0:
        return "low"
    return "none"


def best_cvss(impact):
    """The score to rank one WPVulnerability `impact` block by, or None.

    Prefers the newest complete CVSS block the service provided and falls back;
    `impact` is an empty list when the service has no scoring data at all.
    """
    if not isinstance(impact, dict):
        return None
    for key in ("cvss4", "cvss3", "cvss2", "cvss"):
        block = impact.get(key)
        if isinstance(block, dict) and block.get("score") not in (None, ""):
            try:
                return float(block["score"])
            except (TypeError, ValueError):
                continue
    return None


def severity_sort_key(severity, kev=False, score=None):
    """Sort key: KEV first, then severity, then the score - highest first."""
    try:
        numeric = -float(score)
    except (TypeError, ValueError):
        numeric = 0.0
    return (0 if kev else 1, SEVERITY_ORDER.get(severity, 5), numeric)
