# -*- coding: utf-8 -*-
"""The engine interface every detection source implements (TZ v2, section 6).

An engine takes one already-read file (ScanCtx) and returns hits in the exact
tuple format the scanner uses internally:

    (severity, line, label, snippet, weight)

The interface is deliberately small and uses plain classes only: the scanner
has to keep working on Python 3.6, where dataclasses/typing niceties are not
an option.

The severity tokens and default weights are repeated here from
src/scan_backdoors.py on purpose: importing them from the scanner would make
the scanner import its own subpackage's parent module (a cycle). The
duplication is pinned by a synchronization test (tests/test_yara_engine.py),
so the two copies can never drift apart silently.
"""

SEV_CRIT = "[CRITICAL]"
SEV_OBF = "[OBFUSCATED]"
SEV_WARN = "[WARNING]"
DEFAULT_WEIGHT = {SEV_CRIT: 10, SEV_OBF: 3, SEV_WARN: 1}


class ScanCtx(object):
    """One file as the engines see it: already located, already read as bytes.

    path  absolute path on disk (the engine may re-open the file if it wants)
    rel   site-relative path with forward slashes
    name  base file name
    kind  the scanner's classification: php | js | html | htaccess | ini | text | media | ...
    raw   the full file content as bytes
    size  st_size in bytes (equals len(raw) for every file the scanner reads)
    """

    __slots__ = ("path", "rel", "name", "kind", "raw", "size")

    def __init__(self, path, rel, name, kind, raw, size):
        self.path = path
        self.rel = rel
        self.name = name
        self.kind = kind
        self.raw = raw
        self.size = size


class BaseEngine(object):
    """Detection source: name + version + rules, and a scan() of one file.

    scan() returns (hits, gap_reasons):
      hits         list of (severity, line, label, snippet, weight) tuples,
                   possibly empty;
      gap_reasons  non-empty when the engine could NOT fully check the file.
                   A gap must become a visible finding or a STATISTICS line -
                   an engine that fails silently returning [] is forbidden.
    """

    name = "engine"
    version = ""
    rules_count = 0
    files_loaded = 0

    def scan(self, ctx):
        raise NotImplementedError

    def describe(self):
        """A small JSON-safe dict for reports and the GUI."""
        return {"name": self.name, "version": self.version, "rules": self.rules_count}
