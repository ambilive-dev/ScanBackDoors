# -*- coding: utf-8 -*-
"""Optional YARA rules engine (TZ v2, section 6).

The scanner runs WITHOUT this engine (and without yara-python installed)
exactly as before; --yara-rules adds it as one more detection source.

Facts verified against yara-python 4.5.4 (recorded in docs/OPEN_QUESTIONS.md):
  * externals are anchored at COMPILE time only by their TYPE: the values are
    re-bound per file through match(externals=...), and that keeps working
    after save()/load() of a compiled .yarac. The engine therefore compiles
    every rule set with the placeholder externals below and substitutes real
    per-file values at scan time;
  * 'include' is resolved silently relative to the rule file -> a hostile rule
    file could pull in arbitrary files. Includes are refused twice over: a
    text pre-scan for a clear message, and an include_callback that raises;
  * match() does NOT raise on timeout: it silently returns an incomplete
    result. A wall-clock guard turns every scan that ran close to the limit
    into a visible scan gap - a silent [] is forbidden by the TZ;
  * a rule file that fails to compile is skipped with a reported reason; the
    remaining files still load (per-file isolation).
"""

import hashlib
import os
import re
import time

from .base_engine import BaseEngine, SEV_CRIT, SEV_OBF, SEV_WARN, DEFAULT_WEIGHT

MAX_RULE_FILES = 256
MAX_RULE_FILE_SIZE = 8 * 1024 * 1024
YARA_EXTS = (".yar", ".yara")              # rule file extensions the scanner and the checker accept

# The rule may reference these; the scanner supplies values for every file.
# extension is dotted and lower-case (extension == ".php"), path and folder
# are site-relative with forward slashes, cms is "wordpress" | "joomla" | "",
# wp_root / joomla_root are booleans, rule_language is the scanner's kind
# (php | js | html | htaccess | ini | text | media | ""), file_size is bytes.
PLACEHOLDER_EXTERNS = {
    "file_name": "", "extension": "", "path": "", "folder": "", "file_size": 0,
    "cms": "", "wp_root": False, "joomla_root": False, "rule_language": "",
}

# rule meta severity -> scanner severity; unknown or missing meta is a WARNING,
# so an unaudited third-party rule can never raise the verdict on its own
_META_SEVERITY = {
    "critical": SEV_CRIT, "high": SEV_CRIT, "error": SEV_CRIT,
    "medium": SEV_OBF, "obfuscated": SEV_OBF, "suspicious": SEV_OBF,
    "warning": SEV_WARN, "low": SEV_WARN, "info": SEV_WARN, "informational": SEV_WARN,
}

INCLUDE_RE = re.compile(rb"(?m)^[ \t]*include[ \t]+[\"']")
_NS_BAD = re.compile(r"[^A-Za-z0-9_]")
_CTRL_RE = re.compile(u"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")


def _import_yara():
    try:
        import yara
    except ImportError:
        return None
    return yara


def _forbid_include(identifier, namespace, filename):
    # called by yara while resolving an 'include': anything but returning text
    # aborts the include - raising makes the whole rule file fail to compile
    raise ValueError("include is disabled: rules are compiled flat, "
                     "every .yar file must stand on its own")


def collect_rule_files(source):
    """--yara-rules value -> a deterministic list of rule file paths.

    A directory contributes its *.yar / *.yara files (non-recursive, sorted);
    a single file path is used as is. Anything else is a startup error.
    """
    if os.path.isdir(source):
        out = [os.path.join(source, n) for n in sorted(os.listdir(source))
               if n.lower().endswith(YARA_EXTS)]
        if not out:
            raise ValueError("no .yar/.yara rule files in folder: %s" % source)
    elif os.path.isfile(source):
        out = [source]
    else:
        raise ValueError("no YARA rules found at: %s" % source)
    if len(out) > MAX_RULE_FILES:
        raise ValueError("too many YARA rule files: %d (max %d)" % (len(out), MAX_RULE_FILES))
    return out


class YaraEngine(BaseEngine):
    name = "yara"

    def __init__(self, yara_mod, rules, rules_count, base_externals, timeout):
        self._y = yara_mod
        self._rules = rules
        self._timeout_exc = getattr(yara_mod, "TimeoutError", None)
        self._base = dict(base_externals or {})
        self.rules_count = rules_count
        self.timeout = float(timeout)
        # yara-python only accepts whole seconds for its internal limit; the
        # wall-clock guard below still uses the exact (possibly fractional) value
        self._yara_timeout = max(1, int(round(self.timeout)))
        # yara's internal timeout may already have cut the scan short when it
        # finishes this close to the limit: treat that as a gap, not as clean
        self._wall_limit = self.timeout - min(0.25, self.timeout * 0.1)
        self.version = str(getattr(yara_mod, "__version__", "?"))

    def scan(self, ctx):
        ext = dict(self._base)
        ext["file_name"] = ctx.name
        ext["extension"] = os.path.splitext(ctx.name)[1].lower()
        ext["path"] = ctx.rel
        ext["folder"] = ctx.rel.rsplit("/", 1)[0] if "/" in ctx.rel else ""
        ext["file_size"] = ctx.size
        ext["rule_language"] = ctx.kind or ""
        t0 = time.time()
        try:
            matches = self._rules.match(data=ctx.raw, externals=ext, timeout=self._yara_timeout)
        except Exception as exc:                    # never let one rule break the file's scan
            if self._timeout_exc is not None and isinstance(exc, self._timeout_exc):
                return [], ["the YARA scan exceeded its %gs timeout" % self.timeout]
            return [], ["the YARA scan failed: %s: %s" % (type(exc).__name__, str(exc)[:160])]
        hits = [self._hit(m, ctx) for m in matches]
        if time.time() - t0 >= self._wall_limit:
            return hits, ["the YARA scan ran up to its %gs timeout: the matches may be incomplete"
                          % self.timeout]
        return hits, []

    def _hit(self, m, ctx):
        meta = m.meta or {}
        sev = _META_SEVERITY.get(str(meta.get("severity", "")).strip().lower(), SEV_WARN)
        try:
            weight = int(meta.get("score"))
            weight = max(1, min(50, weight))
        except (TypeError, ValueError):
            weight = DEFAULT_WEIGHT[sev]
        ns = "%s." % m.namespace if m.namespace and m.namespace != "default" else ""
        label = "YARA: %s%s" % (ns, m.rule)
        line, snip = 0, ""
        if m.strings:
            try:
                inst = m.strings[0].instances[0]
                line = ctx.raw.count(b"\n", 0, inst.offset) + 1
                snip = _CTRL_RE.sub(".", inst.matched_data[:140].decode("utf-8", "replace"))
                snip = snip.replace("\n", " ").replace("\r", " ")
            except (AttributeError, IndexError, TypeError):
                pass
        return (sev, line, label, snip, weight)


def build_yara_engine(sources, cache_dir="", base_externals=None, timeout=5.0):
    """Compile the rule files into one YaraEngine.

    Returns (engine or None, problems): problems are human-readable lines the
    caller prints - broken rule files are isolated (skipped with a reason),
    never silently dropped, and the engine works without yara-python installed
    by reporting itself unavailable. When cache_dir is usable the FULLY
    compiled set is saved as a .yarac keyed by the rule content, and the next
    process (including each worker process) loads it instead of recompiling.
    """
    y = _import_yara()
    if y is None:
        return None, ["yara-python is not installed - the YARA engine is OFF "
                      "(pip install yara-python, see requirements-optional.txt)"]

    problems = []
    read = []                                    # (namespace, path, content)
    taken_ns = set()
    for path in sources:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            problems.append("%s: cannot be read: %s - the file is skipped" % (path, exc))
            continue
        if len(data) > MAX_RULE_FILE_SIZE:
            problems.append("%s: %d bytes exceeds the %d MB rule-file limit - the file is skipped"
                            % (path, len(data), MAX_RULE_FILE_SIZE // (1024 * 1024)))
            continue
        if INCLUDE_RE.search(data):
            problems.append("%s: 'include' directives are refused (every rule file must stand "
                            "on its own) - the file is skipped" % path)
            continue
        stem = os.path.splitext(os.path.basename(path))[0].strip() or "rulefile"
        ns, i = _NS_BAD.sub("_", stem), 2
        while ns in taken_ns:
            ns = "%s_%d" % (_NS_BAD.sub("_", stem), i)
            i += 1
        taken_ns.add(ns)
        read.append((ns, path, data))

    rules = None
    cache_path = None
    if read and cache_dir:
        digest = hashlib.sha256()
        digest.update(("yara-python|%s|%d\x00" % (getattr(y, "__version__", "?"),
                                                  MAX_RULE_FILE_SIZE)).encode("utf-8"))
        for ns, _p, data in read:
            digest.update(ns.encode("utf-8", "replace") + b"\x00" + data + b"\x00")
        cache_path = os.path.join(cache_dir, digest.hexdigest() + ".yarac")
        try:
            rules = y.load(cache_path)
        except Exception:
            rules = None                         # missing, unreadable or corrupt: recompile

    loaded = []
    if rules is None:
        # per-file isolation: add one file at a time, keep what compiles
        for ns, path, data in read:
            candidate = dict(loaded)
            candidate[ns] = path
            try:
                rules = y.compile(filepaths=candidate, externals=PLACEHOLDER_EXTERNS,
                                  include_callback=_forbid_include)
            except Exception as exc:
                reason = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
                problems.append("%s: %s - the file is skipped" % (path, reason))
                continue
            loaded.append((ns, path))
        if not loaded:
            if read:
                problems.append("no YARA rule file could be compiled - the engine stays OFF")
            return None, problems
        # the cache may only ever contain a COMPLETE set for its key (which
        # hashes every given file): caching a set that silently lost a broken
        # file would hide that file's problem from the next run
        if cache_path and not problems:
            try:
                if not os.path.isdir(cache_dir):
                    os.makedirs(cache_dir)
                rules.save(cache_path)
            except OSError:
                pass                             # the cache is an optimization, not a contract

    engine = YaraEngine(y, rules, len(list(rules)), base_externals, timeout)
    engine.files_loaded = len(loaded) if loaded else len(read)
    return engine, problems
