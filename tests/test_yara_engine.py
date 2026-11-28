# -*- coding: utf-8 -*-
"""TZ v2 Sprint 1: the optional YARA engine behind the BaseEngine interface.

Two layers of checks:
  * CLI level through the harness (a real subprocess, like a user): default
    runs stay silent about YARA, --no-yara, --yara-rules with a missing path
    is a startup error, a missing yara-python degrades gracefully, broken
    rule files are reported and skipped while good ones keep working;
  * unit level through direct imports: the engine contract, per-file
    externals, gap bookkeeping (never a silent []) and the constant
    synchronization between engines/base_engine.py and the scanner.

The detection golden master (tests/test_golden_scan.py) additionally pins
that a default run - without any YARA flag - reports exactly what it
reported before the engine existed.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

sys.path.insert(0, h.REPO)
sys.path.insert(0, h.SRC)

from engines import base_engine as be              # noqa: E402
from engines import yara_engine as ye              # noqa: E402
import scan_backdoors as sb                        # noqa: E402  (unit seams only)

try:
    import yara as _yara                            # noqa: F401
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

MARKER = b"SBD_YARA_PROBE_MARKER_9182736455"
GOOD_RULE = ('rule SbProbeMarker {\n'
             '    strings:\n'
             '        $a = "%s" ascii wide\n'
             '    condition:\n'
             '        $a\n'
             '}\n' % MARKER.decode())
BAD_RULE = "rule Broken {\n    condition: this is not yara at all\n}\n"


def write_site(files):
    """{relative/path: bytes} -> a throw-away site folder."""
    site = h.workdir("yq-site-")
    for rel, content in files.items():
        p = os.path.join(site, *rel.split("/"))
        d = os.path.dirname(p)
        if not os.path.isdir(d):
            os.makedirs(d)
        with open(p, "wb") as fh:
            fh.write(content)
    return site


def write_rules(files):
    """{name.yar: text} -> a throw-away rules folder."""
    d = h.workdir("yq-rules-")
    for name, text in files.items():
        with open(os.path.join(d, name), "wb") as fh:
            fh.write(text.encode("utf-8"))
    return d


# ---------------------------------------------------------------------------
# the contract: one source of truth for the tokens shared with the scanner
# ---------------------------------------------------------------------------

class EngineContract(unittest.TestCase):

    def test_severity_tokens_match_the_scanner(self):
        self.assertEqual(be.SEV_CRIT, sb.SEV_CRIT)
        self.assertEqual(be.SEV_OBF, sb.SEV_OBF)
        self.assertEqual(be.SEV_WARN, sb.SEV_WARN)
        self.assertEqual(be.DEFAULT_WEIGHT, sb.DEFAULT_WEIGHT)


# ---------------------------------------------------------------------------
# unit level: the seam between scan_file/scan_batch and the engines
# ---------------------------------------------------------------------------

class _StubEngine(object):
    name = "stub"
    version = "0"
    rules_count = 1

    def __init__(self, hits=(), gaps=(), only_for=None):
        self.hits = list(hits)
        self.gaps = list(gaps)
        self.only_for = only_for      # when set: hits/gaps apply to this file name only

    def scan(self, ctx):
        if self.only_for is not None and ctx.name != self.only_for:
            return [], []
        return list(self.hits), list(self.gaps)


def _cfg(site):
    return {"start": site, "max_size": 5 * 1024 * 1024, "max_matches": 60, "since": None,
            "enabled": {sb.SEV_CRIT, sb.SEV_OBF, sb.SEV_WARN}, "wl_hashes": set(), "wl_paths": [],
            "baseline": None, "baseline_dirs": set(), "skip_paths": set(), "baseline_pkgs": set(),
            "posix": os.name != "nt", "exclude_ext": set(), "cms": None, "audit_wl": False,
            "yara": None}


class EngineWiring(unittest.TestCase):

    def setUp(self):
        self.site = write_site({"probe.txt": b"x " + MARKER + b" y\n",
                                "clean.txt": b"nothing to see here\n"})
        self.probe = os.path.join(self.site, "probe.txt")
        self.clean = os.path.join(self.site, "clean.txt")
        self._real_get_engines = sb.get_engines
        self.addCleanup(self._restore)

    def _restore(self):
        sb.get_engines = self._real_get_engines

    def _use(self, engines):
        sb.get_engines = lambda cfg: list(engines)

    def test_engine_hits_reach_the_result(self):
        self._use([_StubEngine(hits=[(sb.SEV_CRIT, 1, "STUB: planted hit", "x", 7)])])
        sb._init(_cfg(self.site))
        res, status = sb.scan_file(self.probe)
        self.assertEqual(status, "scanned")
        self.assertIn("STUB: planted hit", [hh[2] for hh in res["hits"]])
        self.assertEqual(res["gaps"], [])

    def test_gap_becomes_a_visible_hit_never_a_silent_pass(self):
        self._use([_StubEngine(gaps=["yara: the YARA scan failed: RuntimeError: boom"])])
        sb._init(_cfg(self.site))
        res, status = sb.scan_file(self.probe)
        self.assertEqual(status, "scanned")
        self.assertIsNotNone(res, "a blind spot must flag the file, not pass it silently")
        self.assertEqual(len(res["gaps"]), 1)
        self.assertTrue(any(hh[2].startswith("YARA rules did not fully scan this file")
                            for hh in res["hits"]))
        self.assertEqual(res["verdict"], "LOW")     # 5 points: visible, not alarming

    def test_scan_batch_coverage_counters(self):
        self._use([_StubEngine(gaps=["stub gap"], only_for="probe.txt")])
        sb._init(_cfg(self.site))
        _res, counters = sb.scan_batch([self.probe, self.clean])
        self.assertEqual(counters.get("yara_gap"), 1)
        self.assertEqual(counters.get("yara_ok"), 1)

    def test_without_engines_no_coverage_keys_no_change(self):
        sb._init(_cfg(self.site))                   # cfg["yara"] is None: the pre-Sprint-1 path
        _res, counters = sb.scan_batch([self.probe, self.clean])
        self.assertNotIn("yara_ok", counters)
        self.assertNotIn("yara_gap", counters)


# ---------------------------------------------------------------------------
# unit level: the YaraEngine itself against a stubbed compiled ruleset
# (the real yara-python is exercised by the builder and CLI classes below)
# ---------------------------------------------------------------------------

class _StubInstance(object):
    def __init__(self, offset, matched):
        self.offset = offset
        self.matched_data = matched


class _StubString(object):
    def __init__(self, offset, matched):
        self.instances = [_StubInstance(offset, matched)]


class _StubMatch(object):
    def __init__(self, rule="R", namespace="default", meta=None, strings=()):
        self.rule = rule
        self.namespace = namespace
        self.meta = meta if meta is not None else {}
        self.strings = list(strings)


class _StubRules(object):
    def __init__(self, matches=(), exc=None, sleep=0.0):
        self.matches = list(matches)
        self.exc = exc
        self.sleep = sleep
        self.last_externals = None

    def match(self, data=None, externals=None, timeout=None):
        self.last_externals = externals
        if self.sleep:
            time.sleep(self.sleep)
        if self.exc is not None:
            raise self.exc
        return list(self.matches)


def _ctx(rel="inc/x.php", kind="php", name=None, raw=b"line one\nevil MARK here\n"):
    return be.ScanCtx("C:\\site\\" + rel.replace("/", "\\"), rel, name or rel.rsplit("/", 1)[-1],
                      kind, raw, len(raw))


class YaraEngineUnit(unittest.TestCase):

    def _engine(self, rules, timeout=5.0, base=None):
        return ye.YaraEngine(None, rules, 1, base if base is not None else {"cms": "joomla"},
                             timeout)

    def test_scan_failure_becomes_a_gap_reason(self):
        eng = self._engine(_StubRules(exc=RuntimeError("kaboom")))
        hits, gaps = eng.scan(_ctx())
        self.assertEqual(hits, [])
        self.assertEqual(len(gaps), 1)
        self.assertIn("kaboom", gaps[0])

    def test_externals_are_bound_per_file(self):
        stub = _StubRules()
        eng = self._engine(stub, base={"cms": "wordpress", "wp_root": True, "joomla_root": False})
        eng.scan(_ctx(rel="a/b/c.php", kind="php"))
        ext = stub.last_externals
        self.assertEqual(ext["file_name"], "c.php")
        self.assertEqual(ext["extension"], ".php")
        self.assertEqual(ext["path"], "a/b/c.php")
        self.assertEqual(ext["folder"], "a/b")
        self.assertEqual(ext["file_size"], 24)
        self.assertEqual(ext["rule_language"], "php")
        self.assertEqual(ext["cms"], "wordpress")
        self.assertIs(ext["wp_root"], True)

    def test_wall_clock_guard_turns_a_slow_scan_into_a_gap(self):
        eng = self._engine(_StubRules(sleep=0.15), timeout=0.1)
        hits, gaps = eng.scan(_ctx())
        self.assertEqual(len(gaps), 1)
        self.assertIn("timeout", gaps[0])

    def test_hit_severity_weight_line_from_match(self):
        m = _StubMatch(rule="EvilRule", namespace="webshells",
                       meta={"severity": "critical", "score": "12"},
                       strings=[_StubString(offset=9, matched=b"evil MARK here")])
        eng = self._engine(_StubRules(matches=[m]))
        hits, gaps = eng.scan(_ctx())
        self.assertEqual(gaps, [])
        sev, line, label, snip, weight = hits[0]
        self.assertEqual(sev, be.SEV_CRIT)
        self.assertEqual(line, 2)                       # offset 9 is on the second line
        self.assertEqual(label, "YARA: webshells.EvilRule")
        self.assertIn("evil MARK here", snip)
        self.assertEqual(weight, 12)

    def test_rule_without_meta_defaults_to_a_weak_warning(self):
        m = _StubMatch(rule="Quiet", namespace="default")
        eng = self._engine(_StubRules(matches=[m]))
        hits, _gaps = eng.scan(_ctx())
        sev, line, label, _snip, weight = hits[0]
        self.assertEqual(sev, be.SEV_WARN)
        self.assertEqual(weight, 1)
        self.assertEqual(label, "YARA: Quiet")
        self.assertEqual(line, 0)

    def test_placeholder_externals_cover_every_documented_name(self):
        for name in ("file_name", "extension", "path", "folder", "file_size",
                     "cms", "wp_root", "joomla_root", "rule_language"):
            self.assertIn(name, ye.PLACEHOLDER_EXTERNS)


# ---------------------------------------------------------------------------
# builder: isolation, cache - with the real yara-python when it is installed
# ---------------------------------------------------------------------------

@unittest.skipUnless(HAVE_YARA, "yara-python is not installed")
class YaraBuilder(unittest.TestCase):

    def _sources(self, rules_folder):
        return ye.collect_rule_files(rules_folder)

    def test_broken_rule_file_is_isolated_good_one_keeps_working(self):
        rd = write_rules({"good.yar": GOOD_RULE, "bad.yar": BAD_RULE})
        eng, problems = ye.build_yara_engine(self._sources(rd))
        self.assertIsNotNone(eng)
        self.assertEqual(eng.files_loaded, 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("bad.yar", problems[0])
        hits, gaps = eng.scan(_ctx(rel="probe.txt", kind="text", name="probe.txt",
                                   raw=b"x " + MARKER + b" y"))
        self.assertEqual(gaps, [])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][2], "YARA: good.SbProbeMarker")
        self.assertEqual(hits[0][0], be.SEV_WARN)       # no meta: never more than a warning

    def test_include_directive_is_refused(self):
        rd = write_rules({"host.yar": 'include "part.inc"\nrule Host { condition: SbAny }\n',
                          "part.inc": "rule SbAny { condition: true }\n"})
        eng, problems = ye.build_yara_engine(self._sources(rd))
        self.assertIsNone(eng)
        self.assertTrue(any("include" in p for p in problems), problems)

    def test_externals_gate_matches_per_file(self):
        rd = write_rules({"gate.yar":
                          'rule ExtGate {\n    strings:\n        $a = "%s" ascii wide\n'
                          '    condition:\n        extension == ".php" and $a\n}\n' % MARKER.decode()})
        eng, problems = ye.build_yara_engine(self._sources(rd))
        self.assertEqual(problems, [])
        php_hits, _ = eng.scan(_ctx(rel="shell.php", kind="php", name="shell.php",
                                    raw=b"<?php " + MARKER))
        txt_hits, _ = eng.scan(_ctx(rel="notes.txt", kind="text", name="notes.txt",
                                    raw=b"see " + MARKER))
        self.assertEqual(len(php_hits), 1)
        self.assertEqual(len(txt_hits), 0)

    def test_yarac_cache_is_written_used_and_self_heals(self):
        rd = write_rules({"good.yar": GOOD_RULE})
        cache = os.path.join(h.workdir("yq-cache-"), "not-created-yet")
        src = self._sources(rd)

        eng1, _p1 = ye.build_yara_engine(src, cache_dir=cache)
        cached = [n for n in os.listdir(cache) if n.endswith(".yarac")]
        self.assertEqual(len(cached), 1)

        eng2, _p2 = ye.build_yara_engine(src, cache_dir=cache)      # loaded, not recompiled
        hits, _ = eng2.scan(_ctx(rel="probe.txt", kind="text", name="probe.txt",
                                 raw=b"z " + MARKER))
        self.assertEqual(len(hits), 1)

        with open(os.path.join(cache, cached[0]), "wb") as fh:
            fh.write(b"corrupted on purpose")
        eng3, problems3 = ye.build_yara_engine(src, cache_dir=cache)
        self.assertIsNotNone(eng3)
        self.assertEqual(problems3, [])


# ---------------------------------------------------------------------------
# CLI level
# ---------------------------------------------------------------------------

class YaraCli(unittest.TestCase):

    def setUp(self):
        self.site = write_site({"probe.txt": b"x " + MARKER + b" y\n",
                                "clean.txt": b"nothing to see here\n"})
        self.rules = write_rules({"good.yar": GOOD_RULE})

    def test_default_run_stays_silent_about_yara(self):
        res, _report = h.scan(self.site)
        self.assertFalse(any(ln.startswith("YARA") for ln in res.lines()), res.out)

    def test_no_yara_flag_disables_even_with_rules(self):
        res, _report = h.scan(self.site, "--yara-rules", self.rules, "--no-yara")
        self.assertFalse(any(ln.startswith("YARA") for ln in res.lines()), res.out)

    def test_missing_rules_path_is_a_startup_error(self):
        res, _report = h.scan(self.site, "--yara-rules", os.path.join(self.site, "no-such-rules"))
        self.assertEqual(res.returncode, 1)
        self.assertIn("YARA:", res.out)

    def test_missing_yara_python_degrades_to_built_in_heuristics(self):
        """A stub 'yara' module that refuses to import simulates the package
        being absent; the scan must finish exactly as without the flag."""
        stub = h.workdir("yq-stub-")
        with open(os.path.join(stub, "yara.py"), "wb") as fh:
            fh.write(b"raise ImportError('simulated: yara-python is not installed')\n")
        base, _ = h.scan(self.site)
        res = h.run("scan_backdoors.py",
                    [self.site, "--no-progress", "--no-csv", "--workers", "1",
                     "--yara-rules", self.rules],
                    env={"PYTHONPATH": stub})
        self.assertEqual(res.returncode, base.returncode)
        self.assertIn("yara-python is not installed", res.out)
        self.assertIn("no rules are active", res.out)


@unittest.skipUnless(HAVE_YARA, "yara-python is not installed")
class YaraCliWithRules(unittest.TestCase):

    def setUp(self):
        self.site = write_site({"probe.txt": b"x " + MARKER + b" y\n",
                                "clean.txt": b"nothing to see here\n"})
        self.cache = os.path.join(h.workdir("yq-clicache-"), "cache")

    def test_end_to_end_hit_coverage_and_stats(self):
        rules = write_rules({"good.yar": GOOD_RULE})
        res, report = h.scan(self.site, "--yara-rules", rules, "--yara-cache", self.cache)
        self.assertEqual(res.returncode, 0, res.out)         # LOW only: no criticals
        self.assertIn("YARA: 1 rule(s) from 1 of 1 file(s)", res.out)
        found = h.findings_by_path(report)
        self.assertIn("probe.txt", found)
        self.assertIn("YARA: good.SbProbeMarker", found["probe.txt"]["signatures"])
        self.assertNotIn("clean.txt", found)
        stats = h.stats_of(report)
        self.assertEqual(stats["YARA: rules loaded"], 1)
        self.assertEqual(stats["YARA: files scanned"], 2)
        self.assertEqual(stats["YARA: scan gaps (files not fully scanned)"], 0)

    def test_broken_rule_is_visible_on_stdout_and_good_rules_still_run(self):
        rules = write_rules({"good.yar": GOOD_RULE, "bad.yar": BAD_RULE})
        res, report = h.scan(self.site, "--yara-rules", rules, "--yara-cache", self.cache)
        self.assertIn("bad.yar", res.out)
        self.assertIn("skipped", res.out)
        self.assertIn("YARA: 1 rule(s) from 1 of 2 file(s)", res.out)
        found = h.findings_by_path(report)
        self.assertIn("probe.txt", found)

    def test_rule_without_markers_costs_nothing(self):
        """A rule that matches nothing changes no verdict and no exit code."""
        empty = write_rules({"quiet.yar":
                             'rule NeverHitsHere {\n    strings:\n        $a = "%s"\n'
                             '    condition:\n        $a\n}\n' % ("NOPE_NOT_ON_THIS_SITE_ZQX" )})
        base, base_report = h.scan(self.site)
        res, report = h.scan(self.site, "--yara-rules", empty, "--yara-cache", self.cache)
        self.assertEqual(res.returncode, base.returncode)
        self.assertEqual(h.findings_by_path(base_report), h.findings_by_path(report))
        self.assertEqual(h.stats_of(report)["YARA: files scanned"], 2)


if __name__ == "__main__":
    unittest.main()
