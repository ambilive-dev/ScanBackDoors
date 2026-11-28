#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Benchmark the scanner against itself: the same tree, scanned with and without
the optional engine, in the same process run, on the same machine.

Standard library only, Python 3.6+ - the same rule the tools follow, because a
benchmark that cannot run on the oldest supported interpreter cannot describe how
that interpreter behaves. Read benchmarks/README.md first: what is measured here is
a DIFFERENCE, not a throughput claim, and the +30 % budget in the technical
specification is a statement about a difference.

Usage:
    python3 benchmarks/bench_scan.py
    python3 benchmarks/bench_scan.py --files 3000 --workers 1
    python3 benchmarks/bench_scan.py --corpus /srv/sites/shop --yara-rules "$(python3 src/updater.py --rules-path)"
    python3 benchmarks/bench_scan.py --compare benchmarks/reference/joomla-10k.json

Exit codes: 0 the run completed inside the budget, 3 the budget was exceeded,
1 the benchmark or a scan could not be run at all.
"""

from __future__ import print_function

import argparse
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SCANNER = os.path.join(REPO, "src", "scan_backdoors.py")

# The exit codes of scan_backdoors.py that mean "the scan happened". 2 is not an
# error: it means the tree contained [CRITICAL] findings, and a corpus with no
# suspicious strings in it would measure a scanner that gave up early.
SCAN_OK = (0, 2)

# Strings that the heuristics react to. They are inert: a benchmark must not put a
# working payload anywhere, and it must not measure a corpus the scanner finds
# boring either - scanning 10 000 clean files measures file reading, not detection.
NEEDLES = ["eval(base64_decode(", "$_GET[", "assert(", "preg_replace('/.*/e'",
           "create_function(", "system(", "file_get_contents($_REQUEST[",
           "gzinflate(", "str_rot13(", "base64_decode(\""]

FILLER = ("/**\n * @package %s\n * @license GNU GPLv2\n */\n"
          "defined('_JEXEC') or die;\n"
          "class %s extends JControllerAdmin {\n"
          "    public function getModel($name = '', $prefix = '', $options = array()) {\n"
          "        return JModelLegacy::getInstance($name, $prefix, $options);\n"
          "    }\n}\n")

DIRS = ["components/com_%s", "components/com_%s/views/%s/tmpl", "components/com_%s/helpers",
        "components/com_%s/models", "components/com_%s/tables", "libraries/joomla/%s",
        "libraries/src/%s", "modules/mod_%s/tmpl", "plugins/system/%s", "plugins/content/%s",
        "templates/%s/html", "libraries/vendor/%s/src", "media/com_%s/js",
        "wp-content/plugins/%s", "wp-content/plugins/%s/includes", "wp-content/themes/%s",
        "wp-content/uploads/%s", "wp-includes/Requests/Library", "wp-admin/network"]
WORDS = ["user", "contact", "banner", "content", "fields", "finder", "action", "associations",
         "installer", "languages", "menus", "messages", "privacy", "profiles", "redirect",
         "tags", "templates", "users", "widgets", "api", "cache", "session", "mail", "log"]


# --------------------------------------------------------------------- corpus
def build_corpus(root, want_files, seed, density):
    """Generate a deterministic CMS-shaped tree. Returns the file list it wrote.

    Deterministic for a given (want_files, seed): two runs of this script must
    scan the same bytes, otherwise the difference they measure is the difference
    between two corpora. Sizes span 512 B..150 KB and `density` controls how many
    files hold a string the heuristics react to.
    """
    rnd = random.Random(seed)
    written = []
    n = 0
    while n < want_files:
        shape = rnd.choice(DIRS)
        folder = shape % tuple(rnd.choice(WORDS) for _ in range(shape.count("%s")))
        target = os.path.join(root, folder.replace("/", os.sep))
        if not os.path.isdir(target):
            os.makedirs(target)
        ext = rnd.choice([".php"] * 8 + [".js", ".html", ".tpl", ".css", ".txt", ".ini"])
        name = "%s_%05d%s" % (rnd.choice(WORDS), n, ext)
        path = os.path.join(target, name)
        size = int(rnd.lognormvariate(9.0, 1.4))          # median ~8 KB, tail ~150 KB
        size = max(512, min(size, 150 * 1024))
        cls = "".join(w.capitalize() for w in rnd.choice(WORDS).split("_"))[:24] or "Std"
        block = FILLER % (rnd.choice(WORDS), cls)         # one block, no format left in it
        text = (block * (size // len(block) + 1))[:size]
        if rnd.random() < density:                        # a file worth looking at
            pos = rnd.randrange(0, max(1, len(text) - 1))
            text = text[:pos] + rnd.choice(NEEDLES) + text[pos:]
        with open(path, "wb") as fh:
            fh.write(text.encode("utf-8", "replace"))
        written.append(os.path.relpath(path, root).replace(os.sep, "/"))
        n += 1
    return written


def corpus_fingerprint(root):
    """(files, bytes) of a tree - enough to tell whether two runs scanned the same thing."""
    files = total = 0
    for _dir, _sub, names in os.walk(root):
        for name in names:
            files += 1
            try:
                total += os.path.getsize(os.path.join(_dir, name))
            except OSError:
                pass
    return files, total


# ------------------------------------------------------------------- memory
class PeakMemory(object):
    """Sample the peak resident set of a child process and its children.

    The scanner parallelises with `multiprocessing`, so "the memory of the scan" is
    the sum of a process tree, and a sum has to be sampled while it runs. Three
    sources, in order of trustworthiness, and the result says which one produced it:

      * `/proc` (Linux): VmHWM per process;
      * `psapi` through ctypes (Windows): the working set per process;
      * `resource.getrusage(RUSAGE_CHILDREN)` (POSIX fallback): the peak of any ONE
        child, which is not the tree - the record says `one_child` so nobody reads
        it as a tree total.

    A platform with none of them reports `None`. A benchmark that guesses the
    memory of a platform it cannot read is worse than one that says nothing.
    """

    def __init__(self, root_pid):
        self.root_pid = root_pid
        self.peak = 0
        self.source = None
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._sample_loop)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _sample_loop(self):
        while not self._stop.is_set():
            total, source = self._tree_total()
            if total is not None:
                if self.source is None:
                    self.source = source
                if total > self.peak:
                    self.peak = total
            self._stop.wait(0.02)

    def _tree_total(self):
        if sys.platform.startswith("linux"):
            pids = _proc_tree(self.root_pid)
            if not pids:
                return None, None
            total = 0
            for pid in pids:
                rss = _proc_rss(pid)
                if rss is None:
                    return None, None
                total += rss
            return total, "proc_tree"
        if os.name == "nt":
            pids = _win_tree(self.root_pid)
            if not pids:
                return None, None
            total = 0
            for pid in pids:
                rss = _win_rss(pid)
                if rss is None:
                    return None, None
                total += rss
            return total, "psapi_tree"
        return _rusage_child_peak(), "rusage_one_child"


def _proc_tree(root_pid):
    out = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return out
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry) as fh:
                fields = fh.read().rsplit(") ", 1)[-1].split()
            ppid = int(fields[1])
        except (IOError, OSError, IndexError, ValueError):
            continue
        if ppid == root_pid or int(entry) == root_pid:
            out.append(entry)
    return out


def _proc_rss(pid):
    """VmHWM: the peak resident set so far, which is what a sampler would converge to."""
    try:
        with open("/proc/%s/status" % pid) as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
    except (IOError, OSError, ValueError):
        return None
    return None


def _win_tree(root_pid):
    import ctypes
    import ctypes.wintypes
    TH32CS_SNAPPROCESS = 0x00000002

    class Entry(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.wintypes.DWORD), ("cntUsage", ctypes.wintypes.DWORD),
                    ("th32ProcessID", ctypes.wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", ctypes.wintypes.DWORD),
                    ("cntThreads", ctypes.wintypes.DWORD),
                    ("th32ParentProcessID", ctypes.wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260)]

    kernel32 = ctypes.windll.kernel32
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (0, -1):
        return []
    out = []
    try:
        entry = Entry()
        entry.dwSize = ctypes.sizeof(Entry)
        ok = kernel32.Process32First(snap, ctypes.byref(entry))
        while ok:
            if entry.th32ProcessID == root_pid or entry.th32ParentProcessID == root_pid:
                out.append(str(entry.th32ProcessID))
            ok = kernel32.Process32Next(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return out


def _win_rss(pid):
    import ctypes
    import ctypes.wintypes

    class Counter(ctypes.Structure):
        _fields_ = [("cb", ctypes.wintypes.DWORD),
                    ("PageFaultCount", ctypes.wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t)]

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_READ = 0x0010
    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not handle:
        return None
    try:
        info = Counter()
        info.cb = ctypes.sizeof(Counter)
        if not ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(info), info.cb):
            return None
        return int(info.PeakWorkingSetSize)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _rusage_child_peak():
    try:
        import resource
    except ImportError:
        return None
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if peak <= 0:
        return None
    return peak * (1024 if sys.platform != "darwin" else 1)


# --------------------------------------------------------------------- scans
def run_scan(corpus, args, label, extra_args, cache_dir, keep_cache=False):
    """One scan. Returns a metrics dict, or raises RuntimeError with the output.

    `keep_cache=False` empties the `.yarac` cache first: the first run against a rule
    package pays for compiling it, and that cost is a number worth seeing. The run
    after it, with the cache left alone, is what the scanner actually feels on the
    second scan of the day. Both are reported, because a cache that is never measured
    is a cache that quietly grew.
    """
    report = os.path.join(args.scratch, "report-%s.json" % label)
    if not keep_cache:
        for stale in os.listdir(cache_dir):
            path = os.path.join(cache_dir, stale)
            shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
    cmd = [args.python, SCANNER, corpus, "--no-progress", "--no-csv", "--json", report,
           "--yara-cache", cache_dir, "--workers", str(args.workers)] + extra_args
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=args.scratch)
    sampler = PeakMemory(proc.pid)
    sampler.start()
    try:
        out = proc.communicate()[0].decode("utf-8", "replace")
    finally:
        sampler.stop()
    wall = time.time() - started
    if proc.returncode not in SCAN_OK:
        raise RuntimeError("%s exited %d\n%s" % (" ".join(cmd), proc.returncode,
                                                 out[-4000:]))
    stats = {}
    if os.path.isfile(report):
        with open(report, "rb") as fh:
            stats = (json.loads(fh.read().decode("utf-8", "replace")) or {}).get("stats", {})
    os.remove(report)
    scanned = stats.get("Files scanned") or 0
    return {
        # the record is committed as a reference, so it must not carry the paths of
        # the machine that produced it: the folder roles become tokens
        "command": _display_command(cmd, args, corpus, cache_dir, report),
        "wall_s": round(wall, 2),
        "scanner_time_s": stats.get("Time, s"),
        "files_visited": stats.get("Files visited"),
        "files_scanned": scanned,
        "files_per_s": round(scanned / wall, 1) if wall > 0 and scanned else None,
        "flagged": stats.get("Files flagged"),
        "peak_rss_bytes": sampler.peak or None,
        "peak_rss_source": sampler.source,
        "exit_code": proc.returncode,
        "yara_rules_loaded": stats.get("YARA: rules loaded"),
        "yara_scan_gaps": stats.get("YARA: scan gaps (files not fully scanned)"),
    }


def _display_command(cmd, args, corpus, cache_dir, report):
    """The command line with the machine's paths replaced by tokens.

    A reference record is committed to the repository: it has to say what was run
    without carrying the folder layout - and therefore the user name - of the
    machine that ran it.
    """
    tokens = {SCANNER: os.path.relpath(SCANNER, REPO).replace(os.sep, "/"),
              corpus: "<CORPUS>", cache_dir: "<YARA-CACHE>", report: "<REPORT>"}
    if args.yara_rules:
        tokens[os.path.abspath(args.yara_rules)] = "<RULE-PACKAGE>"
        tokens[args.yara_rules] = "<RULE-PACKAGE>"
    return [tokens.get(part, part) for part in cmd[1:]]


def measure(corpus, args):
    """The baseline scan, and the same scan with the rule package, each cold and warm."""
    runs = {}
    base_cache = os.path.join(args.scratch, "cache-base")
    os.makedirs(base_cache)
    runs["baseline"] = run_scan(corpus, args, "baseline", [], base_cache)

    rules = args.yara_rules
    if rules:
        y_cache = os.path.join(args.scratch, "cache-yara")
        os.makedirs(y_cache)
        cold = run_scan(corpus, args, "yara-cold", ["--yara-rules", rules], y_cache)
        # the second run keeps the cache the first one wrote: that is the warm case
        warm = run_scan(corpus, args, "yara-warm", ["--yara-rules", rules], y_cache,
                        keep_cache=True)
        runs["yara_cold"] = cold
        runs["yara_warm"] = warm
        if not cold["yara_rules_loaded"]:
            print("[WARN] the rule package loaded 0 rules - the numbers below compare a "
                  "scan against an engine that did nothing")
    return runs


def compare_runs(runs, budget):
    """Ratio of the yara scan to the baseline, and the verdict against the budget."""
    base = runs["baseline"]["wall_s"]
    out = {}
    for key in ("yara_cold", "yara_warm"):
        if key not in runs or not base:
            continue
        ratio = round(runs[key]["wall_s"] / base, 4)
        out[key + "_ratio"] = ratio
        out[key + "_within_budget"] = ratio <= budget
    comparable = (runs["baseline"]["files_scanned"] ==
                  runs.get("yara_cold", runs["baseline"])["files_scanned"])
    out["same_tree_scanned"] = comparable
    if not comparable:
        # Different numbers of scanned files mean the two runs did not do the same
        # work (a file the antivirus removed, a size limit, a read error). A ratio
        # between two different amounts of work is not a measurement at all.
        out["warning"] = ("the runs scanned different numbers of files (%s vs %s): the "
                          "ratio is meaningless, do not read it"
                          % (runs["baseline"]["files_scanned"],
                             runs["yara_cold"]["files_scanned"]))
    return out


# ----------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--files", type=int, default=10000, help="PHP files to generate (default 10000)")
    ap.add_argument("--corpus", default="", help="scan this folder instead of generating one")
    ap.add_argument("--seed", type=int, default=20261128, help="corpus seed (default 20261128)")
    ap.add_argument("--density", type=float, default=0.06,
                    help="share of generated files holding a suspicious string (default 0.06)")
    ap.add_argument("--workers", type=int, default=0, help="scanner workers: 0 auto, 1 serial")
    ap.add_argument("--yara-rules", default="",
                    help="rule package to compare against (`python3 src/updater.py --rules-path`)")
    ap.add_argument("--budget", type=float, default=1.30,
                    help="largest accepted ratio to the baseline scan (default 1.30 = +30 %)")
    ap.add_argument("--out", default="", help="write the JSON record here")
    ap.add_argument("--compare", default="", help="print the delta against an earlier record")
    ap.add_argument("--keep", action="store_true", help="keep the generated corpus and say where")
    ap.add_argument("--python", default=sys.executable, help="interpreter for the scans")
    args = ap.parse_args(argv)

    if not os.path.isfile(SCANNER):
        print("cannot find %s - run this from a checkout" % SCANNER)
        return 1
    args.scratch = tempfile.mkdtemp(prefix="sbd-bench-")

    try:
        if args.corpus:
            corpus = os.path.abspath(args.corpus)
            if not os.path.isdir(corpus):
                print("--corpus must be an existing folder: %s" % corpus)
                return 1
            print("corpus: %s (given)" % corpus)
        else:
            corpus = os.path.join(args.scratch, "site")
            os.makedirs(corpus)
            print("building %d files in %s (seed %d, density %.2f) ..."
                  % (args.files, corpus, args.seed, args.density))
            t0 = time.time()
            build_corpus(corpus, args.files, args.seed, args.density)
            print("  built in %.1f s" % (time.time() - t0))
        files, total_bytes = corpus_fingerprint(corpus)
        print("corpus: %d files, %.1f MB" % (files, total_bytes / 1048576.0))
        print("python: %s on %s" % (platform.python_version(), sys.platform))

        runs = measure(corpus, args)
        verdict = compare_runs(runs, args.budget)

        record = {
            "record": 1,
            "tool": "bench_scan",
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine_cpus": os.cpu_count(),
            "workers": args.workers,
            "corpus": {"files": files, "bytes": total_bytes,
                       "seed": None if args.corpus else args.seed,
                       "given": bool(args.corpus)},
            "yara_rules": ("<RULE-PACKAGE>" if args.yara_rules else None),
            "budget_ratio": args.budget,
            "runs": runs,
            "verdict": verdict,
        }
        print("")
        print("%-12s %9s %9s %9s %11s %s" % ("run", "wall s", "files/s", "peak MB",
                                             "rules", "memory source"))
        for key in ("baseline", "yara_cold", "yara_warm"):
            if key not in runs:
                continue
            r = runs[key]
            print("%-12s %9.2f %9s %9s %11s %s" % (
                key, r["wall_s"],
                "-" if r["files_per_s"] is None else "%.0f" % r["files_per_s"],
                "-" if r["peak_rss_bytes"] is None else "%.0f" % (r["peak_rss_bytes"] / 1048576.0),
                r["yara_rules_loaded"] if r["yara_rules_loaded"] is not None else "-",
                r["peak_rss_source"] or "unavailable"))
        if "yara_cold_ratio" in verdict:
            print("\ncold / baseline : %.3f  (%s the %.0f %% budget)" % (
                verdict["yara_cold_ratio"], "WITHIN" if verdict["yara_cold_within_budget"] else "OVER",
                (args.budget - 1) * 100))
            print("warm / baseline : %.3f  (%s)" % (
                verdict["yara_warm_ratio"], "WITHIN" if verdict["yara_warm_within_budget"] else "OVER"))
        if "warning" in verdict:
            print("\n[WARN] " + verdict["warning"])

        if args.compare and os.path.isfile(args.compare):
            with open(args.compare, "rb") as fh:
                prev = json.loads(fh.read().decode("utf-8", "replace"))
            print("\nvs %s:" % os.path.basename(args.compare))
            for key in sorted(runs):
                old = (prev.get("runs") or {}).get(key)
                if not old:
                    print("  %-12s not in the earlier record" % key)
                    continue
                delta = (runs[key]["wall_s"] / old["wall_s"] - 1.0) * 100.0
                print("  %-12s %+.1f %%  (%.2f s -> %.2f s)"
                      % (key, delta, old["wall_s"], runs[key]["wall_s"]))
            same = (prev.get("corpus") or {}).get("files") == files
            if not same:
                print("  note: the earlier record scanned a different corpus - "
                      "the percentages above are not a like-for-like comparison")

        if args.out:
            with open(args.out, "w") as fh:
                json.dump(record, fh, indent=1, sort_keys=True)
            print("\nrecord: %s" % args.out)
        if args.keep:
            print("corpus kept at %s" % corpus)
        else:
            shutil.rmtree(corpus, ignore_errors=True)

        over = [k for k in ("yara_cold_within_budget", "yara_warm_within_budget")
                if verdict.get(k) is False]
        if over or "warning" in verdict:
            return 3
        return 0
    finally:
        if not args.keep:
            shutil.rmtree(args.scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
