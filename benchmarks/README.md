# Benchmarks

`bench_scan.py` measures what a scan of a real-looking site costs, and - the part
that matters for a release decision - **what a new engine costs compared to the scan
without it**. Absolute throughput on a machine nobody owns is not a fact anyone can
reuse; "the YARA engine added 11 % to the wall time of the same tree on the same
machine, in this run, next to the run without it" is.

The acceptance budget the project works to (from the technical specification):
**the full scan of the reference tree must stay within +30 % of the same scan with
the optional engine switched off**, and the peak worker memory must be written down
rather than assumed.

## Run it

```bash
python3 benchmarks/bench_scan.py                       # 10 000 PHP files, both variants
python3 benchmarks/bench_scan.py --files 3000          # a quick local run
python3 benchmarks/bench_scan.py --yara-rules "$(python3 src/updater.py --rules-path)"
python3 benchmarks/bench_scan.py --corpus /srv/sites/joomla-shop   # your own tree
python3 benchmarks/bench_scan.py --compare previous-bench.json
```

Nothing here is installed and nothing is required: `bench_scan.py` is standard
library and calls `src/scan_backdoors.py` as a subprocess, exactly the way a user
does. The interpreter that runs the benchmark is the interpreter that runs the scan.

## What it does

1. **Builds the corpus** (or uses `--corpus`). The generated tree is deterministic
   for a given `--seed` and `--files`: Joomla- and WordPress-shaped folders, file
   sizes from 0.5 KB to 150 KB, and a controlled density of strings that the
   heuristics react to (`eval`, `base64_decode`, `$_GET`, `@include`). A corpus of
   10 000 empty `<?php` files would measure process startup, not scanning.
   The tree is written under the system temporary folder, never into a site.
2. **Runs the scan twice** over the *same* tree with identical options - once
   without `--yara-rules`, once with - each preceded by a cold start (the `.yarac`
   cache emptied) and followed by a warm start (the cache kept). Both are reported:
   compiling a rule package costs real time, and a scanner that ships a cache
   should be measured using it.
3. **Measures** wall time, the scanner's own `Time, s`, files/second, the exit code,
   the number of files the scanner actually scanned (a run that skipped half the
   tree is not a comparable run - the benchmark refuses to compare such runs), and
   the **peak RSS of the whole process tree**, sampled from outside the child.
4. **Decides** against the +30 % budget and writes a JSON record that a later run
   can `--compare` against.

## What is deliberately *not* measured

- **Peak memory per worker.** The scanner parallelises with `multiprocessing`, so a
  single "worker RSS" is not a thing one process holds; the benchmark samples the
  launched child *and its children* and reports the peak of the tree. On Linux it
  reads `VmHWM`/`RssAnon` from `/proc`; on Windows `psapi`; on anything else it says
  `null` and the JSON records that the number is missing. No number is invented on
  a platform the sampler cannot read.
- **A machine-wide "files per second" target.** Throughput depends on disk cache,
  CPU, and on how much of the tree the baseline matched. Only two runs on the same
  machine, one next to the other, are comparable; every JSON records the Python
  version, the platform and the machine so that a comparison across machines is
  visibly a comparison across machines.
- **Network.** Nothing in a benchmark may reach out: the scans run without
  `--online`, and the reference tree contains no real CMS.

## The reference numbers

`benchmarks/reference/` holds JSON records produced on the maintainer's machine.
They are the "previous behaviour" a `--compare` should be pointed at; they are not
a promise about your hardware. Regenerate them rather than editing them by hand —
and keep the paths out of them by letting the tool write the file (it records the
command with `<CORPUS>`/`<RULE-PACKAGE>` tokens instead of the folders of the machine).

The first record, `py311-win32-php10k.json` (Python 3.11.9 on Windows, 10 000 generated
PHP files / 183 MB, a 6-rule package, `--workers 0`):

| run | wall | files/s | peak RSS of the tree |
|---|---|---|---|
| baseline (no rule package) | 46.5 s | 215 | 144 MB |
| rules, cold `.yarac` cache | 42.3 s | 237 | 152 MB |
| rules, warm cache | 42.3 s | 236 | 151 MB |

`cold / baseline = 0.91`, `warm / baseline = 0.91` — inside the +30 % budget, with room
to spare: on this corpus the rule engine is not what makes a scan slow, and the 8 MB of
extra resident memory is the compiled rules sitting in each worker. A future release that
makes the ratio move is the reason this file exists.

## CI

`.github/workflows/ci.yml` runs this on a small corpus (800 files) with a generated
six-rule package and `--budget 2.5`. That is a **smoke test of the benchmark itself** — it
proves the script runs, produces a parseable record and does not error — not the
performance gate: 800 files measure mostly startup, and a shared runner is not a machine
whose timings mean anything. The budget is widened there on purpose so that a catastrophic
regression (a quadratic walk, a re-compile per file) fails CI while noise does not; the
+30 % of the specification is decided by a human reading a run on fixed hardware against
`benchmarks/reference/`, which is the only place the number means anything.
