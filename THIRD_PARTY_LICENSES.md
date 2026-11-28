# Third-party licences and sources

This repository's own code is **MIT** (see `LICENSE`). The tools import nothing at
runtime: the scanner, the GUI, the cleaner, the baseline fetcher and the updater are
standard library on Python 3.6+. This file records the parts that are **not** ours -
what they are, under what terms they reach a machine, and where a fact here was
checked. Nothing below is vendored: no third-party source file, rule file, dataset
or icon is copied into this repository, so there is no redistribution to licence.

Date of the licence facts below: 2026-11-28, read from the projects' own PyPI
metadata and repositories. Re-check them when a version in
`requirements-optional.txt` is bumped.

## Optional Python packages

Nothing here is installed by anything in this repository. An operator installs them
(`pip install -r requirements-optional.txt`) and the tools notice: every import is
inside the one function that needs it, and the absence of a package changes a feature
from available to "not available, and here is why" - never a crash. `tests/test_compat.py`
enforces that a third-party name can only ever be imported that way.

| Package | What it is for | Licence | Where it was read |
|---|---|---|---|
| `yara-python` | the optional YARA engine behind `--yara-rules` | Apache-2.0 (`info.license` "Apache 2.0", classifier "License :: OSI Approved :: Apache Software License"); its `LICENSE` file is the Apache text | <https://pypi.org/pypi/yara-python/json>, <https://github.com/VirusTotal/yara-python/blob/master/LICENSE> |
| `cryptography` | lets `updater.py` honour a pinned minisign public key (Ed25519); the scanner never imports it | Apache-2.0 **or** BSD-3-Clause (`info.license_expression`) | <https://pypi.org/pypi/cryptography/json> |

`yara-python` binds libYARA into its wheels, so an installed wheel carries libYARA's
own terms as well as Apache-2.0. This project does not build, bundle or ship that
wheel, so it does not speak for the combination; anyone packaging a self-contained
installer must read libYARA's licence at
<https://github.com/VirusTotal/yara/blob/master/COPYING> themselves.
`# TODO(verify): libYARA's licence terms as shipped in the wheel we do not build.`

The interpreter itself is CPython under the PSF licence, and the runtime it needs is
the operator's.

## Detection rules

**This repository ships no third-party detection rules.** The built-in signatures are
written here. `updater.py` can install a rule package from a pinned source
(`sources.json`), and a rule package from somewhere else arrives under *that*
somewhere's licence and terms of use, not ours: it is downloaded to the operator's
machine at the operator's command, is treated as hostile input (compiled per file,
`include` refused, size caps, never executed), and is never mirrored into this
repository. Third-party rule sets in the wild (for example Neo23x0/sigma and similar
repositories) have their own licences, and some of them restrict redistribution -
which is one reason the publication channel is still closed by default
(`docs/OPEN_QUESTIONS.md` #13).

## Test fixtures that are not ours

- **minisign signature fixtures** in `tests/test_updater.py` are real signatures
  produced by the `minisign` tool over the message `test`. They are data, not code.
  The format was cross-checked against the author's reference port
  [`jedisct1/go-minisign`](https://github.com/jedisct1/go-minisign) (ISC licence); no
  code from it was copied here, and the ISC terms of the reference port apply to that
  repository, not to these bytes.

## Datasets

- `data/whitelist-known-clean.txt` is our own curated data.
- Clean **Joomla/WordPress baselines** are downloaded by `joomla_baseline.py` from
  the official project sites, on request, into the operator's data folder. Those
  distributions are GPL; this project neither contains them nor mirrors them, and the
  comparison works on hashes computed locally.
- A **known-clean allowlist** is generated on the operator's own site by
  `tools/build_allowlist.py`. Its content is whatever that site contains, so it is
  the operator's data and the operator's licence problem; nothing is committed.

## Continuous integration

The workflow in `.github/workflows/ci.yml` uses
[`actions/checkout`](https://github.com/actions/checkout),
[`actions/setup-python`](https://github.com/actions/setup-python),
[`actions/upload-artifact`](https://github.com/actions/upload-artifact) and
[`github/codeql-action`](https://github.com/github/codeql-action) (MIT, as published
in their repositories), pinned to commit SHAs. They run on GitHub's infrastructure on
the repository owner's account; no code from them is distributed with this project.

The development tools are pinned in `requirements-dev.txt` and are not part of any bundle:

| Tool | Licence | `requires_python` | Where it was read |
|---|---|---|---|
| `coverage` 7.17.5 | Apache-2.0 | >= 3.11 | <https://pypi.org/pypi/coverage/json> |
| `ruff` 0.17.6 | MIT (`license_expression`) | >= 3.7 | <https://pypi.org/pypi/ruff/json> |
| `bandit` 1.9.4 | Apache-2.0 | >= 3.10 | <https://pypi.org/pypi/bandit/json> |

Note the asymmetry, recorded because it surprises people: the tools that *measure* this
repository require a newer Python than the code they measure. The 3.6 and 3.8 jobs run the
test suite; they do not, and cannot, run these three packages.
