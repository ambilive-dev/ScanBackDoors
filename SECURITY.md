# Security policy

## What this tool guarantees — and what it does not

Scan Backdoors is a signature scanner for your own sites. It reads the folder you
point it at and writes only the reports you ask for.

**Holds for every release:**

- No network access from the scanner unless you ask for it. Without `--online` the
  scanner, the cleaner and the GUI make no request at all; nothing is uploaded, no
  telemetry, no update checks. The GUI listens on `127.0.0.1` only.
- The outbound requests in the bundle are the ones you explicitly start: the
  clean-baseline downloader (`joomla_baseline.py`, also the GUI's *Fetch baseline*
  button), the signature updater (`updater.py`, also its GUI buttons) and the CMS
  audit (`scan_backdoors.py --online`, needed by `--check-integrity`/`--audit-cve`).
  All speak HTTPS only to a fixed host allowlist and re-check every redirect against
  it; all use size-capped responses. The updater never executes what it
  downloads: a rule package is unpacked under path/symlink/size guards, every rule
  file is compile-checked in a separate process, and only then does an atomic pointer
  switch make it active - a failed update leaves the previous release in place, and
  an unverified package is refused unless you pass `--allow-unverified` (which is
  recorded in the manifest).
- What the CMS audit gives away, since it is the one part of a scan that can talk to
  somebody else: `--check-integrity` sends the WordPress version it found to
  `api.wordpress.org`; `--audit-cve` sends every plugin/theme slug and version it
  found to `api.wpvulnerability.com`. No site name, no paths, no file contents, and
  answers are cached for a day in your data folder, so repeat runs of the same site
  stay offline. The scanner never acts on what a site claims about itself: a manifest
  is parsed under size and `DOCTYPE`/`ENTITY` guards, no PHP of the site is executed,
  and the version the site declares is only trusted while the integrity pass agrees -
  if the CMS's own version file is modified, every vulnerability verdict in that run
  drops to low confidence. Nothing is uploaded by any of them.
- What a signature update is trusted by: a public key you pinned in `sources.json`
  (minisign/Ed25519 - the updater activates only a package whose bytes that key
  signed), and/or a sha256 you pinned. A pinned hash says "nobody changed this since
  I pinned it"; only a pinned key says who made it, so pin the key for the project's
  own channel. `sources.json` is therefore a file of trust: editing a pinned key is
  the same decision as trusting a new publisher. The signature check uses the optional
  `cryptography` package; without it the updater says so in the output and records
  `"signature": "not-checked"` instead of pretending - `--require-signature` makes that
  a hard refusal. The `minisign` program is never executed.
- Nothing is deleted without an explicit action: quarantine by default, copies of
  modified files are kept, `clean_malware.py` needs `--apply` to change anything
  and can be rolled back with `--restore manifest.json`.
- A scan never writes into the scanned site except into the `_quarantine_*`
  folder it creates.

**Not a guarantee:**

- No scanner detects everything. A clean report is not proof that a site is clean;
  it is one signal among many. Compare file hashes against a clean distribution
  (`--baseline-dir`), check `access`/`error` logs and outbound connections too.
- The bundled `data/whitelist-known-clean.txt` suppresses findings by hash. Treat
  it as a starting point: review it before trusting it, and rebuild it for your
  own set of extensions.
- A vulnerability verdict (`--audit-cve`) says a published CVE applies to the version
  a component declares. It is not evidence of compromise, it is not scored with the
  file findings, and it is never offered for quarantine or delete - the fix is to
  update the component. The local database ships empty (the scanner does not invent
  CVE data), so an offline audit against it honestly reports nothing.

## Reporting a vulnerability

Please use [private vulnerability reporting](../../security/advisories/new) on this
repository instead of a public issue. Public issues are the right place for false
positives, feature requests and everything non-sensitive.

Expect a first reply within a week. Fixes are released as regular versions;
nothing is shipped silently.

## Hardening the GUI on a remote machine

Do not expose port 8765. Use an SSH tunnel:

```
ssh -L 8765:127.0.0.1:8765 user@server
```

and open <http://127.0.0.1:8765/> locally. The GUI accepts requests only for the
host names `127.0.0.1`/`localhost` on its own port and requires its own custom
header, which blocks DNS rebinding and cross-site requests from other pages.
