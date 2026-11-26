# Security policy

## What this tool guarantees — and what it does not

Scan Backdoors is a signature scanner for your own sites. It reads the folder you
point it at and writes only the reports you ask for.

**Holds for every release:**

- No network access of any kind from the scanner or the cleaner. Nothing is
  uploaded, no telemetry, no update checks. The GUI listens on `127.0.0.1` only.
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
