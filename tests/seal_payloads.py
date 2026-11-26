#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seal/unseal the malicious test payloads.

tests/payloads/*.b64 hold the samples as base64 with a description in a header
comment. Two reasons, both practical:

  * a public repository that contains copy-pasteable web shells is a magnet for
    malware scanners (GitHub's own, and the antivirus on every machine that
    clones it), which has nothing to do with the tool being developed here;
  * Windows Defender on a developer machine deletes such files the moment they
    are written - the samples are only ever unsealed into the fixture folder
    while a test runs.

It is encoding, not protection: `--show` prints any payload in plain text.

    python tests/seal_payloads.py                 # verify every seal decodes
    python tests/seal_payloads.py --list          # name + description
    python tests/seal_payloads.py --show filefuns.php
    python tests/seal_payloads.py --write filefuns.php < /tmp/new-sample.php
"""

import argparse
import base64
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_DIR = os.path.join(HERE, "payloads")
ENCODING = "utf-8"


def names():
    return sorted(f[:-4] for f in os.listdir(PAYLOAD_DIR) if f.endswith(".b64"))


def _path(name):
    return os.path.join(PAYLOAD_DIR, name + ".b64")


def describe(name):
    out = []
    with io.open(_path(name), encoding=ENCODING) as f:
        for line in f:
            if not line.startswith("#"):
                break
            out.append(line[1:].strip())
    return " ".join(out)


def unseal(name):
    """Raw bytes of a payload."""
    with io.open(_path(name), encoding=ENCODING) as f:
        b64 = "".join(line.strip() for line in f if not line.startswith("#"))
    return base64.b64decode(b64)


def text(name):
    return unseal(name).decode(ENCODING)


def seal(name, raw, description):
    body = base64.b64encode(raw if isinstance(raw, bytes) else raw.encode(ENCODING)).decode("ascii")
    lines = ["# " + description]
    lines += [body[i:i + 76] for i in range(0, len(body), 76)]
    if not os.path.isdir(PAYLOAD_DIR):
        os.makedirs(PAYLOAD_DIR)
    with io.open(_path(name), "w", encoding=ENCODING, newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return _path(name)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Seal/unseal malicious test payloads.")
    ap.add_argument("--list", action="store_true", help="list payloads with their description")
    ap.add_argument("--show", metavar="NAME", help="print a payload in plain text")
    ap.add_argument("--write", metavar="NAME", help="(re)seal a payload from STDIN")
    ap.add_argument("--note", default="", help="description used with --write")
    args = ap.parse_args(argv)

    if args.list:
        for n in names():
            print("%-34s %s" % (n, describe(n)))
        return 0
    if args.show:
        sys.stdout.write(text(args.show))
        return 0
    if args.write:
        raw = sys.stdin.buffer.read() if hasattr(sys.stdin, "buffer") else sys.stdin.read()
        note = args.note or (describe(args.write) if os.path.exists(_path(args.write)) else args.write)
        print("sealed -> %s (%d bytes)" % (seal(args.write, raw, note), len(raw)))
        return 0

    bad = []
    for n in names():
        try:
            unseal(n).decode(ENCODING)
            print("ok   %s" % n)
        except Exception as exc:
            bad.append(n)
            print("FAIL %s: %s" % (n, exc))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
