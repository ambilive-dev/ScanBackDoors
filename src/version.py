#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Version of the Scan Backdoors bundle - the only place where it is written.

scan_backdoors.py (CLI scanner), scan_backdoors_gui.py (browser front end) and
clean_malware.py (mass cleanup) all take VERSION from this file, so one release
always reports one number: `--version` of any of the three prints the same value.

Every script also keeps the same value as a one-line fallback, because the CLI
scanner is routinely uploaded to a server as a single file and must still start
without its neighbours there. tests/test_release.py compares the fallbacks with
this file, so the copies can never drift apart silently.
"""

VERSION = "3.1.1"

# Oldest scan_backdoors.py the GUI can drive: it needs the @@PROGRESS / @@STATS
# marker lines introduced with scanner 2.1 (see build_scan_command in the GUI).
MIN_SCANNER = "2.1"
