# -*- coding: utf-8 -*-
"""Detection engines for ScanBackDoors (TZ v2, section 6).

base_engine.py is mandatory and uses the standard library only: the scanner
imports it unconditionally. An engine with a third-party dependency (YARA)
lives in this package too, but MUST import that dependency lazily inside its
builder, so importing the module stays safe when the dependency is absent
(the engine then reports itself unavailable and the scan proceeds without it).
"""
