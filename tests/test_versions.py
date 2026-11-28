# -*- coding: utf-8 -*-
"""TZ v2 Sprint 3: engines/versions.py - parsing, PHP-style ordering, ranges.

Everything a CVE verdict rests on is decided here, so the tests are the
specification: which strings count as a version, which do not, where a range
boundary is inclusive, and what "cannot be decided" means. The last one matters
most: a wrong True is a false positive the user reads, a wrong False is a real
vulnerability that disappears, and both are worse than an honest unknown.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

sys.path.insert(0, h.REPO)

from engines import versions as V  # noqa: E402


class ParseTest(unittest.TestCase):
    ACCEPTED = [
        "1.2.3", "1.2.3.4", "6.4.2", "0.1", "2026.01.02",
        "2.0b1", "5.3-rc2", "4.5.0-dev", "6.5-alpha-57123", "1.0a", "1.2pl1",
        "v1.2.3",                       # a leading v is a spelling, not a version
        "1.2.3 ",                       # surrounding blanks are a header artifact
    ]
    REJECTED = [
        "", "   ", "abc", "not-a-version", "1.2.3-something", "1.2.3.final",
        "1.2.3.4.5.6.7.8.9.0",          # more components than any CMS uses
        "6.4.2\n<?php system($_GET[0]);?>",   # content wearing a version's clothes
        "1.2.3; rm -rf /", "C:\\windows\\system32",
        "../../../../wp-config.php", "1.2.3\x00", "1.2\rcache",
        "1.2.3-build+5",                # a build metadata scheme we do not know
        "3.10.12/1", "1.2.3.4-rc2-1",
        "9" * 40,                       # a number, but not a version anyone ships
        None, 12, ["1.2.3"], b"\xff\xfe\x00",
    ]

    def test_accepted_versions_parse(self):
        for text in self.ACCEPTED:
            with self.subTest(version=text):
                self.assertIsNotNone(V.parse_version(text),
                                     "%r is a version real software carries" % text)

    def test_rejected_versions_stay_unknown(self):
        for text in self.REJECTED:
            with self.subTest(version=text):
                self.assertIsNone(V.parse_version(text),
                                  "%r must not be guessed into a version" % text)

    def test_bytes_are_decoded_not_guessed(self):
        self.assertIsNotNone(V.parse_version(b"6.4.2"))
        self.assertIsNone(V.parse_version(b"\xff\xfe\x01\x02"))


class CompareTest(unittest.TestCase):
    LESS = [("1.2.3", "1.2.4"), ("1.2", "1.10"), ("1.9", "1.10.1"),
            ("6.4.2", "6.4.10"), ("1.2.3.4", "1.2.4"), ("0.9", "1.0"),
            ("2.0b1", "2.0"), ("2.0-alpha", "2.0-beta"), ("1.0-rc1", "1.0-rc2"),
            ("1.0-dev", "1.0-alpha"), ("1.2rc1", "1.2.1"), ("4.4.9", "4.5.0-dev")]
    EQUAL = [("1.2", "1.2.0"), ("1.2", "v1.2.00"), ("1.2.3", "1.2.3"),
             ("2.0-rc1", "2.0rc1")]

    def test_ordering(self):
        for low, high in self.LESS:
            with self.subTest(pair=(low, high)):
                self.assertEqual(V.compare_version(low, high), -1,
                                 "%s must sort before %s (PHP version_compare semantics)" % (low, high))
                self.assertEqual(V.compare_version(high, low), 1)

    def test_padded_equalities(self):
        for a, b in self.EQUAL:
            with self.subTest(pair=(a, b)):
                self.assertEqual(V.compare_version(a, b), 0)

    def test_unknown_sides_answer_none_not_false(self):
        for a, b in (("abc", "1.2.3"), ("1.2.3", ""), (None, "1.2"), ("1.2.3", "1.2.3-x")):
            with self.subTest(pair=(a, b)):
                self.assertIsNone(V.compare_version(a, b))


class SatisfiesTest(unittest.TestCase):
    CASES = [
        ("6.4.2", "lt", "6.4.3", True), ("6.4.2", "lt", "6.4.2", False),
        ("6.4.2", "le", "6.4.2", True), ("6.4.2", "gt", "6.4.1", True),
        ("6.4.2", "ge", "6.4.2", True), ("6.4.2", "eq", "6.4.2", True),
        ("6.4.2", "ne", "6.4.3", True), ("1.2", "lt", "1.10", True),
        ("2.0-beta", "lt", "2.0", True),
        ("6.4.2", "close_to", "6.4.3", None),   # an operator we do not know
        ("6.4.2", "", "6.4.3", None),
        ("banana", "lt", "6.4.3", None),
        ("6.4.2", "lt", "banana", None),
    ]

    def test_operators(self):
        for version, op, bound, expected in self.CASES:
            with self.subTest(case=(version, op, bound)):
                self.assertIs(V.satisfies(version, op, bound), expected)

    def test_the_six_operators_are_all_here(self):
        for op in ("lt", "le", "eq", "ne", "gt", "ge"):
            self.assertIsNotNone(V.satisfies("1.0", op, "1.0"), op)


class OperatorBlockTest(unittest.TestCase):
    """The shape WPVulnerability actually answers with."""

    def test_upper_bound_only(self):
        self.assertIs(V.affected_by_operator("3.1.4", {"max_version": "3.1.5",
                                                       "max_operator": "lt"}), True)
        self.assertIs(V.affected_by_operator("3.1.5", {"max_version": "3.1.5",
                                                       "max_operator": "lt"}), False)

    def test_both_bounds(self):
        rng = {"min_version": "5.0", "min_operator": "ge",
               "max_version": "5.3", "max_operator": "lt"}
        self.assertIs(V.affected_by_operator("5.0", rng), True)     # inclusive floor
        self.assertIs(V.affected_by_operator("4.9.9", rng), False)
        self.assertIs(V.affected_by_operator("5.2.9", rng), True)
        self.assertIs(V.affected_by_operator("5.3", rng), False)    # fixed in 5.3

    def test_last_affected_spelling(self):
        rng = {"min_version": "5.0", "min_operator": "ge",
               "max_version": "5.2.9", "max_operator": "le"}
        self.assertIs(V.affected_by_operator("5.2.9", rng), True)
        self.assertIs(V.affected_by_operator("5.3", rng), False)

    def test_unfixed_without_bounds_affects_every_version(self):
        self.assertIs(V.affected_by_operator("1.0", {"min_version": None,
                                                     "max_version": None}), True)

    def test_unreadable_version_or_bound_is_unknown(self):
        self.assertIsNone(V.affected_by_operator("nightly", {"max_version": "3.1.5",
                                                             "max_operator": "lt"}))
        self.assertIsNone(V.affected_by_operator("3.1.4", {"max_version": "soon",
                                                           "max_operator": "lt"}))

    def test_a_bound_with_an_unknown_operator_is_unknown_not_false(self):
        self.assertIsNone(V.affected_by_operator("3.1.4", {"max_version": "3.1.5",
                                                           "max_operator": "before"}))
        self.assertIsNone(V.affected_by_operator("3.1.4", "not a block"))


class IsAffectedTest(unittest.TestCase):
    def test_boundaries(self):
        rng = [{"introduced": "5.0", "fixed": "5.3"}]
        self.assertIs(V.is_affected("4.9", rng), False)
        self.assertIs(V.is_affected("5.0", rng), True)      # introduced: inclusive
        self.assertIs(V.is_affected("5.2.9", rng), True)
        self.assertIs(V.is_affected("5.3", rng), False)     # fixed: exclusive

    def test_open_bounds(self):
        self.assertIs(V.is_affected("1.0", [{"introduced": None, "fixed": "2.0"}]), True)
        self.assertIs(V.is_affected("9.9", [{"introduced": "2.0", "fixed": None}]), True)
        self.assertIs(V.is_affected("1.0", [{"introduced": "2.0", "fixed": None}]), False)

    def test_last_affected(self):
        rng = [{"introduced": "1.0", "last_affected": "1.4.9"}]
        self.assertIs(V.is_affected("1.4.9", rng), True)
        self.assertIs(V.is_affected("1.5", rng), False)

    def test_several_ranges(self):
        rng = [{"introduced": "1.0", "fixed": "1.2"},
               {"introduced": "2.0", "fixed": "2.1"}]
        self.assertIs(V.is_affected("1.1", rng), True)
        self.assertIs(V.is_affected("1.5", rng), False)     # the gap between ranges
        self.assertIs(V.is_affected("2.0", rng), True)

    def test_unknown_version_and_empty_input(self):
        self.assertIsNone(V.is_affected("banana", [{"introduced": "1.0"}]))
        self.assertIsNone(V.is_affected("1.0", []))
        self.assertIsNone(V.is_affected("1.0", None))

    def test_a_broken_range_is_unknown_not_false(self):
        # A database entry we cannot read must never answer "you are not affected".
        self.assertIsNone(V.is_affected("1.0", [{"introduced": "soon"}]))
        self.assertIsNone(V.is_affected("1.0", [{"nonsense": True}]))
        self.assertIsNone(V.is_affected("1.0", ["not a range"]))
        # ... and one broken range must not hide a range that does match:
        self.assertIs(V.is_affected("1.0", [{"introduced": "0.9", "fixed": "1.5"},
                                            {"junk": 1}]), True)


class CleanVersionTest(unittest.TestCase):
    def test_useful_values_survive(self):
        self.assertEqual(V.clean_version(" 6.4.2 "), "6.4.2")
        self.assertEqual(V.clean_version("'1.2.3'"), "1.2.3")
        self.assertEqual(V.clean_version("4.4.10"), "4.4.10")

    def test_hostile_or_silly_values_become_empty(self):
        bad = ["", None, 1,
               "<script>alert(1)</script>",
               "1.2.3 || rm -rf /",
               "$(whoami)",
               "\\\\evil\\share\\x",
               "1.2.3\x1b[31m",
               "\u202e6.4.2",                    # a bidi override in a version
               "1.2.3" + "x" * 40,
               "ver\xc3\xa9sion 1.2"]
        for value in bad:
            with self.subTest(value=value):
                self.assertEqual(V.clean_version(value), "")

    def test_limit_is_respected(self):
        self.assertEqual(V.clean_version("1.2.3", limit=5), "1.2.3")
        self.assertEqual(V.clean_version("1.2.3.4.5", limit=5), "")


class SeverityTest(unittest.TestCase):
    BANDS = [(10.0, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"),
             (6.9, "medium"), (4.0, "medium"), (3.9, "low"), (0.1, "low"),
             (0.0, "none"), ("7.2", "high"), (None, "unknown"), ("", "unknown"),
             ("n/a", "unknown"), (float("nan"), "unknown")]

    def test_bands(self):
        for score, expected in self.BANDS:
            with self.subTest(score=score):
                self.assertEqual(V.cvss_severity(score), expected)

    def test_best_cvss_prefers_the_newest_block(self):
        impact = {"cvss": {"score": "5.0"}, "cvss2": {"score": "5.0"},
                  "cvss3": {"score": "7.2"}, "cvss4": {"score": "8.1"}}
        self.assertEqual(V.best_cvss(impact), 8.1)
        del impact["cvss4"]
        self.assertEqual(V.best_cvss(impact), 7.2)
        del impact["cvss3"]
        self.assertEqual(V.best_cvss(impact), 5.0)

    def test_best_cvss_handles_no_data(self):
        self.assertIsNone(V.best_cvss([]))            # what the API sends with no score
        self.assertIsNone(V.best_cvss(None))
        self.assertIsNone(V.best_cvss({"cvss3": {}}))
        self.assertIsNone(V.best_cvss({"cvss3": {"score": "nope"}}))
        self.assertEqual(V.best_cvss({"cvss3": {"score": "0.0"}}), 0.0)

    def test_sorting_puts_known_exploited_first_then_severity(self):
        rows = [{"label": "medium-kev", "sev": "medium", "kev": True, "score": 6.0},
                {"label": "critical", "sev": "critical", "kev": False, "score": 9.8},
                {"label": "high", "sev": "high", "kev": False, "score": 7.5},
                {"label": "high-old", "sev": "high", "kev": False, "score": 7.1},
                {"label": "unknown", "sev": "unknown", "kev": False, "score": None}]
        order = [r["label"] for r in sorted(
            rows, key=lambda r: V.severity_sort_key(r["sev"], r["kev"], r["score"]))]
        self.assertEqual(order, ["medium-kev", "critical", "high", "high-old", "unknown"])


if __name__ == "__main__":
    unittest.main()
