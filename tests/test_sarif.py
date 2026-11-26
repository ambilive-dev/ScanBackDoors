# -*- coding: utf-8 -*-
"""scan_backdoors.py --sarif: the SARIF 2.1.0 report is well-formed and its
results map 1:1 to the JSON report (rule = signature, level = severity).

Black-box like the rest of the suite: the scanner runs as a separate python
process; the .sarif file is read back and checked with the json module only.
"""

import json
import os
import unittest

import harness as H
import fixtures_sites as fx

LEVEL = {"[CRITICAL]": "error", "[OBFUSCATED]": "warning", "[WARNING]": "note"}


def load_sarif(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8-sig"))


class SarifTest(unittest.TestCase):
    def _scan(self, site, name):
        sarif = os.path.join(H.workdir(name), "report.sarif")
        _res, rep = H.scan(site, "--sarif", sarif)
        self.assertTrue(os.path.isfile(sarif), "the .sarif report was not created")
        return load_sarif(sarif), rep

    def test_planted_structure_and_mapping(self):
        site = fx.build("sarif-a", planted=True)
        present, _vanished = fx.wait_readables(site, list(fx.PLANTED))
        if len(present) < 3:
            raise unittest.SkipTest("too few planted samples survived: %s" % H.AV_HINT)
        doc, rep = self._scan(site, "sarif-a")

        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0", doc["$schema"])
        run = doc["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "ScanBackDoors")
        self.assertEqual(driver["version"], H.bundle_version())
        rules = {r["id"]: r for r in driver["rules"]}
        results = run["results"]
        self.assertTrue(results, "the planted site produced no SARIF results")
        art = {a["uri"] for a in run["artifacts"]}

        # The SARIF and JSON reports are written from the same in-memory results
        # in the same order, so the findings must line up one-to-one.
        json_hits = [(f["path"], h["signature"], h["line"] or None, h["severity"])
                     for f in rep.get("files", []) for h in f["hits"]]
        self.assertEqual(len(results), len(json_hits),
                         "SARIF result count %d != JSON hit count %d"
                         % (len(results), len(json_hits)))
        for res, (p, sig, line, sev) in zip(results, json_hits):
            loc = res["locations"][0]["physicalLocation"]
            self.assertEqual(loc["artifactLocation"]["uri"], p)
            self.assertEqual(res["ruleId"], sig)
            self.assertIn(res["ruleId"], rules)
            self.assertIn(loc["artifactLocation"]["uri"], art)
            self.assertEqual(loc.get("region", {}).get("startLine"), line)
            self.assertEqual(res["level"], LEVEL[sev],
                             "level %s does not match severity %s" % (res["level"], sev))
            self.assertIn(res["level"], set(LEVEL.values()))
            self.assertEqual(rules[res["ruleId"]]["defaultConfiguration"]["level"], res["level"])

    def test_clean_site_empty_results(self):
        site = fx.build("sarif-b", planted=False)
        doc, _rep = self._scan(site, "sarif-b")
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["artifacts"], [])


if __name__ == "__main__":
    unittest.main()
