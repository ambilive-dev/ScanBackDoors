# -*- coding: utf-8 -*-
"""The GUI AI review: a local-model verdict for each suspicious file.

Black-box: the GUI is a subprocess on a private port with a private home, the
scanner is the real scanner against the synthetic site, and the "AI" is a fake
localhost HTTP server in the test process that records every request and answers
with whatever verdict the test asked for. Nothing outside 127.0.0.1 is ever
contacted.
"""

import csv
import http.server
import json
import os
import re
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402
import fixtures_sites as fx  # noqa: E402


# ---------------------------------------------------------------------------
# the fake localhost AI server
# ---------------------------------------------------------------------------
def real_verdict(prompt):
    return {"status": "real_threat", "comment": "evidence-based verdict"}


def fp_verdict(prompt):
    return {"status": "false_positive", "comment": "matches a known-safe pattern"}


def uncertain_verdict(prompt):
    return {"status": "uncertain", "comment": "not enough evidence"}


def valid_signature(prompt):
    import hashlib
    m = re.search(r"^File: (.+)$", prompt, re.M)
    rel = (m.group(1).strip() if m else "?").strip()
    tag = hashlib.sha1(rel.encode("utf-8")).hexdigest()[:8]
    return {"propose": True, "label": "AI unit test signature %s" % tag,
            "pattern": "zzz_ai_signature_marker_%s" % tag,
            "severity": "critical", "kinds": "php",
            "weight": 25, "reason": "evidence-based proposal"}


SIGNATURE_MARKER = "security analyst hardening"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.rstrip('/').endswith('/models'):
            data = json.dumps({"object": "list", "data": [{
                "id": "fake-model", "object": "model", "created": 0,
                "status": {"value": "loaded"}}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n) if n else b"{}"
            req = json.loads(body.decode("utf-8"))
            self.server.requests.append(req)
            prompt = ((req.get("messages") or [{}])[0] or {}).get("content") or ""
            if SIGNATURE_MARKER in prompt:
                content = json.dumps(self.server.signature(prompt))
            else:
                v = self.server.verdict(prompt)
                content = json.dumps({"status": v.get("status", "uncertain"),
                                      "comment": v.get("comment", "")})
            payload = {"choices": [{"message": {"content": content}}]}
            data = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as exc:  # noqa: BLE001 - report what went wrong to the test
            data = json.dumps({"error": str(exc)}).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    def log_message(self, *args):
        pass


class FakeAI(http.server.ThreadingHTTPServer):
    """One request per suspicious file, on 127.0.0.1 only."""

    def __init__(self, verdict=real_verdict):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.verdict = verdict
        self.signature = valid_signature
        self.requests = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server_address[1]

    def close(self):
        self.shutdown()
        self.server_close()


def prompt_text(req):
    return ((req.get("messages") or [{}])[0] or {}).get("content") or ""


# ---------------------------------------------------------------------------
class AiReviewTestBase(unittest.TestCase):
    """One boot + one real scan per class; each test runs its own AI review."""

    @classmethod
    def setUpClass(cls):
        cls.home = h.workdir("sbd-ai-home-")
        cls.site = fx.build("ai-site", planted=True)
        present, vanished = fx.wait_readables(cls.site, list(fx.PLANTED))
        if len(present) < 1:
            raise unittest.SkipTest(
                "only %d planted samples reached the scanner: %s" % (len(present), h.AV_HINT))
        cls.present = present
        cls.csv_path = os.path.join(cls.home, "report.csv")
        cls.fake = FakeAI()
        cls.gui = h.Gui(cls.home)
        cls.gui.start(wait=60)
        cls.gui.api("POST", "/api/settings", {"settings": {
            "site_dir": cls.site, "csv_path": cls.csv_path, "workers": "1",
            "ai_enabled": True, "ai_base_url": "http://127.0.0.1:%d/v1" % cls.fake.port,
            "ai_model": ""}})
        cls.gui.api("POST", "/api/scan/start", {"settings": {
            "site_dir": cls.site, "csv_path": cls.csv_path, "workers": "1"}})
        state = cls.gui.wait_scan(timeout=180)
        cls.scan_status = state.get("status") or ""
        assert "critical findings detected" in cls.scan_status, cls.scan_status
        cls.csv_rows_before = read_csv(cls.csv_path)

    @classmethod
    def tearDownClass(cls):
        cls.gui.stop()
        cls.fake.close()

    # -- helpers -----------------------------------------------------------
    def set_verdict(self, verdict):
        self.fake.verdict = verdict
        self.fake.requests = []

    def set_signature(self, signature):
        self.fake.signature = signature
        self.fake.requests = []

    def review(self, settings=None):
        s = {"ai_enabled": True, "ai_base_url": "http://127.0.0.1:%d/v1" % self.fake.port,
             "ai_model": ""}
        if settings:
            s.update(settings)
        self.gui.api("POST", "/api/settings", {"settings": s})
        r = self.gui.api("POST", "/api/ai/review", {})
        self.assertTrue(r.get("ok"), r)
        self.wait_ai()
        return r

    def wait_ai(self, timeout=120):
        deadline = time.time() + timeout
        last = {}
        while time.time() < deadline:
            st = self.gui.api("GET", "/api/state")
            last = st
            if not st.get("job") and "AI review" in (st.get("status") or ""):
                return st
            time.sleep(0.3)
        raise RuntimeError("the AI review did not finish in %ds (status=%r)" % (timeout, last.get("status")))

    def csv_rows(self):
        return read_csv(self.csv_path)


def read_csv(path):
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8-sig")
    return [dict(row) for row in csv.DictReader(raw.splitlines())]


# ---------------------------------------------------------------------------
class PromptContractTest(AiReviewTestBase):
    def test_the_prompt_carries_the_evidence_and_is_bounded(self):
        self.set_verdict(real_verdict)
        self.review()
        self.assertTrue(self.fake.requests, "no request reached the fake AI server")
        for req in self.fake.requests:
            prompt = prompt_text(req)
            self.assertIn("Scanner verdict:", prompt)
            self.assertIn("Findings (most important first):", prompt)
            self.assertIn("File: ", prompt)
            # bounded: snippets + metadata, never the whole file
            self.assertLess(len(prompt), 26000, "the prompt must stay bounded")
        # one request per unique file, not per row
        files_in_csv = {row.get("File", "") for row in self.csv_rows_before}
        self.assertEqual(len(self.fake.requests), len(files_in_csv))

    def test_the_request_body_is_a_chat_completion(self):
        self.set_verdict(real_verdict)
        self.review()
        req = self.fake.requests[0]
        self.assertIn("messages", req)
        self.assertEqual(req["messages"][0]["role"], "user")
        self.assertIn("temperature", req)


class PersistenceTest(AiReviewTestBase):
    def test_the_csv_gains_ai_columns_and_keeps_the_scanner_columns(self):
        self.set_verdict(real_verdict)
        self.review()
        rows = self.csv_rows()
        self.assertTrue(rows)
        self.assertIn("AI Verdict", rows[0])
        self.assertIn("AI Comment", rows[0])
        for row in rows:
            # the scanner's own columns must not be overwritten by the AI
            self.assertTrue((row.get("Verdict") or "").upper() in ("HIGH", "MEDIUM", "LOW"),
                            row.get("Verdict"))
            self.assertNotEqual((row.get("Verdict") or "").lower(), "real_threat")
            # the original Findings rows were not hidden or rewritten
            self.assertIn(row.get("Delete", ""), ("No", ""))
            self.assertEqual(row.get("AI Verdict", "").lower(), "real_threat")
            self.assertIn("evidence-based verdict", row.get("AI Comment", ""))

    def test_the_reported_findings_carry_the_ai_verdict(self):
        self.set_verdict(real_verdict)
        self.review()
        data = self.gui.api("GET", "/api/findings?ai=all")
        self.assertTrue(data["rows"])
        for row in data["rows"]:
            self.assertIsNotNone(row.get("ai"), row)
            self.assertEqual(row["ai"]["status"], "real_threat")

    def test_false_positive_verdicts_hide_the_rows(self):
        self.set_verdict(fp_verdict)
        self.review()
        all_rows = self.gui.api("GET", "/api/findings?ai=all")["rows"]
        hide_fp = self.gui.api("GET", "/api/findings?ai=hide_fp")["rows"]
        real_only = self.gui.api("GET", "/api/findings?ai=real")["rows"]
        self.assertEqual(len(all_rows), len(hide_fp) + len([r for r in all_rows if r["ai"] and r["ai"]["status"] == "false_positive"]))
        self.assertEqual(len(hide_fp), 0, "all rows are false positives")
        self.assertEqual(len(real_only), 0)

    def test_the_ai_results_survive_a_restart(self):
        self.set_verdict(real_verdict)
        self.review()
        # a fresh GUI reads the verdicts from the CSV (no review is started)
        data = self.gui.api("GET", "/api/findings?ai=all")
        statuses = {r["ai"]["status"] for r in data["rows"] if r.get("ai")}
        self.assertEqual(statuses, {"real_threat"})


class CandidatesTest(AiReviewTestBase):
    def test_candidates_are_composed_from_the_real_threat_verdicts(self):
        self.set_verdict(real_verdict)
        self.review()
        d = self.gui.api("POST", "/api/ai/candidates", {})
        self.assertGreaterEqual(len(d["candidates"]), 1)
        self.assertEqual(d["files"], len({r["File"] for r in self.csv_rows()}))
        for cand in d["candidates"]:
            self.assertTrue(cand["signature"])
            self.assertGreaterEqual(cand["count"], 1)
            self.assertTrue(cand["files"])
            for ex in cand["examples"]:
                self.assertTrue(ex["file"])
        signatures = {r.get("Signature") for r in self.csv_rows()}
        for cand in d["candidates"]:
            self.assertIn(cand["signature"], signatures)

    def test_no_real_threat_no_candidates(self):
        self.set_verdict(fp_verdict)
        self.review()
        with self.assertRaises(h.ApiError) as cm:
            self.gui.api("POST", "/api/ai/candidates", {})
        self.assertIn("real threats", str(cm.exception).lower())


class AiStatsTest(AiReviewTestBase):
    """The run-bar stats: the threats/errors counter and the candidates count.

    Black-box: the state endpoint reports the AI counts right after a review,
    and they shrink when the false positives are removed from the list."""

    def test_state_carries_counts_and_candidates_after_a_review(self):
        self.set_verdict(real_verdict)
        self.review()
        st = self.gui.api("GET", "/api/state?since=0")
        stats = st.get("ai_stats")
        self.assertIsNotNone(stats, "the state must carry the ai_stats block")
        files = {r.get("File", "") for r in self.csv_rows_before}
        self.assertGreater(len(files), 0)
        self.assertEqual(stats["reviewed"], len(files))
        self.assertEqual(stats["real_threat"], len(files))
        self.assertEqual(stats["false_positive"], 0)
        self.assertEqual(stats["error"], 0)
        self.assertGreaterEqual(stats["candidates"], 1)
        # the candidates count equals the number of groups the endpoint composes
        d = self.gui.api("POST", "/api/ai/candidates", {})
        self.assertEqual(stats["candidates"], len(d["candidates"]))

    def test_stats_drop_after_removing_false_positives(self):
        self.set_verdict(fp_verdict)
        self.review()
        st = self.gui.api("GET", "/api/state?since=0")
        stats = st.get("ai_stats")
        self.assertIsNotNone(stats)
        self.assertGreaterEqual(stats["false_positive"], 1)
        self.assertEqual(stats["false_positive"], stats["reviewed"])
        self.assertEqual(stats["real_threat"], 0)
        rows_before = self.gui.api("GET", "/api/findings?ai=all")["rows"]
        fp_rows = sum(1 for row in rows_before if row.get("ai") and row["ai"]["status"] == "false_positive")
        r = self.gui.api("POST", "/api/ai/review/remove_false_positives", {})
        self.assertEqual(r["count"], fp_rows, "the removal hides every false-positive row")
        st = self.gui.api("GET", "/api/state?since=0")
        # every row is hidden now, so there is nothing reviewed left to count
        self.assertIsNone(st.get("ai_stats"), "hidden rows must not keep the stats alive")
        # the removal persists: the rows stay in the CSV, only hidden from the list
        self.assertTrue(self.csv_rows())
        self.assertEqual(self.gui.api("GET", "/api/findings?ai=all")["rows"], [])


class ValidationTest(AiReviewTestBase):
    def test_the_endpoint_must_stay_on_localhost(self):
        self.gui.api("POST", "/api/settings", {"settings": {
            "ai_enabled": True, "ai_base_url": "http://169.254.169.254/v1"}})
        with self.assertRaises(h.ApiError) as cm:
            self.gui.api("POST", "/api/ai/review", {})
        self.assertIn("localhost", str(cm.exception).lower())
        state = self.gui.api("GET", "/api/state")
        self.assertIsNone(state.get("job"), "no job may start with a bad endpoint")

    def test_the_endpoint_must_not_carry_credentials_or_a_query(self):
        for bad in ("http://user:pass@127.0.0.1:8080/v1",
                    "http://127.0.0.1:8080/v1?token=1",
                    "http://127.0.0.1:8080/v1#frag",
                    "not-a-url", ""):
            self.gui.api("POST", "/api/settings", {"settings": {
                "ai_enabled": True, "ai_base_url": bad}})
            with self.assertRaises(h.ApiError):
                self.gui.api("POST", "/api/ai/review", {})

    def test_the_review_is_refused_when_disabled(self):
        self.gui.api("POST", "/api/settings", {"settings": {
            "ai_enabled": False,
            "ai_base_url": "http://127.0.0.1:%d/v1" % self.fake.port}})
        with self.assertRaises(h.ApiError) as cm:
            self.gui.api("POST", "/api/ai/review", {})
        self.assertIn("disabled", str(cm.exception).lower())

    def test_dry_run_plans_without_starting_or_contacting_the_ai(self):
        self.set_verdict(real_verdict)
        self.gui.api("POST", "/api/settings", {"settings": {
            "ai_enabled": True,
            "ai_base_url": "http://127.0.0.1:%d/v1" % self.fake.port}})
        self.fake.requests = []
        r = self.gui.api("POST", "/api/ai/review", {"dry_run": True})
        self.assertTrue(r["ok"])
        self.assertEqual(r["files"], len({row["File"] for row in self.csv_rows_before}))
        self.assertEqual(self.fake.requests, [])
        self.assertIsNone(self.gui.api("GET", "/api/state").get("job"))


class ErrorHandlingTest(AiReviewTestBase):
    def test_an_unreachable_endpoint_yields_error_verdicts_and_a_finishing_review(self):
        # point at a port nobody is listening on: the job must still finish
        self.set_verdict(real_verdict)
        self.gui.api("POST", "/api/settings", {"settings": {
            "ai_enabled": True, "ai_base_url": "http://127.0.0.1:1/v1"}})
        self.gui.api("POST", "/api/ai/review", {})
        state = self.wait_ai()
        self.assertIn("error", state.get("status", "").lower())
        rows = self.csv_rows()
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row.get("AI Verdict", "").lower(), "error")
        # and the candidates endpoint says there is nothing real to propose
        with self.assertRaises(h.ApiError):
            self.gui.api("POST", "/api/ai/candidates", {})


# ---------------------------------------------------------------------------
class SignatureLibraryTest(AiReviewTestBase):
    """The AI-prepared signature flow: prepare -> confirm -> library, and the
    false-positive removal that sits next to it. All black-box."""

    def setUp(self):
        # each test starts clean: no leftover library, no leftover requests
        lib = os.path.join(self.home, ".scan_backdoors_user_signatures.json")
        try:
            os.remove(lib)
        except OSError:
            pass
        self.set_verdict(real_verdict)
        self.set_signature(valid_signature)

    def _lib_path(self):
        return os.path.join(self.home, ".scan_backdoors_user_signatures.json")

    def _read_lib(self):
        with open(self._lib_path(), encoding="utf-8") as f:
            return json.load(f)

    def test_prepare_returns_one_proposal_per_real_threat_file(self):
        self.review()
        self.fake.requests = []
        d = self.gui.api("POST", "/api/ai/signatures/prepare", {})
        self.assertTrue(d["ok"])
        self.assertGreaterEqual(d["files"], 1)
        self.assertEqual(d["problems"], [])
        self.assertEqual(len(d["proposals"]), d["files"])
        for p in d["proposals"]:
            self.assertTrue(p["label"])
            self.assertTrue(p["pattern"])
            self.assertIn(p["severity"], ("critical", "obfuscated", "warning"))
            self.assertTrue(p["kinds"])
            self.assertTrue(p["file"])
        # one AI request per real-threat file, and each carries the evidence
        sig_reqs = [r for r in self.fake.requests if SIGNATURE_MARKER in prompt_text(r)]
        self.assertEqual(len(sig_reqs), d["files"])
        for req in sig_reqs:
            prompt = prompt_text(req)
            self.assertIn("File:", prompt)
            self.assertIn("Findings", prompt)
            self.assertLess(len(prompt), 30000, "the signature prompt must stay bounded")

    def test_prepare_is_refused_when_no_real_threat_was_found(self):
        self.set_verdict(fp_verdict)
        self.review()
        with self.assertRaises(h.ApiError) as cm:
            self.gui.api("POST", "/api/ai/signatures/prepare", {})
        self.assertIn("real threat", str(cm.exception).lower())

    def test_apply_writes_the_library_and_dedupes_on_a_second_apply(self):
        self.review()
        d = self.gui.api("POST", "/api/ai/signatures/prepare", {})
        r = self.gui.api("POST", "/api/ai/signatures/apply", {"signatures": d["proposals"]})
        self.assertTrue(r["ok"])
        self.assertEqual(r["added"], len(d["proposals"]))
        self.assertEqual(r["replaced"], 0)
        self.assertEqual(r["count"], len(d["proposals"]))
        self.assertEqual(r["problems"], [])
        lib = self._read_lib()
        self.assertEqual(len(lib), len(d["proposals"]))
        for entry in lib:
            self.assertTrue(entry["label"])
            self.assertTrue(entry["pattern"])
            self.assertIn(entry["severity"], ("critical", "obfuscated", "warning"))
            self.assertTrue(entry["kinds"])
            self.assertEqual(entry["flags"], "i")
            self.assertTrue(entry["created"])
        # the same proposals applied again: no duplicates, nothing added
        r2 = self.gui.api("POST", "/api/ai/signatures/apply", {"signatures": d["proposals"]})
        self.assertEqual(r2["added"], 0)
        self.assertEqual(r2["replaced"], len(d["proposals"]))
        self.assertEqual(r2["count"], len(d["proposals"]))

    def test_apply_rejects_invalid_entries_but_keeps_the_valid_ones(self):
        self.review()
        d = self.gui.api("POST", "/api/ai/signatures/prepare", {})
        valid = d["proposals"][0]
        entries = [valid,
                   {"label": "x", "pattern": "not-a-regex[", "severity": "bogus", "kinds": "bogus"},
                   {"label": "", "pattern": "", "severity": "critical", "kinds": "php"}]
        r = self.gui.api("POST", "/api/ai/signatures/apply", {"signatures": entries})
        self.assertTrue(r["ok"])
        self.assertEqual(r["added"], 1)
        self.assertEqual(len(r["problems"]), 2)
        lib = self._read_lib()
        self.assertEqual(len(lib), 1)
        self.assertEqual(lib[0]["label"], valid["label"])

    def test_apply_is_refused_without_entries(self):
        with self.assertRaises(h.ApiError):
            self.gui.api("POST", "/api/ai/signatures/apply", {"signatures": []})

    def test_remove_false_positives_hides_rows_but_keeps_them_in_the_csv(self):
        self.set_verdict(fp_verdict)
        self.review()
        before = len(self.csv_rows())
        findings_before = len(self.gui.api("GET", "/api/findings?ai=all")["rows"])
        self.assertGreater(before, 0)

        d = self.gui.api("POST", "/api/ai/review/remove_false_positives", {})
        self.assertTrue(d["ok"])
        self.assertEqual(d["count"], findings_before)
        self.assertGreater(d["count"], 0)

        # the rows are hidden from the list, not deleted
        self.assertEqual(self.gui.api("GET", "/api/findings?ai=all")["rows"], [])
        rows = self.csv_rows()
        self.assertEqual(len(rows), before)
        for row in rows:
            self.assertEqual(row.get("AI Handled", "").lower(), "false_positive")

    def test_remove_false_positives_is_refused_when_there_is_nothing_to_remove(self):
        # a previous test emptied the list; restore it with a fresh scan
        self.gui.api("POST", "/api/scan/start", {"settings": {
            "site_dir": self.site, "csv_path": self.csv_path, "workers": "1"}})
        self.gui.wait_scan(timeout=180)
        self.set_verdict(real_verdict)
        self.review()
        with self.assertRaises(h.ApiError) as cm:
            self.gui.api("POST", "/api/ai/review/remove_false_positives", {})
        self.assertIn("false positive", str(cm.exception).lower())

    def test_the_scan_passes_the_user_signature_library(self):
        os.makedirs(self.home, exist_ok=True)
        with open(self._lib_path(), "w", encoding="utf-8") as f:
            json.dump([{"label": "AI test wiring signature", "pattern": r"<\?php",
                        "severity": "critical", "kinds": "php", "flags": "i", "weight": 30}], f)
        try:
            self.gui.api("POST", "/api/scan/start", {"settings": {
                "site_dir": self.site, "csv_path": self.csv_path, "workers": "1"}})
            self.gui.wait_scan(timeout=180)
            rows = read_csv(self.csv_path)
            labels = {row.get("Signature") for row in rows}
            self.assertIn("AI test wiring signature", labels)
        finally:
            try:
                os.remove(self._lib_path())
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
