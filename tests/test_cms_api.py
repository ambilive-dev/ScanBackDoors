# -*- coding: utf-8 -*-
"""TZ v2 Sprint 3: engines/cms_api.py - the audit's network layer.

No test in this file opens a socket: the client is exercised through a fake
opener, and the real `build_opener` is replaced by a trap for the whole module,
so a mistake (a client built without an opener that then reaches the network)
fails the suite instead of sending a site's plugin list to somebody's server.
"""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

sys.path.insert(0, h.REPO)

from engines import cms_api as api  # noqa: E402


class FakeResponse(object):
    def __init__(self, body):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        self.closed = False

    def read(self, size):
        chunk, self.body = self.body[:size], self.body[size:]
        return chunk

    def close(self):
        self.closed = True


class FakeOpener(object):
    """Stands in for urllib's opener: records the URLs it was asked for."""

    def __init__(self, payloads=None, error=None, chunker=None):
        self.payloads = payloads or {}
        self.error = error
        self.calls = []
        self.requests = []

    def open(self, req, timeout=None):
        url = getattr(req, "full_url", None) or str(req)
        self.calls.append(url)
        self.requests.append(req)
        if self.error:
            raise self.error
        for prefix, payload in self.payloads.items():
            if url.startswith(prefix):
                return FakeResponse(payload)
        raise AssertionError("the fake opener was not told about %s" % url)


class NoNetworkCase(unittest.TestCase):
    """The trap: anything that tries to build a real opener is a failing test."""

    def setUp(self):
        self._real = api.build_opener
        api.build_opener = lambda *a, **kw: self.fail(
            "a test tried to reach the network")

    def tearDown(self):
        api.build_opener = self._real


class UrlRulesTest(NoNetworkCase):
    def test_https_only(self):
        for url in ("http://api.wordpress.org/core/checksums/1.0/?version=6.4.2",
                    "ftp://api.wordpress.org/x", "//api.wordpress.org/x", ""):
            with self.subTest(url=url):
                self.assertRaises(api.AuditError, api.check_url, url)

    def test_foreign_host_is_refused(self):
        for url in ("https://evil.example/core/checksums/",
                    "https://api.wordpress.org.evil.example/x",
                    "https://localhost/x",
                    "https://127.0.0.1/x"):
            with self.subTest(url=url):
                self.assertRaises(api.AuditError, api.check_url, url)

    def test_credentials_and_ports_are_refused(self):
        self.assertRaises(api.AuditError, api.check_url, "https://u:p@api.wordpress.org/x")
        self.assertRaises(api.AuditError, api.check_url, "https://api.wordpress.org:8443/x")

    def test_the_two_services_are_allowed(self):
        api.check_url("https://api.wordpress.org/core/checksums/1.0/?version=6.4.2&locale=en_US")
        api.check_url("https://api.wpvulnerability.com/plugin/akismet/")
        api.check_url("https://www.wpvulnerability.net/theme/twentytwentyfour/")

    def test_a_redirect_is_rechecked(self):
        handler = api.StrictRedirect(api.ALLOWED_HOSTS)
        self.assertRaises(api.AuditError, handler.redirect_request,
                          None, None, 302, "Found", {},
                          "http://api.wordpress.org/core/checksums/1.0/")
        self.assertRaises(api.AuditError, handler.redirect_request,
                          None, None, 302, "Found", {},
                          "https://cdn.evil.example/x.json")


class InputValidationTest(unittest.TestCase):
    def test_slugs(self):
        for slug in ("akismet", "hello-dolly", "wpseo.1", "a+b", "twentytwentyfour"):
            self.assertTrue(api.valid_slug(slug), slug)
        for slug in ("", "A", ".hidden", "..", "../evil", "a/b", "a\\b", " with space",
                     "a?b", "a#b", "a\nb", u"\u043f\u043b\u0430\u0433\u0438\u043d", "x" * 101,
                     None, 12):
            with self.subTest(slug=slug):
                self.assertFalse(api.valid_slug(slug))

    def test_versions(self):
        for version in ("6.4.2", "6.4", "4.9.6", "6"):
            self.assertTrue(api.valid_wp_version(version), version)
        for version in ("", "6.4.2'", "6.4.2&locale=xx", "nightly", "-1", "6.4.2.1.1",
                        None, 6.4):
            with self.subTest(version=version):
                self.assertFalse(api.valid_wp_version(version))

    def test_urls_are_built_not_concatenated(self):
        self.assertEqual(api.checksums_url("6.4.2"),
                         "https://api.wordpress.org/core/checksums/1.0/?version=6.4.2&locale=en_US")
        self.assertEqual(api.wpvuln_url("plugin", "akismet"),
                         "https://api.wpvulnerability.com/plugin/akismet/")
        self.assertEqual(api.wpvuln_url("core", "6.4.2"),
                         "https://api.wpvulnerability.com/core/6.4.2/")
        for bad in ("../../etc/passwd", "a/b", "", None):
            self.assertRaises(api.AuditError, api.wpvuln_url, "plugin", bad)
        self.assertRaises(api.AuditError, api.wpvuln_url, "core", "6.4.2 or 1=1")
        self.assertRaises(api.AuditError, api.wpvuln_url, "everything", "x")
        self.assertRaises(api.AuditError, api.wpvuln_url, "plugin", "x",
                          host="evil.example")

    def test_a_suspicious_locale_falls_back(self):
        url = api.checksums_url("6.4.2", locale="de_DE; DROP TABLE")
        self.assertIn("locale=en_US", url)


class ChecksumsShapeTest(unittest.TestCase):
    def test_the_normal_answer(self):
        got = api.parse_checksums({"checksums": {"wp-login.php": "a" * 32,
                                                 "wp-includes/x.php": "b" * 32}})
        self.assertEqual(sorted(got), ["wp-includes/x.php", "wp-login.php"])
        self.assertEqual(got["wp-login.php"], "a" * 32)

    def test_unknown_version_answers_an_empty_list(self):
        self.assertEqual(api.parse_checksums({"checksums": []}), {})

    def test_the_answer_without_a_locale_is_nested_by_version(self):
        got = api.parse_checksums({"checksums": {"6.4.2": {"index.php": "c" * 32}}})
        self.assertEqual(got, {"index.php": "c" * 32})

    def test_a_non_md5_digest_is_skipped_not_guessed(self):
        got = api.parse_checksums({"checksums": {"a.php": "c" * 64, "b.php": "d" * 32,
                                                 "c.php": "nope"}})
        self.assertEqual(list(got), ["b.php"])

    def test_a_path_that_leaves_the_site_is_dropped(self):
        got = api.parse_checksums({"checksums": {"../../etc/passwd": "a" * 32,
                                                 "/etc/shadow": "b" * 32,
                                                 "wp-admin\\..\\..\\x": "c" * 32,
                                                 "ok.php": "d" * 32}})
        self.assertEqual(list(got), ["ok.php"])

    def test_garbage_is_an_error_not_an_empty_catalogue(self):
        for payload in (None, [], {}, {"checksum": {}}, {"checksums": "nonsense"},
                        {"checksums": ["one", "two"]}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertRaises(api.AuditError, api.parse_checksums, payload)


class WpvulnEnvelopeTest(unittest.TestCase):
    def test_the_normal_answer(self):
        got = api.parse_wpvuln({"error": 0, "message": None, "updated": "1776963060",
                                "data": {"core": "6.4.2",
                                         "vulnerability": [{"uuid": "x"}, {"uuid": "y"}]}})
        self.assertEqual(len(got), 2)

    def test_nothing_known_is_an_empty_list_not_an_error(self):
        self.assertEqual(api.parse_wpvuln({"error": 0, "data": {"name": None, "plugin": "x",
                                                                "vulnerability": None}}), [])
        self.assertEqual(api.parse_wpvuln({"error": 0, "data": None}), [])

    def test_refused_is_refused(self):
        with self.assertRaises(api.AuditError):
            api.parse_wpvuln({"error": 1, "message": "Nothing here.", "data": None})

    def test_wrong_shape(self):
        for payload in (None, [], {}, {"data": {}},
                        {"error": 0, "data": {"vulnerability": "nope"}}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertRaises(api.AuditError, api.parse_wpvuln, payload)


class ClientTest(NoNetworkCase):
    def test_a_request_carries_our_user_agent_and_no_secrets(self):
        opener = FakeOpener({"https://api.wpvulnerability.com/plugin/akismet/":
                             {"error": 0, "data": {"vulnerability": []}}})
        client = api.AuditClient(opener=opener)
        got = client.get_json("https://api.wpvulnerability.com/plugin/akismet/")
        self.assertEqual(got["error"], 0)
        request = opener.requests[0]
        self.assertEqual(request.get_header("User-agent"), api.USER_AGENT)
        self.assertEqual(client.requests, 1)

    def test_a_foreign_url_is_refused_before_anything_is_opened(self):
        opener = FakeOpener({"https://evil.example/": {}})
        client = api.AuditClient(opener=opener)
        self.assertRaises(api.AuditError, client.get_json, "https://evil.example/akismet")
        self.assertEqual(opener.calls, [], "the request was built before the host was checked")

    def test_an_oversized_answer_is_refused(self):
        opener = FakeOpener({"https://api.wordpress.org/": {"checksums": {"a": "x" * 4000000}}})
        client = api.AuditClient(opener=opener, max_bytes=4096)
        self.assertRaises(api.AuditError, client.get_json, "https://api.wordpress.org/x")

    def test_non_json_is_an_error(self):
        opener = FakeOpener({"https://api.wordpress.org/":
                             b"<html><body>502 Bad Gateway</body></html>"})
        client = api.AuditClient(opener=opener)
        self.assertRaises(api.AuditError, client.get_json, "https://api.wordpress.org/x")

    def test_an_http_error_becomes_an_audit_error(self):
        from urllib.error import HTTPError, URLError
        opener = FakeOpener({}, error=HTTPError("https://api.wpvulnerability.com/x",
                                                503, "Service Unavailable", None, None))
        client = api.AuditClient(opener=opener)
        with self.assertRaises(api.AuditError) as got:
            client.get_json("https://api.wpvulnerability.com/plugin/akismet/")
        self.assertIn("503", str(got.exception))
        opener = FakeOpener({}, error=URLError("name or service not known"))
        client = api.AuditClient(opener=opener)
        with self.assertRaises(api.AuditError) as got:
            client.get_json("https://api.wpvulnerability.com/plugin/akismet/")
        self.assertIn("cannot reach", str(got.exception))

    def test_the_request_budget_is_enforced(self):
        opener = FakeOpener({"https://api.wpvulnerability.com/": {"error": 0, "data": None}})
        client = api.AuditClient(opener=opener, budget=3)
        for i in range(3):
            client.get_json("https://api.wpvulnerability.com/plugin/p%d/" % i)
        self.assertRaises(api.BudgetExhausted, client.get_json,
                          "https://api.wpvulnerability.com/plugin/p99/")
        self.assertEqual(len(opener.calls), 3, "the budget stopped the requests")

    def test_a_client_without_permission_uses_the_cache_and_never_the_network(self):
        cache = h.workdir("audit-cache-")
        opener = FakeOpener({"https://api.wordpress.org/": {"error": 0, "data": None}})
        allowed = api.AuditClient(cache_dir=cache, opener=opener)
        allowed.get_json("https://api.wordpress.org/x")            # fills the cache
        strict = api.AuditClient(cache_dir=cache, opener=opener, allow_network=False)
        got = strict.get_json("https://api.wordpress.org/x")       # from the cache
        self.assertEqual(got["error"], 0)
        self.assertRaises(api.AuditError, strict.get_json, "https://api.wordpress.org/other")
        self.assertEqual(len(opener.calls), 1, "the second client made no request")


class CacheTest(NoNetworkCase):
    def setUp(self):
        NoNetworkCase.setUp(self)
        self.cache = h.workdir("audit-cache-")

    def _client(self, body, **kw):
        opener = FakeOpener({"https://api.wordpress.org/": body})
        return api.AuditClient(cache_dir=self.cache, opener=opener, **kw), opener

    def test_a_second_call_comes_from_the_cache(self):
        client, opener = self._client({"error": 0, "data": None})
        client.get_json("https://api.wordpress.org/x?a=1")
        client.get_json("https://api.wordpress.org/x?a=1")
        self.assertEqual(len(opener.calls), 1, "the second call must be answered from the cache")
        self.assertEqual(client.cache_hits, 1)
        self.assertEqual(len(os.listdir(self.cache)), 1)

    def test_an_expired_entry_is_fetched_again(self):
        client, opener = self._client({"error": 0, "data": None}, cache_ttl=3600)
        client.get_json("https://api.wordpress.org/x")
        path = os.path.join(self.cache, os.listdir(self.cache)[0])
        with io.open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["fetched_at"] -= 7200                       # pretend it is two days old
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        client.get_json("https://api.wordpress.org/x")
        self.assertEqual(len(opener.calls), 2)

    def test_a_cache_file_that_does_not_match_the_url_is_ignored(self):
        client, opener = self._client({"error": 0, "data": None})
        client.get_json("https://api.wordpress.org/x")
        path = os.path.join(self.cache, os.listdir(self.cache)[0])
        with io.open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["url"] = "https://api.wordpress.org/other"
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        client.get_json("https://api.wordpress.org/x")
        self.assertEqual(len(opener.calls), 2)

    def test_a_poisoned_cache_file_does_not_crash_the_run(self):
        with io.open(os.path.join(self.cache, "deadbeef.json"), "w", encoding="utf-8") as fh:
            fh.write("{ this is not json")
        client, opener = self._client({"error": 0, "data": None})
        client.get_json("https://api.wordpress.org/x")
        self.assertEqual(len(opener.calls), 1)

    def test_a_cache_directory_that_cannot_be_written_is_a_note_not_a_failure(self):
        blocker = os.path.join(self.cache, "blocker")
        with io.open(blocker, "w", encoding="utf-8") as fh:
            fh.write("a file where a folder will be needed")
        opener = FakeOpener({"https://api.wordpress.org/": {"error": 0, "data": None}})
        client = api.AuditClient(cache_dir=os.path.join(blocker, "sub"), opener=opener)
        got = client.get_json("https://api.wordpress.org/x")     # must not raise
        self.assertEqual(got["error"], 0)
        self.assertTrue(any("cache" in note for note in client.notes),
                        "an audit that cannot keep its cache says so: %r" % client.notes)


if __name__ == "__main__":
    unittest.main()
