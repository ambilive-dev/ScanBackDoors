# -*- coding: utf-8 -*-
"""The audit's only outbound calls - and everything that keeps them honest.

Two services, and nothing else:

* ``api.wordpress.org`` - the official WordPress core checksums
  (``GET /core/checksums/1.0/?version=<v>&locale=<loc>``). The answer is
  ``{"checksums": {"wp-login.php": "<md5>", ...}}``, MD5 as WordPress uses it
  internally: treat it as a catalogue key for "does this file match the official
  release", never as a cryptographic signature of authenticity. An unknown
  version answers ``{"checksums": []}`` - an empty *list*, which is why the
  reader below does not assume a dict. Omitting ``locale`` nests the answer under
  the version instead, so the locale is always sent (default ``en_US``).
  [verified 2026-11-28]
* ``api.wpvulnerability.com`` - WordPress vulnerability data by component
  (``GET /core/<version>/``, ``/plugin/<slug>/``, ``/theme/<slug>/``). Envelope
  ``{"error": 0|1, "message": ..., "data": ..., "updated": <unix>}``, HTTP 200
  even for an unknown path (then ``error: 1``), 403 for a bad key, 503 for a
  database failure. ``data.vulnerability`` is ``null`` when nothing is known.
  Version ranges come as PHP ``version_compare`` operators - they are compared
  locally with engines/versions.py, never by asking the service "is my site safe".
  [verified 2026-11-28 against the service's own OpenAPI description]

There is deliberately NO plugin or theme file-checksum service: the corresponding
``api.wordpress.org/plugins/checksums/`` and ``/themes/checksums/`` paths answer
404 [verified 2026-11-28], so component files have no official reference and the
integrity check says so instead of inventing one.

Rules this module exists to enforce:

* https only, fixed host allowlist, no credentials and no odd ports, and every
  redirect is re-checked against the same rules (a service that redirects to a
  third host must not quietly move the audit there);
* the response is hostile input: a size cap while reading, a parse inside
  try/except, and a shape check before anything is trusted;
* responses are cached in the data folder for a day, so a scan of a big site
  cannot hammer a free public service - and a second run works offline;
* a bounded number of requests per run, because "online" is a user's favour,
  not a licence to flood somebody else's API.

The caller (scan_backdoors.py) only reaches this module when the user asked for
it with ``--online``; nothing here runs by default.
"""

import hashlib
import io
import json
import os
import re
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

USER_AGENT = "ScanBackDoors-audit/1.0"
TIMEOUT = 20
MAX_JSON = 12 * 1024 * 1024            # the biggest real answer (WP 6.4 core) is ~250 KB
CACHE_TTL = 24 * 3600                  # a day: releases do not change hourly
MAX_REQUESTS_PER_RUN = 120             # politeness cap for one --online run

WORDPRESS_HOST = "api.wordpress.org"
WPVULN_HOSTS = ("api.wpvulnerability.com", "www.wpvulnerability.net")
ALLOWED_HOSTS = {WORDPRESS_HOST} | set(WPVULN_HOSTS)

SLUG_RE = re.compile(r"\A[a-z0-9][a-z0-9._+-]{0,99}\Z")
WP_VERSION_RE = re.compile(r"\A\d{1,6}(?:\.\d{1,6}){0,3}\Z")
LOCALE_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{0,20}\Z")


class AuditError(Exception):
    """The audit could not be done. Never partial-trusted: the caller reports it."""


class BudgetExhausted(AuditError):
    """The request budget of this run is spent: report, do not keep asking."""


class OfflineMode(AuditError):
    """The caller never allowed a request, and the cache had nothing.

    A separate type because it is not a failure of the service: an audit that was
    not allowed to ask reports that once, instead of once per component.
    """


# ---------------------------------------------------------------------------
# the two things that decide whether a request may be made at all
# ---------------------------------------------------------------------------

def check_url(url, allowed_hosts=None):
    """Refuse anything that is not https on an allowlisted host, port 443, no user info."""
    u = urlsplit(str(url))
    allowed = ALLOWED_HOSTS if allowed_hosts is None else allowed_hosts
    if u.scheme != "https":
        raise AuditError("only https is allowed, got %r" % (u.scheme or "no scheme"))
    if u.username or u.password:
        raise AuditError("credentials in the URL are forbidden")
    if u.port not in (None, 443):
        raise AuditError("unexpected port %s" % u.port)
    if (u.hostname or "").lower() not in allowed:
        raise AuditError("host is not on the allowlist: %s" % u.hostname)


class StrictRedirect(HTTPRedirectHandler):
    """Re-check every hop. An un-followed redirect becomes an HTTPError, which the
    caller already treats as "the audit could not be done"."""

    def __init__(self, allowed=None):
        HTTPRedirectHandler.__init__(self)
        self.allowed = allowed
        self.hops = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl, self.allowed)              # raises -> urllib surfaces an error
        self.hops.append(urlsplit(str(newurl)).hostname)
        return HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)


# ---------------------------------------------------------------------------
# what may go into a URL at all
# ---------------------------------------------------------------------------

def valid_slug(slug):
    """A WordPress plugin/theme slug, safe to put in a path segment.

    The service itself rejects a slug with a slash, but a scanner must never
    depend on the server to notice that a value read from a scanned site could
    change the path of the request. Empty, "..", spaces and anything non-ASCII:
    no request.
    """
    if not isinstance(slug, str) or ".." in slug:
        return False
    return bool(SLUG_RE.match(slug))


def valid_wp_version(version):
    """Only a plain dotted version reaches the checksums API as a query value."""
    return isinstance(version, str) and bool(WP_VERSION_RE.match(version))


def valid_locale(locale):
    return isinstance(locale, str) and bool(LOCALE_RE.match(locale))


# ---------------------------------------------------------------------------
# the client
# ---------------------------------------------------------------------------

class AuditClient(object):
    """A small JSON GET client with an allowlist, a budget and a one-day cache.

    `cache_dir` may be None (no caching, used by tests that only check URLs);
    `opener` may be replaced to test the reading rules without a network.
    """

    def __init__(self, cache_dir=None, allowed_hosts=None, budget=MAX_REQUESTS_PER_RUN,
                 timeout=TIMEOUT, max_bytes=MAX_JSON, opener=None, cache_ttl=CACHE_TTL,
                 allow_network=True):
        self.cache_dir = cache_dir
        self.allowed_hosts = ALLOWED_HOSTS if allowed_hosts is None else set(allowed_hosts)
        self.allow_network = allow_network
        self.budget = budget
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._opener = opener
        self.cache_ttl = cache_ttl
        self.requests = 0
        self.cache_hits = 0
        self.notes = []

    # -- the cache ---------------------------------------------------------
    def _cache_path(self, url):
        return os.path.join(self.cache_dir, hashlib.sha256(url.encode("utf-8")).hexdigest()
                            + ".json")

    def _cache_read(self, url):
        if not self.cache_dir:
            return None
        path = self._cache_path(url)
        try:
            with io.open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(doc, dict) or doc.get("url") != url:
            return None                    # written by another tool/version: ignore
        age = time.time() - float(doc.get("fetched_at") or 0)
        if age > self.cache_ttl:
            return None
        if "payload" not in doc:
            return None
        return doc["payload"]

    def _cache_write(self, url, payload):
        if not self.cache_dir:
            return
        try:
            if not os.path.isdir(self.cache_dir):
                os.makedirs(self.cache_dir)
            tmp = self._cache_path(url) + ".part"
            with io.open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"url": url, "fetched_at": time.time(), "payload": payload},
                          fh, ensure_ascii=False)
            os.replace(tmp, self._cache_path(url))
        except (OSError, ValueError) as exc:
            self.notes.append("audit cache is not writable: %s" % type(exc).__name__)

    # -- the request -------------------------------------------------------
    def get_json(self, url, referer_note=""):
        """GET `url` and return the parsed JSON, or raise AuditError."""
        check_url(url, self.allowed_hosts)
        cached = self._cache_read(url)
        if cached is not None:
            self.cache_hits += 1
            return cached
        if not self.allow_network:
            raise OfflineMode("offline: nothing is cached for this request and the user "
                              "did not allow one")
        if self.budget is not None and self.requests >= self.budget:
            raise BudgetExhausted("the request budget of this run (%d) is used up"
                                  % self.budget)
        self.requests += 1
        opener = self._opener or build_opener(StrictRedirect(self.allowed_hosts))
        req = Request(str(url), headers={"User-Agent": USER_AGENT,
                                         "Accept": "application/json"})
        try:
            resp = opener.open(req, timeout=self.timeout)
        except HTTPError as exc:              # a real answer with an error status
            raise AuditError("%s answered HTTP %d%s" %
                             (urlsplit(str(url)).hostname, exc.code,
                              (" for " + referer_note) if referer_note else ""))
        except OSError as exc:                # URLError, DNS, TLS, timeout: no answer
            raise AuditError("cannot reach %s: %s" % (urlsplit(str(url)).hostname, exc))
        try:
            body = self._read_capped(resp)
        finally:
            try:
                resp.close()
            except Exception:
                pass
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            raise AuditError("%s did not answer JSON" % urlsplit(str(url)).hostname)
        self._cache_write(url, payload)
        return payload

    def _read_capped(self, resp):
        """Read the body, refusing to allocate more than max_bytes."""
        chunks = []
        total = 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > self.max_bytes:
                raise AuditError("the answer is larger than %d bytes: refused"
                                 % self.max_bytes)
            chunks.append(chunk)
        return b"".join(chunks)


# ---------------------------------------------------------------------------
# the two endpoints
# ---------------------------------------------------------------------------

def checksums_url(version, locale="en_US"):
    if not valid_wp_version(version):
        raise AuditError("not a WordPress version to ask about: %r" % (version,))
    if not valid_locale(locale):
        locale = "en_US"
    return ("https://%s/core/checksums/1.0/?version=%s&locale=%s"
            % (WORDPRESS_HOST, quote(version, safe=""), quote(locale, safe="")))


def parse_checksums(payload):
    """The checksums answer -> {site-relative path: md5}.

    Shapes seen: a dict of path -> 32 hex; an empty list for an unknown version;
    and, when no locale was sent, a dict keyed by version. Anything else is an
    error, because "no data" and "unparsable data" must not look the same.
    """
    if not isinstance(payload, dict) or "checksums" not in payload:
        raise AuditError("the checksums answer has an unexpected shape")
    data = payload["checksums"]
    if isinstance(data, dict) and len(data) == 1:
        only = list(data.keys())[0]
        if valid_wp_version(only) and isinstance(data[only], dict):
            data = data[only]              # the answer without a locale
    if isinstance(data, (list, tuple)):
        if not data:
            return {}
        raise AuditError("the checksums answer is a list, not a catalogue")
    if not isinstance(data, dict):
        raise AuditError("the checksums answer has an unexpected shape")
    out = {}
    for path, digest in data.items():
        if not isinstance(path, str) or not isinstance(digest, str):
            continue
        if len(digest) != 32 or any(c not in "0123456789abcdef" for c in digest.lower()):
            continue                      # a future sha256 answer: skipped, not guessed
        raw = path.replace("\\", "/")
        clean = raw.lstrip("/")
        parts = [p for p in clean.split("/") if p not in ("", ".")]
        if raw.startswith("/") or ".." in parts or not parts:
            continue                      # not a site-relative path: not a core file
        if any(("\x00" in p or p in ("", ".")) for p in parts):
            continue
        out["/".join(parts)] = digest.lower()
    return out


def core_checksums(client, version, locale="en_US"):
    return parse_checksums(client.get_json(checksums_url(version, locale), "core checksums"))


def wpvuln_url(kind, identifier, host=WPVULN_HOSTS[0]):
    """The component endpoint. The kind is one of ours, never a caller's string."""
    if host not in WPVULN_HOSTS:
        raise AuditError("host is not on the allowlist: %s" % host)
    if kind == "core":
        if not valid_wp_version(identifier):
            raise AuditError("not a WordPress version: %r" % (identifier,))
        return "https://%s/core/%s/" % (host, quote(identifier, safe=""))
    if kind in ("plugin", "theme"):
        if not valid_slug(identifier):
            raise AuditError("not a %s slug to ask about: %r" % (kind, identifier))
        return "https://%s/%s/%s/" % (host, kind, quote(identifier, safe=""))
    raise AuditError("unknown component kind %r" % (kind,))


def parse_wpvuln(payload):
    """The envelope -> the list of vulnerability entries ([] when nothing known).

    `error: 1` (an unknown path or a database problem) is an AuditError: treating
    "the service did not answer about this component" as "this component is fine"
    is the one mistake an auditor is not allowed to make.
    """
    if not isinstance(payload, dict) or "error" not in payload:
        raise AuditError("the WPVulnerability answer has an unexpected shape")
    if payload.get("error") not in (0, "0", False):
        raise AuditError("WPVulnerability refused the request: %s"
                         % (payload.get("message") or "no reason given"))
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    vulns = data.get("vulnerability")
    if vulns in (None, ""):
        return []
    if not isinstance(vulns, list):
        raise AuditError("WPVulnerability sent something that is not a list of entries")
    return [v for v in vulns if isinstance(v, dict)]
