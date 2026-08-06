#!/usr/bin/env python3
"""
SEE-Monitor: ssl-tools.net Client (remote active, per-MX)

ssl-tools.net (Digineo GmbH) runs a STARTTLS test against a domain's mail
servers from ITS OWN network and exposes the result as JSON
(`/mailservers/<domain>?format=json`). Like MXToolbox it is egress-independent
— it confirms STARTTLS even when this host cannot open port 25 outbound — but
it is free, needs no account, and returns a row per MX server.

TWO OPERATIONAL CAVEATS (both handled here)
-------------------------------------------
1. Stale-by-default. A plain GET returns a CACHED report whose age can be
   years (bde.es returned a 2020 report). This client reads the report
   timestamp and, when older than `freshness_days`, triggers the site's
   `/refresh` action and re-polls. If it cannot refresh, stale data is
   returned flagged `stale=True` and is NOT used as an authoritative active
   vote by the reconciler.
2. Undocumented JSON schema. The `?format=json` field names were not verifiable
   from the build sandbox (robots policy blocks the automated fetch there). The
   parser is deliberately tolerant of several key shapes and fails safe to
   `starttls=None`. `scripts/check_apis.py ssltools -v` dumps the parsed shape
   so the mapping can be confirmed live and tightened.

robots.txt on ssl-tools.net targets recursive crawlers (RFC 9309); this client
performs single, specific programmatic lookups of a documented JSON endpoint,
not crawling. Confirm acceptable use with Digineo before enabling in
production (config: ssltools.enabled).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import re
import time
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

logger = logging.getLogger(__name__)

_BASE = "https://ssl-tools.net/mailservers"
_WEAK_TLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1")
_UA = "SEE-Monitor/0.8 (+mail-security assessment; single-domain lookup)"

# Candidate key names for the tolerant parser (schema unverified upstream).
_SERVER_LIST_KEYS = ("servers", "mailservers", "hosts", "results", "incoming")
_HOST_KEYS = ("hostname", "host", "name", "server", "address", "fqdn")
_STARTTLS_KEYS = ("starttls", "tls", "supported", "secure", "tls_available")
_VERSION_LIST_KEYS = ("protocols", "versions", "tls_versions", "protocol_versions")
_VERSION_KEYS = ("tls_version", "protocol", "version", "highest_protocol")
_CREATED_KEYS = ("created_at", "report_created_at", "created", "checked_at",
                 "updated_at", "timestamp")


def _best_version(values) -> str:
    order = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "TLSv1",
             "SSLv3", "SSLv2"]
    found = [v for v in order if any(str(x).replace(" ", "") == v
                                     or str(x).replace(" ", "").startswith(v)
                                     for x in values)]
    return found[0] if found else ""


class SSLToolsClient:
    def __init__(self, enabled: bool = False, mode: str = "fallback",
                 freshness_days: int = 7, timeout: int = 20,
                 refresh_wait: int = 25):
        self.enabled = bool(enabled)
        self.mode = (mode or "fallback").lower()   # off | fallback | always
        self.freshness_days = int(freshness_days)
        self.timeout = int(timeout)
        self.refresh_wait = int(refresh_wait)
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": _UA,
                                      "Accept": "application/json"})

    @property
    def available(self) -> bool:
        return self.enabled and self.mode != "off"

    # -- parsing ------------------------------------------------------------
    @staticmethod
    def _first(d: dict, keys):
        for k in keys:
            if k in d and d[k] not in (None, ""):
                return d[k]
        return None

    @classmethod
    def _server_starttls(cls, srv: dict):
        raw = cls._first(srv, _STARTTLS_KEYS)
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            low = raw.strip().lower()
            if low in ("supported", "yes", "true", "ok", "available"):
                return True
            if low in ("unsupported", "no", "false", "missing", "unavailable"):
                return False
        return None

    @classmethod
    def _server_version(cls, srv: dict) -> str:
        lst = cls._first(srv, _VERSION_LIST_KEYS)
        if isinstance(lst, (list, tuple)) and lst:
            return _best_version(lst)
        v = cls._first(srv, _VERSION_KEYS)
        return str(v) if v else ""

    @staticmethod
    def _parse_ts(raw):
        s = str(raw).strip()
        for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S %Z",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        try:
            return parsedate_to_datetime(s)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _report_age_days(cls, data: dict):
        raw = cls._first(data, _CREATED_KEYS)
        if not raw:
            return None
        dt = cls._parse_ts(raw)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0

    @classmethod
    def _parse(cls, data: dict) -> dict:
        """
        Parse the (thin) ssl-tools JSON. Real shape:
          {hostname, state, created_at, hosts:[{hostname,address,preference,
           certificate:<fp>}], chains:[[{fingerprint,subject,not_before,
           not_after}, ...]]}
        The JSON carries NO starttls flag or TLS version — a presented
        certificate (host.certificate + a matching chain) is proof that a
        STARTTLS handshake succeeded, so cert-presence => starttls True.
        Absence is left as unknown (never a false no_tls).
        """
        # leaf-cert expiry by fingerprint (chain[0] is the leaf)
        cert_expiry = {}
        for chain in (data.get("chains") or []):
            if isinstance(chain, list) and chain and isinstance(chain[0], dict):
                fp = chain[0].get("fingerprint")
                if fp:
                    cert_expiry[fp] = chain[0].get("not_after")

        hosts = data.get("hosts")
        if not isinstance(hosts, list):
            for k in _SERVER_LIST_KEYS:
                if isinstance(data.get(k), list):
                    hosts = data[k]
                    break

        servers = {}
        for srv in (hosts or []):
            if not isinstance(srv, dict):
                continue
            host = cls._first(srv, _HOST_KEYS)
            if not host:
                continue
            host = str(host).rstrip(".").lower()
            cert_fp = (srv.get("certificate") or srv.get("cert")
                       or srv.get("fingerprint"))
            st = cls._server_starttls(srv)           # explicit field, if any
            if st is None and cert_fp:
                st = True                            # cert presented => STARTTLS
            ver = cls._server_version(srv)
            servers[host] = {
                "starttls": st, "tls_version": ver,
                "weak_tls": ver in _WEAK_TLS,
                "cert_not_after": cert_expiry.get(cert_fp) if cert_fp else None,
                # Fresh reports carry a per-host probe error + PFS flag. We keep
                # them for diagnostics only: cert capture is unreliable against
                # many MTAs ("unexpected EOF" even where TLS clearly works), so
                # we never infer STARTTLS from pfs/error — cert presence is the
                # only signal we trust, and its absence stays unknown.
                "error": srv.get("error") or "",
                "pfs": srv.get("pfs")}
        return {"report_age_days": cls._report_age_days(data),
                "state": (data.get("state") or "").lower(),
                "servers": servers}

    # -- HTTP ---------------------------------------------------------------
    def _get_json(self, domain: str):
        resp = self._session.get(f"{_BASE}/{domain}",
                                 params={"format": "json"},
                                 timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def _refresh(self, domain: str) -> None:
        """Trigger a fresh test. The /refresh route is a Rails POST guarded by
        CSRF (a plain GET 404s), so fetch the page for the csrf-token + session
        cookie, then POST with X-CSRF-Token. Best-effort; tolerant of failure."""
        try:
            page = self._session.get(
                f"{_BASE}/{domain}", timeout=self.timeout,
                headers={"Accept": "text/html"})
            token = None
            m = re.search(
                r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)',
                page.text)
            if m:
                token = m.group(1)
            headers = {"X-Requested-With": "XMLHttpRequest"}
            if token:
                headers["X-CSRF-Token"] = token
            r = self._session.post(f"{_BASE}/{domain}/refresh",
                                   headers=headers, timeout=self.timeout,
                                   allow_redirects=True)
            logger.info("ssltools refresh(%s) POST -> %s (csrf=%s)",
                        domain, r.status_code, "yes" if token else "no")
        except Exception as exc:                       # noqa: BLE001
            logger.info("ssltools refresh(%s) failed: %s", domain, exc)

    # -- public -------------------------------------------------------------
    def mailserver_info(self, domain: str) -> dict:
        out = {"source": "ssltools", "found": False, "stale": False,
               "report_age_days": None, "servers": {}, "raw_keys": [],
               "error": ""}
        if not self.available:
            out["error"] = "ssltools disabled"
            return out
        try:
            logger.info("ssltools lookup %s", domain)
            data = self._get_json(domain)
        except Exception as exc:                       # noqa: BLE001
            out["error"] = str(exc)
            logger.info("ssltools lookup %s failed: %s", domain, exc)
            return out

        out["raw_keys"] = sorted(data.keys()) if isinstance(data, dict) else []
        parsed = self._parse(data if isinstance(data, dict) else {})
        age = parsed["report_age_days"]
        state = parsed["state"]
        out["report_age_days"] = round(age, 1) if age is not None else None

        def _fresh(a, s):
            return (a is not None and a <= self.freshness_days
                    and (s in ("", "done")))

        # Refresh if the cached report is stale or unparseable, then poll.
        if not _fresh(age, state):
            logger.info("ssltools report for %s stale (age=%s, state=%s) — "
                        "requesting refresh", domain, out["report_age_days"],
                        state or "?")
            self._refresh(domain)
            deadline = min(self.refresh_wait, 60)
            waited = 0
            while waited < deadline:
                time.sleep(5)
                waited += 5
                try:
                    data = self._get_json(domain)
                    parsed = self._parse(data)
                    age = parsed["report_age_days"]
                    state = parsed["state"]
                    out["report_age_days"] = round(age, 1) \
                        if age is not None else None
                    if _fresh(age, state):
                        break
                except Exception as exc:               # noqa: BLE001
                    logger.info("ssltools re-fetch %s failed: %s", domain, exc)
                    break

        out["stale"] = not _fresh(age, state)
        out["servers"] = parsed["servers"]
        out["found"] = bool(parsed["servers"])
        if not parsed["servers"]:
            out["error"] = out["error"] or "no server rows parsed (verify JSON schema)"
        return out
