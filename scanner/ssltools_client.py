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
                 refresh_wait: int = 20):
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

    @classmethod
    def _report_age_days(cls, data: dict):
        raw = cls._first(data, _CREATED_KEYS)
        if not raw:
            return None
        dt = None
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            try:
                dt = parsedate_to_datetime(str(raw))
            except (TypeError, ValueError):
                dt = None
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0

    @classmethod
    def _parse(cls, data: dict) -> dict:
        """Return {report_age_days, servers:{host:{starttls,tls_version,...}}}."""
        servers = {}
        raw_list = None
        for k in _SERVER_LIST_KEYS:
            if isinstance(data.get(k), list):
                raw_list = data[k]
                break
        if raw_list is None and isinstance(data.get("mailservers"), dict):
            # some shapes nest incoming/outgoing
            raw_list = (data["mailservers"].get("incoming")
                        or data["mailservers"].get("servers"))
        for srv in (raw_list or []):
            if not isinstance(srv, dict):
                continue
            host = cls._first(srv, _HOST_KEYS)
            if not host:
                continue
            host = str(host).rstrip(".").lower()
            ver = cls._server_version(srv)
            servers[host] = {"starttls": cls._server_starttls(srv),
                             "tls_version": ver,
                             "weak_tls": ver in _WEAK_TLS}
        return {"report_age_days": cls._report_age_days(data),
                "servers": servers}

    # -- HTTP ---------------------------------------------------------------
    def _get_json(self, domain: str):
        resp = self._session.get(f"{_BASE}/{domain}",
                                 params={"format": "json"},
                                 timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def _refresh(self, domain: str) -> None:
        """Best-effort trigger of a fresh test. Tolerant of GET/redirect."""
        try:
            self._session.get(f"{_BASE}/{domain}/refresh",
                              timeout=self.timeout, allow_redirects=True)
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
        out["report_age_days"] = round(age, 1) if age is not None else None

        # Refresh if the cached report is older than the freshness window.
        if age is not None and age > self.freshness_days:
            logger.info("ssltools report for %s is %.1f days old (>%d) — "
                        "requesting refresh", domain, age, self.freshness_days)
            self._refresh(domain)
            time.sleep(min(self.refresh_wait, 20))
            try:
                data = self._get_json(domain)
                parsed = self._parse(data)
                age = parsed["report_age_days"]
                out["report_age_days"] = round(age, 1) if age is not None else None
            except Exception as exc:                   # noqa: BLE001
                logger.info("ssltools re-fetch %s failed: %s", domain, exc)

        out["stale"] = bool(age is not None and age > self.freshness_days)
        out["servers"] = parsed["servers"]
        out["found"] = bool(parsed["servers"])
        if not parsed["servers"]:
            out["error"] = out["error"] or "no server rows parsed (verify JSON schema)"
        return out
