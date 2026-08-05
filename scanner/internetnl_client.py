#!/usr/bin/env python3
"""
SEE-Monitor: Internet.nl Batch API v2 Client (remote active, domain-level)

Internet.nl runs the NCSC-aligned mail test (STARTTLS, DANE, DNSSEC, SPF/DKIM/
DMARC, RPKI) from its own infrastructure, so it is egress-independent. It is a
free, government-backed (Dutch Internet Standards Platform), open-source
service. Access requires an approved account (HTTP Basic auth); central banks /
public bodies qualify (non-profit + NIS2 high-criticality). Attribution is
requested when re-surfacing results.

BATCH, NOT PER-HOST. The API is asynchronous: submit a batch of domains, poll
until done, then fetch results. Batches are FIFO per user and share resources,
so completion takes minutes. SEE-Monitor therefore consumes this via a
SCHEDULED batch that caches per-domain STARTTLS/DANE verdicts (see
scheduler.internetnl_batch); the scanner reads that cache at scan time. This
client only speaks to the API; caching/scheduling live elsewhere.

Flow (v2, https://batch.internet.nl/api/batch/v2/):
  POST requests                {"type":"mail","domains":[...],"name":...}
  GET  requests/{id}           -> status: registering|running|generating|done
  GET  requests/{id}/results   -> per-domain test verdicts

Result field names below (mail_starttls_tls_available, mail_starttls_dane_*)
follow the documented test identifiers, but the exact results envelope was not
verifiable without an account from the build sandbox. The parser is tolerant
and fails safe; confirm live once the account is approved
(scripts/check_apis.py internetnl).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import time
import logging

import requests

logger = logging.getLogger(__name__)

_DEFAULT_BASE = "https://batch.internet.nl/api/batch/v2"
_DONE = "done"
_ERROR_STATES = ("error", "cancelled", "failed")

# Test identifiers we map to a STARTTLS verdict / DANE signal.
_STARTTLS_TEST = "mail_starttls_tls_available"
_DANE_TESTS = ("mail_starttls_dane_valid", "mail_starttls_dane_exist")
_PASS = ("passed", "pass", "good", "ok")
_FAIL = ("failed", "fail", "bad", "insufficient")


class InternetNLClient:
    def __init__(self, username: str | None, password: str | None,
                 base_url: str = _DEFAULT_BASE, timeout: int = 30):
        self.username = (username or "").strip()
        self.password = (password or "").strip()
        self.base_url = (base_url or _DEFAULT_BASE).rstrip("/")
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.username and self.password)

    def _auth(self):
        return (self.username, self.password)

    # -- API calls ----------------------------------------------------------
    def submit(self, domains, name: str) -> dict:
        """POST a mail batch. Returns {"request_id": str, "error": str}."""
        out = {"request_id": None, "error": ""}
        if not self.available:
            out["error"] = "no credentials"
            return out
        try:
            resp = requests.post(
                f"{self.base_url}/requests", auth=self._auth(),
                json={"type": "mail", "name": name, "domains": list(domains)},
                timeout=self.timeout)
            if resp.status_code in (401, 403):
                out["error"] = "authentication failed"
                return out
            resp.raise_for_status()
            data = resp.json()
            req = data.get("request", data)
            out["request_id"] = req.get("request_id") or req.get("id")
            if not out["request_id"]:
                out["error"] = "no request_id in response"
        except Exception as exc:                       # noqa: BLE001
            out["error"] = str(exc)
        return out

    def status(self, request_id: str) -> dict:
        out = {"status": None, "error": ""}
        try:
            resp = requests.get(f"{self.base_url}/requests/{request_id}",
                                auth=self._auth(), timeout=self.timeout)
            resp.raise_for_status()
            req = resp.json().get("request", {})
            out["status"] = (req.get("status") or "").lower()
        except Exception as exc:                       # noqa: BLE001
            out["error"] = str(exc)
        return out

    def results(self, request_id: str) -> dict:
        """GET results and map to {domain: {starttls, dane, tls_version}}."""
        out = {"domains": {}, "error": ""}
        try:
            resp = requests.get(
                f"{self.base_url}/requests/{request_id}/results",
                auth=self._auth(), timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:                       # noqa: BLE001
            out["error"] = str(exc)
            return out
        domains = data.get("domains", data.get("results", {})) or {}
        for domain, entry in domains.items():
            out["domains"][domain] = self._map_domain(entry)
        return out

    # -- mapping ------------------------------------------------------------
    @staticmethod
    def _test_status(tests: dict, name: str):
        t = tests.get(name)
        if not isinstance(t, dict):
            return None
        st = (t.get("status") or t.get("verdict") or "").lower()
        if any(p in st for p in _PASS):
            return True
        if any(f in st for f in _FAIL):
            return False
        return None

    @classmethod
    def _map_domain(cls, entry: dict) -> dict:
        res = entry.get("results", entry) if isinstance(entry, dict) else {}
        tests = res.get("tests", res.get("custom", res)) or {}
        if not isinstance(tests, dict):
            tests = {}
        st = cls._test_status(tests, _STARTTLS_TEST)
        starttls = "ok" if st is True else "no_tls" if st is False else None
        dane = None
        for dt in _DANE_TESTS:
            d = cls._test_status(tests, dt)
            if d is not None:
                dane = "ok" if d else "no"
                break
        return {"starttls": starttls, "dane": dane, "tls_version": ""}

    # -- convenience: submit, poll to completion, return results ------------
    def run_batch(self, domains, name: str, poll_interval: int = 30,
                  max_wait: int = 3600) -> dict:
        """Blocking helper for the scheduled job (NOT for per-scan use)."""
        sub = self.submit(domains, name)
        if sub["error"]:
            return {"domains": {}, "error": sub["error"], "request_id": None}
        rid = sub["request_id"]
        waited = 0
        while waited < max_wait:
            time.sleep(poll_interval)
            waited += poll_interval
            stt = self.status(rid)
            state = stt["status"]
            if state == _DONE:
                r = self.results(rid)
                r["request_id"] = rid
                return r
            if state in _ERROR_STATES:
                return {"domains": {}, "error": f"batch {state}",
                        "request_id": rid}
            logger.info("internetnl batch %s: %s (%ds)", rid, state, waited)
        return {"domains": {}, "error": "batch timed out", "request_id": rid}
