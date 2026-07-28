#!/usr/bin/env python3
"""
SEE-Monitor: Censys Client (passive, alternative to Shodan)

Uses the **Censys Platform API** (api.platform.censys.io) to extract
SMTP/STARTTLS evidence for MX hosts. Authentication is a Personal Access Token
(PAT) sent as a Bearer token, with an optional organisation id. The legacy
Search API (search.censys.io, API id/secret, HTTP Basic auth) is deprecated by
Censys in September 2026 and is no longer used here.

Host lookup:   GET /v3/global/asset/host/{ip}
               Accept: application/vnd.censys.api.v3.host.v1+json
               Authorization: Bearer <PAT>
Response shape: {"result": {"resource": {"ip": ..., "services": [ ... ]}}}

As with every passive source, results are intel only and are re-confirmed
against authoritative sources before they affect scoring.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import socket

import requests

logger = logging.getLogger(__name__)

# Platform API base (reused by scripts/check_apis.py).
_API = "https://api.platform.censys.io/v3"
_HOST_PATH = "/global/asset/host/{ip}"
_HOST_ACCEPT = "application/vnd.censys.api.v3.host.v1+json"
# Quota-free Free-user credit balance endpoint — "does not cost any credits to
# execute" — used to validate a token without spending credits.
_CREDITS_PATH = "/accounts/users/credits"
_SMTP_PORTS = (25, 465, 587, 2525)


class CensysClient:
    def __init__(self, personal_access_token: str | None,
                 organization_id: str | None = None, timeout: int = 15):
        self.token = personal_access_token or ""
        self.organization_id = organization_id or ""
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.token)

    def _headers(self, accept: str) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Accept": accept}

    def _params(self) -> dict:
        # organization_id is optional; free-tier global lookups work without it,
        # but paid/org-scoped tokens require it. Only send it when configured.
        return {"organization_id": self.organization_id} \
            if self.organization_id else {}

    def host_smtp_info(self, host: str) -> dict:
        """Same shape as ShodanClient.host_smtp_info, source='censys'."""
        out = {"source": "censys", "found": False, "ip": None,
               "ports": {}, "error": ""}
        if not self.available:
            out["error"] = "no API credentials"
            return out
        try:
            ip = socket.gethostbyname(host)
            out["ip"] = ip
        except OSError as exc:
            out["error"] = f"DNS resolution failed: {exc}"
            return out
        try:
            resp = requests.get(
                _API + _HOST_PATH.format(ip=ip),
                headers=self._headers(_HOST_ACCEPT),
                params=self._params(),
                timeout=self.timeout)
            if resp.status_code == 404:
                out["error"] = "host not indexed by Censys"
                return out
            if resp.status_code in (401, 403):
                out["error"] = "Censys token rejected/insufficient access"
                return out
            if resp.status_code == 429:
                out["error"] = "Censys rate limit / quota exceeded"
                return out
            resp.raise_for_status()
            resource = (resp.json().get("result", {}) or {}).get("resource", {})
        except Exception as exc:
            out["error"] = str(exc)
            return out

        for svc in resource.get("services", []):
            port = svc.get("port")
            if port not in _SMTP_PORTS:
                continue
            entry = {"starttls": None, "tls_version": "", "cipher_suite": ""}
            tls = svc.get("tls") or {}
            ext = str(svc.get("extended_service_name")
                      or svc.get("service_name") or "").upper()
            # A TLS object (or an explicit TLS indicator in the extended service
            # name, e.g. "SMTPS"/"SMTP_TLS") means Censys negotiated TLS on this
            # SMTP port. For 25/587/2525 that is STARTTLS; port 465 is implicit
            # TLS, which we leave as None to match the Shodan client semantics.
            tls_seen = bool(tls) or "TLS" in ext or ext.endswith("SMTPS")
            if tls_seen and port != 465:
                entry["starttls"] = True

            version = (tls.get("version_selected")
                       or tls.get("version")
                       or (tls.get("handshake") or {}).get("version_selected", ""))
            if version:
                entry["tls_version"] = str(version)
            cs = (tls.get("cipher_selected")
                  or tls.get("cipher")
                  or (tls.get("handshake") or {}).get("cipher_selected", ""))
            if cs:
                entry["cipher_suite"] = str(cs)
            out["ports"][port] = entry
            out["found"] = True
        if not out["ports"]:
            out["error"] = "no SMTP service data in Censys for this host"
        return out
