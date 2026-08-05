#!/usr/bin/env python3
"""
SEE-Monitor: MXToolbox Client (remote active SMTP source)

MXToolbox runs its SMTP diagnostic (RFC 3207 STARTTLS included) from its OWN
network, so it can observe a target's port-25 TLS posture even when the
SEE-Monitor host cannot egress port 25. That makes it the natural
egress-independent complement to the local active probe: when our own
connection is filtered, a positive STARTTLS observation from MXToolbox still
confirms the control.

CONDITIONS (verify against your account before trusting live output)
--------------------------------------------------------------------
  * The SMTP lookup is a *network* lookup, not a DNS lookup. Free accounts get
    DNS lookups only; network lookups require a paid plan. Quota is reported by
    the /Usage endpoint as NetworkRequests / NetworkMax.
  * Because network quota is scarce and paid, the orchestrator calls this
    source sparingly — by default only when the local active probe returns
    'unknown' for a host (mode=fallback). mode=always issues one network
    lookup per MX per scan; mode=off disables it.
  * The exact result field names ("SMTP TLS" etc.) are parsed defensively
    across all result arrays; see _parse_tls. This mapping should be confirmed
    live against a real response (scripts/check_apis.py exercises the /Usage
    endpoint; a real smtp lookup needs a paid key).

API: https://api.mxtoolbox.com/api/v1/  — key in the Authorization header.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging

import requests

logger = logging.getLogger(__name__)

_API = "https://api.mxtoolbox.com/api/v1"
_WEAK_TLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")

# Substrings that indicate a POSITIVE / NEGATIVE TLS observation in an
# MXToolbox SMTP result item (checked case-insensitively against Name+Info).
_TLS_POSITIVE = ("supports tls", "starttls", "tls is supported",
                 "connection converted to ssl", "supports ssl")
_TLS_NEGATIVE = ("does not support tls", "no tls", "tls not supported",
                 "does not support starttls")


class MXToolboxClient:
    def __init__(self, api_key: str | None, mode: str = "fallback",
                 timeout: int = 20):
        self.api_key = (api_key or "").strip()
        # off | fallback | always
        self.mode = (mode or "fallback").lower()
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_key) and self.mode != "off"

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _scan_items(data: dict, key: str):
        for item in (data.get(key) or []):
            name = (item.get("Name") or "")
            info = (item.get("Info") or "")
            yield f"{name} {info}".strip()

    @classmethod
    def _parse_tls(cls, data: dict) -> tuple:
        """Return (starttls: bool|None, tls_version: str)."""
        tls_version = ""
        positive = negative = False
        for bucket in ("Passed", "Warnings", "Failed", "Errors",
                       "Information", "Transactions"):
            for text in cls._scan_items(data, bucket):
                low = text.lower()
                if any(s in low for s in _TLS_POSITIVE):
                    positive = True
                if any(s in low for s in _TLS_NEGATIVE):
                    negative = True
                for tok in ("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1",
                            "SSLv3", "SSLv2"):
                    if tok.lower() in low:
                        tls_version = tok
                        break
        # A negative marker is more specific than a bare positive keyword hit.
        if negative and not positive:
            return False, tls_version
        if positive:
            return True, tls_version
        return None, tls_version

    # -- public API ---------------------------------------------------------
    def usage(self) -> dict:
        """Query /Usage — cheap, confirms auth and reports network quota."""
        out = {"ok": False, "network_used": None, "network_max": None,
               "error": ""}
        if not self.api_key:
            out["error"] = "no API key"
            return out
        try:
            resp = requests.get(
                f"{_API}/Usage",
                headers={"Authorization": self.api_key},
                timeout=self.timeout)
            if resp.status_code in (401, 403):
                out["error"] = "authentication failed (bad API key)"
                return out
            if resp.status_code == 429:
                out["error"] = "rate limit / quota exceeded"
                return out
            resp.raise_for_status()
            data = resp.json()
            out["ok"] = True
            out["network_used"] = data.get("NetworkRequests")
            out["network_max"] = data.get("NetworkMax")
        except Exception as exc:
            out["error"] = str(exc)
        return out

    def smtp_info(self, host: str) -> dict:
        """
        Run the MXToolbox 'smtp' network lookup against *host*.
        Returns:
          {"source": "mxtoolbox", "found": bool, "reachable": bool,
           "starttls": bool|None, "tls_version": str, "weak_tls": bool,
           "error": str}
        """
        out = {"source": "mxtoolbox", "found": False, "reachable": False,
               "starttls": None, "tls_version": "", "weak_tls": False,
               "error": ""}
        if not self.available:
            out["error"] = "mxtoolbox disabled or no API key"
            return out
        try:
            logger.info("mxtoolbox smtp lookup %s", host)
            resp = requests.get(
                f"{_API}/Lookup/smtp/",
                params={"argument": host},
                headers={"Authorization": self.api_key},
                timeout=self.timeout)
            if resp.status_code in (401, 403):
                out["error"] = "authentication failed (bad API key)"
                return out
            if resp.status_code == 429:
                out["error"] = "rate limit / network quota exceeded"
                return out
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            out["error"] = str(exc)
            logger.info("mxtoolbox smtp lookup %s failed: %s", host, exc)
            return out

        # A returned result set (even with warnings) means MXToolbox reached
        # the host. A transport failure surfaces as an Errors entry.
        errors = data.get("Errors") or []
        unreachable = any(
            "timeout" in (e.get("Info", "").lower())
            or "could not connect" in (e.get("Info", "").lower())
            or "connection refused" in (e.get("Info", "").lower())
            for e in errors)
        out["reachable"] = not unreachable
        out["found"] = bool(data)
        starttls, version = self._parse_tls(data)
        out["starttls"] = starttls
        out["tls_version"] = version
        out["weak_tls"] = version in _WEAK_TLS
        logger.info("mxtoolbox %s: starttls=%s tls=%s reachable=%s",
                    host, starttls, version or "-", out["reachable"])
        return out
