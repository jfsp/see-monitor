#!/usr/bin/env python3
"""
SEE-Monitor: Censys Client (passive, alternative to Shodan)
Uses the Censys Search API v2 (/v2/hosts/{ip}) with API ID + secret
(HTTP Basic auth) to extract SMTP/STARTTLS evidence for MX hosts.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import socket

import requests

logger = logging.getLogger(__name__)

_API = "https://search.censys.io/api/v2"
_SMTP_PORTS = (25, 465, 587, 2525)


class CensysClient:
    def __init__(self, api_id: str | None, api_secret: str | None,
                 timeout: int = 15):
        self.api_id = api_id or ""
        self.api_secret = api_secret or ""
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_id and self.api_secret)

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
                f"{_API}/hosts/{ip}",
                auth=(self.api_id, self.api_secret),
                timeout=self.timeout)
            if resp.status_code == 404:
                out["error"] = "host not indexed by Censys"
                return out
            if resp.status_code == 429:
                out["error"] = "Censys rate limit / quota exceeded"
                return out
            resp.raise_for_status()
            result = resp.json().get("result", {})
        except Exception as exc:
            out["error"] = str(exc)
            return out

        for svc in result.get("services", []):
            port = svc.get("port")
            if port not in _SMTP_PORTS:
                continue
            entry = {"starttls": None, "tls_version": "", "cipher_suite": ""}
            smtp = svc.get("smtp") or {}
            if "start_tls" in smtp:
                entry["starttls"] = bool(smtp.get("start_tls"))
            tls = svc.get("tls") or {}
            hs = ((tls.get("handshake_log") or {})
                  .get("server_hello") or {}) if tls else {}
            version = (tls.get("version_selected")
                       or hs.get("selected_version", {}).get("name", ""))
            if version:
                entry["tls_version"] = str(version)
                if entry["starttls"] is None and port != 465:
                    entry["starttls"] = True
            cs = (tls.get("cipher_selected")
                  or hs.get("selected_cipher_suite", {}).get("name", ""))
            if cs:
                entry["cipher_suite"] = str(cs)
            out["ports"][port] = entry
            out["found"] = True
        if not out["ports"]:
            out["error"] = "no SMTP service data in Censys for this host"
        return out
