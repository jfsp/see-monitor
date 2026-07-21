#!/usr/bin/env python3
"""
SEE-Monitor: Shodan Client (passive)
Looks up MX hosts in Shodan and extracts SMTP/STARTTLS evidence for port 25
(and 465/587 as supporting data) without touching the target.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import socket

import requests

logger = logging.getLogger(__name__)

_API = "https://api.shodan.io"
_SMTP_PORTS = (25, 465, 587, 2525)


class ShodanClient:
    def __init__(self, api_key: str | None, timeout: int = 15):
        self.api_key = api_key or ""
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def host_smtp_info(self, host: str) -> dict:
        """
        Resolve *host* and query Shodan /shodan/host/{ip}.
        Returns:
          {"source": "shodan", "found": bool, "ip": str|None,
           "ports": {port: {"starttls": bool|None, "tls_version": str,
                            "cipher_suite": str}},
           "error": str}
        """
        out = {"source": "shodan", "found": False, "ip": None,
               "ports": {}, "error": ""}
        if not self.available:
            out["error"] = "no API key"
            return out
        try:
            ip = socket.gethostbyname(host)
            out["ip"] = ip
        except OSError as exc:
            out["error"] = f"DNS resolution failed: {exc}"
            return out
        try:
            resp = requests.get(
                f"{_API}/shodan/host/{ip}",
                params={"key": self.api_key, "minify": "false"},
                timeout=self.timeout)
            if resp.status_code == 404:
                out["error"] = "host not indexed by Shodan"
                return out
            if resp.status_code == 429:
                out["error"] = "Shodan rate limit / quota exceeded"
                return out
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            out["error"] = str(exc)
            return out

        for svc in data.get("data", []):
            port = svc.get("port")
            if port not in _SMTP_PORTS:
                continue
            entry = {"starttls": None, "tls_version": "", "cipher_suite": ""}
            ssl_info = svc.get("ssl") or {}
            if ssl_info:
                # Shodan records ssl{} on SMTP banners when STARTTLS succeeded
                # (or implicit TLS on 465).
                entry["starttls"] = True if port != 465 else None
                versions = [v for v in ssl_info.get("versions", [])
                            if isinstance(v, str) and not v.startswith("-")]
                if versions:
                    entry["tls_version"] = sorted(versions)[-1]
                cipher = ssl_info.get("cipher") or {}
                entry["cipher_suite"] = cipher.get("name", "")
            else:
                banner = (svc.get("data") or "").upper()
                if port != 465 and "STARTTLS" in banner:
                    entry["starttls"] = True
            out["ports"][port] = entry
            out["found"] = True
        if not out["ports"]:
            out["error"] = "no SMTP service data in Shodan for this host"
        return out
