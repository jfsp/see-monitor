#!/usr/bin/env python3
"""
SEE-Monitor: SecurityTrails Client (passive DNS intelligence)

SecurityTrails is a passive-DNS database that indexes observed DNS records and
subdomains historically. Because it is *name-indexed*, it is a strong source
for two things SEE-Monitor cares about:

  * DKIM selector discovery — subdomains of the form
    '<selector>._domainkey' that were observed in the wild (including rotated
    or ESP-delegated selectors that a wordlist would miss).
  * A cross-check / fallback view of MX and other mail-related DNS records.

As with every passive source, anything gathered here is treated as *intel and
candidates only*. MX and every DKIM selector are re-confirmed against
authoritative DNS before they affect scoring; SecurityTrails data never feeds
the score directly.

If no API key is configured, all methods are safe no-ops.

API: https://api.securitytrails.com/v1/  (auth header: APIKEY)

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging

import requests

logger = logging.getLogger(__name__)

_BASE = "https://api.securitytrails.com/v1"

# Subdomain prefixes that indicate mail-related infrastructure worth surfacing.
_MAIL_PREFIXES = (
    "mail", "smtp", "mx", "imap", "pop", "webmail", "owa", "mailgun",
    "autodiscover", "autoconfig", "mta-sts", "_smtp._tls", "_dmarc",
    "email", "mailer", "newsletter",
)


def _extract_selectors(subdomains: list[str]) -> list[str]:
    """Return DKIM selectors from a list of subdomain labels."""
    out, seen = [], set()
    for sub in subdomains:
        s = (sub or "").strip().lower().strip(".")
        if "._domainkey" not in s:
            continue
        sel = s.split("._domainkey", 1)[0]
        # A selector delegated under a sub-zone (e.g. 's1._domainkey.mkt')
        # keeps only the selector label closest to _domainkey.
        sel = sel.split(".")[-1] if sel else sel
        if sel and sel not in seen:
            seen.add(sel)
            out.append(sel)
    return out


class SecurityTrailsClient:
    def __init__(self, api_key: str | None, timeout: int = 15):
        self.api_key = api_key or ""
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def _get(self, path: str, params: dict | None = None):
        try:
            resp = requests.get(
                f"{_BASE}{path}",
                headers={"APIKEY": self.api_key, "Accept": "application/json"},
                params=params or {}, timeout=self.timeout)
            if resp.status_code == 401:
                return None, "API key rejected (401)"
            if resp.status_code == 429:
                return None, "quota/rate limit exceeded (429)"
            resp.raise_for_status()
            return resp.json(), None
        except Exception as exc:
            return None, str(exc)

    # ------------------------------------------------------------------
    def get_dns(self, domain: str) -> dict:
        """
        Current DNS view from SecurityTrails.
        Returns {"mx":[{"host","priority"}], "txt":[str], "ns":[str],
                 "soa":str|None, "a":[str], "error":str|None}.
        """
        out = {"mx": [], "txt": [], "ns": [], "soa": None, "a": [],
               "error": None}
        if not self.available:
            out["error"] = "no API key"
            return out
        data, err = self._get(f"/domain/{domain}")
        if err:
            out["error"] = err
            return out
        cur = (data or {}).get("current_dns", {}) or {}
        for rec in (cur.get("mx", {}) or {}).get("values", []) or []:
            host = (rec.get("hostname") or "").strip(".").lower()
            if host:
                out["mx"].append({"host": host,
                                  "priority": rec.get("priority")})
        out["mx"].sort(key=lambda m: (m["priority"] if m["priority"]
                                      is not None else 999, m["host"]))
        for rec in (cur.get("txt", {}) or {}).get("values", []) or []:
            val = rec.get("value") or rec.get("hostname")
            if val:
                out["txt"].append(str(val).strip('"'))
        for rec in (cur.get("ns", {}) or {}).get("values", []) or []:
            host = rec.get("nameserver") or rec.get("hostname")
            if host:
                out["ns"].append(str(host).strip(".").lower())
        soa = (cur.get("soa", {}) or {}).get("values", []) or []
        if soa:
            out["soa"] = soa[0].get("email") or soa[0].get("hostname")
        for rec in (cur.get("a", {}) or {}).get("values", []) or []:
            ip = rec.get("ip")
            if ip:
                out["a"].append(ip)
        return out

    def get_subdomains(self, domain: str) -> tuple[list[str], str | None]:
        if not self.available:
            return [], "no API key"
        data, err = self._get(f"/domain/{domain}/subdomains",
                              {"children_only": "false"})
        if err:
            return [], err
        return list((data or {}).get("subdomains", []) or []), None

    def discover_selectors(self, domain: str) -> list[str]:
        """DKIM selector candidates from observed subdomains. Never raises."""
        subs, err = self.get_subdomains(domain)
        if err:
            logger.debug("SecurityTrails subdomains failed for %s: %s",
                         domain, err)
            return []
        sels = _extract_selectors(subs)
        if sels:
            logger.info("SecurityTrails surfaced %d DKIM selector(s) for %s: %s",
                        len(sels), domain, ", ".join(sels))
        return sels

    def gather(self, domain: str) -> dict:
        """
        One-shot mail-relevant intel:
        {"source":"securitytrails","available":bool,
         "mx":[{host,priority}], "txt":[str], "ns":[str],
         "selectors":[str], "mail_hosts":[str],
         "subdomain_count":int, "error":str|None}
        """
        out = {"source": "securitytrails", "available": self.available,
               "mx": [], "txt": [], "ns": [], "selectors": [],
               "mail_hosts": [], "subdomain_count": 0, "error": None}
        if not self.available:
            out["error"] = "no API key"
            return out
        dns = self.get_dns(domain)
        out["mx"], out["txt"], out["ns"] = dns["mx"], dns["txt"], dns["ns"]
        subs, sub_err = self.get_subdomains(domain)
        out["subdomain_count"] = len(subs)
        out["selectors"] = _extract_selectors(subs)
        out["mail_hosts"] = sorted(
            f"{s}.{domain}" for s in subs
            if any(s == p or s.startswith(p + ".") or s.startswith(p)
                   for p in _MAIL_PREFIXES) and "_domainkey" not in s)[:25]
        out["error"] = dns["error"] or sub_err
        return out
