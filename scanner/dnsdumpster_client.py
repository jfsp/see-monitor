#!/usr/bin/env python3
"""
SEE-Monitor: DNSDumpster Client (passive selector discovery)

DKIM selectors cannot be enumerated from DNS. When a DNSDumpster API key is
configured, this client queries DNSDumpster for a domain and harvests any
observed '<selector>._domainkey.<domain>' names (many ESPs, notably Microsoft
365, publish DKIM keys as CNAMEs that appear in host inventories). The
extracted selectors are fed to the DKIM check purely as *candidates* — every
candidate is still confirmed with an authoritative TXT lookup before it can
affect scoring. DNSDumpster data is never trusted for scoring directly.

If no API key is set, discovery is a no-op and the DKIM check falls back to the
common-selector wordlist plus any per-domain registered selectors.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import re

import requests

logger = logging.getLogger(__name__)

_API_URL = "https://api.dnsdumpster.com/domain/{domain}"


def _walk_strings(obj):
    """Yield every string found anywhere in a nested JSON structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _walk_strings(v)


def extract_selectors(payload, domain: str) -> list[str]:
    """
    Pull DKIM selectors out of an arbitrary DNSDumpster response.

    A selector is captured only from names that end in
    '._domainkey.<domain>' — this deliberately ignores CNAME *targets*
    (e.g. an M365 key host under onmicrosoft.com), which would otherwise
    yield the wrong selector.
    """
    domain = domain.strip(".").lower()
    pattern = re.compile(
        rf"(?:^|[\s\"'=,;])([a-z0-9][a-z0-9._-]*)\._domainkey\."
        rf"{re.escape(domain)}(?:\.|$|[\s\"'=,;])")
    found: list[str] = []
    seen = set()
    for s in _walk_strings(payload):
        for m in pattern.finditer(s.lower()):
            sel = m.group(1).strip(".")
            if sel and sel not in seen:
                seen.add(sel)
                found.append(sel)
    return found


class DNSDumpsterClient:
    def __init__(self, api_key: str | None, timeout: int = 15):
        self.api_key = api_key or ""
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def query(self, domain: str) -> dict | None:
        """Raw DNSDumpster response for *domain*, or None on any failure."""
        if not self.available:
            return None
        try:
            resp = requests.get(
                _API_URL.format(domain=domain),
                headers={"X-API-Key": self.api_key,
                         "Accept": "application/json"},
                timeout=self.timeout)
            if resp.status_code == 401:
                logger.warning("DNSDumpster API key rejected (401)")
                return None
            if resp.status_code == 429:
                logger.warning("DNSDumpster quota/rate limit exceeded (429)")
                return None
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.debug("DNSDumpster query failed for %s: %s", domain, exc)
            return None

    def discover_selectors(self, domain: str) -> list[str]:
        """
        Return DKIM selector candidates observed by DNSDumpster for *domain*.
        Never raises; returns [] when unavailable or on any error.
        """
        payload = self.query(domain)
        if payload is None:
            return []
        selectors = extract_selectors(payload, domain)
        if selectors:
            logger.info("DNSDumpster surfaced %d DKIM selector(s) for %s: %s",
                        len(selectors), domain, ", ".join(selectors))
        return selectors
