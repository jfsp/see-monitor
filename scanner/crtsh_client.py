#!/usr/bin/env python3
"""
SEE-Monitor: Certificate Transparency client (crt.sh)

Passive discovery of subdomain names from public CT logs. CT is a third-party
public record: querying it never touches the assessed domain.

Like every other passive source in this codebase, CT output is treated as
*candidates only* (HANDOVER invariant 1). Nothing discovered here influences a
score until it has been re-confirmed against authoritative DNS.

No API key is required and no external library is used beyond `requests`,
which the project already depends on.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import re

import requests

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
_NAME_RE = re.compile(r"^[a-z0-9_*.-]+$")


class CrtShClient:
    """Minimal crt.sh JSON client. Enabled by default; no credentials."""

    def __init__(self, enabled: bool = True, timeout: int = 20,
                 max_names: int = 500):
        self.enabled = bool(enabled)
        self.timeout = timeout
        self.max_names = max_names

    @property
    def available(self) -> bool:
        return self.enabled

    def discover_subdomains(self, domain: str) -> list[str]:
        """
        Return candidate subdomain names seen in CT logs for *domain*.
        Wildcards are stripped; the apex itself is excluded. Never raises —
        a passive source must not be able to abort a scan.
        """
        if not self.enabled:
            return []
        domain = domain.strip().lower().rstrip(".")
        try:
            resp = requests.get(
                CRTSH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=self.timeout,
                headers={"User-Agent": "see-monitor/0.6 (+passive CT lookup)"})
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.debug("crt.sh lookup failed for %s: %s", domain, exc)
            return []
        return self._extract(data, domain)

    def _extract(self, data, domain: str) -> list[str]:
        names: list[str] = []
        seen = set()
        if not isinstance(data, list):
            return []
        suffix = "." + domain
        for entry in data:
            if not isinstance(entry, dict):
                continue
            raw = entry.get("name_value") or entry.get("common_name") or ""
            for candidate in str(raw).replace(",", "\n").split("\n"):
                name = candidate.strip().lower().rstrip(".")
                if name.startswith("*."):
                    name = name[2:]
                if not name or name == domain:
                    continue
                if not name.endswith(suffix):
                    continue
                if not _NAME_RE.match(name):
                    continue
                if name not in seen:
                    seen.add(name)
                    names.append(name)
                if len(names) >= self.max_names:
                    return names
        return names
