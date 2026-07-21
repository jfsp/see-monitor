#!/usr/bin/env python3
"""
SEE-Monitor: MX Resolver
Resolves and NORMALISES MX records for a domain. Normalisation is strict by
design: values must be bare FQDNs (priority stripped, trailing dot removed,
lowercased) and are validated before use anywhere else in the pipeline.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import re
import logging

from scanner.dns_client import DNSClient

logger = logging.getLogger(__name__)

_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)


def normalise_mx_host(value: str) -> str | None:
    """
    Turn an MX exchange value into a validated bare FQDN.
    Returns None for null-MX (".", RFC 7505) or anything that does not
    look like a hostname.
    """
    if not value:
        return None
    host = str(value).strip().rstrip(".").lower()
    # Strip a leading "<priority> " if the caller passed the full rdata text
    parts = host.split()
    if len(parts) == 2 and parts[0].isdigit():
        host = parts[1].rstrip(".")
    elif len(parts) != 1:
        return None
    if host in ("", "."):
        return None
    return host if _FQDN_RE.match(host) else None


def resolve_mx(domain: str, dns_client: DNSClient | None = None) -> dict:
    """
    Returns:
      {
        "has_mx": bool,
        "null_mx": bool,          # RFC 7505 "0 ." — domain refuses mail
        "mx_hosts": [{"host": str, "priority": int}],
        "invalid_records": [str], # raw values that failed normalisation
      }
    """
    dc = dns_client or DNSClient()
    result = {"has_mx": False, "null_mx": False,
              "mx_hosts": [], "invalid_records": []}
    records = dc.query(domain, "MX")
    for r in records:
        raw = r.exchange.to_text()
        prio = int(r.preference)
        if raw.strip() == "." and prio == 0:
            result["null_mx"] = True
            continue
        host = normalise_mx_host(raw)
        if host:
            result["mx_hosts"].append({"host": host, "priority": prio})
        else:
            result["invalid_records"].append(f"{prio} {raw}")
    result["mx_hosts"].sort(key=lambda m: (m["priority"], m["host"]))
    result["has_mx"] = bool(result["mx_hosts"])
    return result
