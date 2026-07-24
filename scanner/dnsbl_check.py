#!/usr/bin/env python3
"""
SEE-Monitor: DNSBL / Reputation Check

Queries public DNS blocklists for the IP addresses behind a domain's MX hosts
and for the domain itself. This is the strongest single indicator that a domain
is *currently* compromised or abused, as opposed to merely misconfigured.

Purely passive: ordinary DNS lookups against the blocklist zones, no contact
with the assessed domain's servers.

IMPORTANT OPERATIONAL CAVEAT
----------------------------
Spamhaus (and to a lesser extent the other public mirrors) refuse queries that
arrive from public/open resolvers or from large cloud providers, and rate-limit
by querying IP. A refusal is returned in-band as a 127.255.255.x answer and is
NOT a listing. Those responses are surfaced as `blocked` and must never be
scored as a clean or a dirty result — see `status == "blocked"`. For sustained
or community-scale scanning, configure a Spamhaus Data Query Service (DQS) key
and point `dnsbl.ip_zones` at the DQS zones instead.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import ipaddress
import logging

from scanner.dns_client import DNSClient

logger = logging.getLogger(__name__)

# Public zones queried by default. Kept deliberately small: every extra zone
# multiplies query volume across a community scan.
DEFAULT_IP_ZONES = [
    "zen.spamhaus.org",     # SBL + CSS + XBL + PBL
    "bl.spamcop.net",
    "psbl.surriel.com",
]
DEFAULT_DOMAIN_ZONES = [
    "dbl.spamhaus.org",
]

# Spamhaus return codes that mean "we refused your query", not "listed".
_ERROR_PREFIXES = ("127.255.255.", "127.0.1.255")

_ZEN_CODES = {
    "127.0.0.2": "SBL — direct spam source",
    "127.0.0.3": "SBL CSS — snowshoe/low-reputation source",
    "127.0.0.4": "XBL — exploited host or open proxy",
    "127.0.0.5": "XBL — exploited host or open proxy",
    "127.0.0.6": "XBL — exploited host or open proxy",
    "127.0.0.7": "XBL — exploited host or open proxy",
    "127.0.0.9": "SBL DROP/EDROP — hijacked netblock",
    "127.0.0.10": "PBL — dynamic/end-user range, should not send mail",
    "127.0.0.11": "PBL — dynamic/end-user range, should not send mail",
}


def _reverse_ip(ip: str) -> str | None:
    """Return the DNSBL query prefix for an IPv4 or IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        return ".".join(reversed(str(addr).split(".")))
    # IPv6: reversed nibbles (same layout as ip6.arpa without the suffix)
    return ".".join(reversed(addr.exploded.replace(":", "")))


def _classify(answers: list[str], zone: str) -> tuple[str, list[str]]:
    """Map A-record answers to (status, reasons)."""
    if not answers:
        return "clean", []
    if any(a.startswith(_ERROR_PREFIXES) for a in answers):
        return "blocked", [
            f"{zone} refused the query ({', '.join(answers)}) — result unknown; "
            "use a DQS key or a dedicated resolver"]
    reasons = []
    for a in answers:
        reasons.append(f"{zone}: {_ZEN_CODES.get(a, a)}")
    return "listed", reasons


def _lookup(name: str, dc: DNSClient) -> list[str]:
    return [r.to_text() for r in dc.query(name, "A")]


def check_dnsbl(domain: str, mx_ips: list[str] | None = None,
                dns_client: DNSClient | None = None,
                ip_zones: list[str] | None = None,
                domain_zones: list[str] | None = None,
                enabled: bool = True) -> dict:
    """
    Returns:
      {
        "control": "reputation", "enabled": bool, "applicable": bool,
        "ips_checked": int, "zones": [str],
        "listings": [{"target","zone","status","reasons"}],
        "listed_ips": [str], "domain_listed": bool|None,
        "any_listed": bool, "any_blocked": bool,
        "confidence": "high"|"low", "issues": [str],
      }
    'confidence' drops to "low" when any zone refused our queries, so the
    assessor can avoid scoring an unverifiable clean result.
    """
    out = {"control": "reputation", "enabled": enabled, "applicable": False,
           "ips_checked": 0, "zones": [], "listings": [], "listed_ips": [],
           "domain_listed": None, "any_listed": False, "any_blocked": False,
           "confidence": "high", "issues": []}
    if not enabled:
        out["issues"].append("DNSBL checks disabled in configuration")
        return out

    dc = dns_client or DNSClient()
    izones = ip_zones if ip_zones is not None else DEFAULT_IP_ZONES
    dzones = domain_zones if domain_zones is not None else DEFAULT_DOMAIN_ZONES
    out["zones"] = list(izones) + list(dzones)

    ips = [ip for ip in (mx_ips or []) if ip]
    out["ips_checked"] = len(ips)
    out["applicable"] = bool(ips) or bool(dzones)

    for ip in ips:
        prefix = _reverse_ip(ip)
        if not prefix:
            continue
        for zone in izones:
            status, reasons = _classify(_lookup(f"{prefix}.{zone}", dc), zone)
            if status == "clean":
                continue
            out["listings"].append({"target": ip, "zone": zone,
                                    "status": status, "reasons": reasons})
            if status == "listed":
                out["any_listed"] = True
                if ip not in out["listed_ips"]:
                    out["listed_ips"].append(ip)
            else:
                out["any_blocked"] = True

    for zone in dzones:
        status, reasons = _classify(_lookup(f"{domain}.{zone}", dc), zone)
        if status == "clean":
            out["domain_listed"] = False if out["domain_listed"] is None \
                else out["domain_listed"]
            continue
        out["listings"].append({"target": domain, "zone": zone,
                                "status": status, "reasons": reasons})
        if status == "listed":
            out["domain_listed"] = True
            out["any_listed"] = True
        else:
            out["any_blocked"] = True

    if out["any_blocked"]:
        out["confidence"] = "low"
        out["issues"].append(
            "One or more blocklists refused our queries — reputation result is "
            "not conclusive (configure a DQS key or a dedicated resolver)")
    if out["listed_ips"]:
        out["issues"].append(
            "MX address(es) listed on a blocklist: "
            + ", ".join(out["listed_ips"]))
    if out["domain_listed"]:
        out["issues"].append(
            f"{domain} is listed on a domain blocklist (DBL)")
    for entry in out["listings"]:
        if entry["status"] == "listed":
            for reason in entry["reasons"]:
                out["issues"].append(f"{entry['target']} — {reason}")
    return out
