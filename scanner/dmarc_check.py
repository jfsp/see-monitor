#!/usr/bin/env python3
"""
SEE-Monitor: DMARC Check (RFC 7489 / NIST SP 800-177r1 §4.6)

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging

from scanner.dns_client import DNSClient

logger = logging.getLogger(__name__)

_POLICIES = ("none", "quarantine", "reject")


def _report_domain(uri: str) -> str | None:
    """Extract the domain part of a 'mailto:user@domain[!size]' DMARC URI."""
    u = uri.strip()
    if u.lower().startswith("mailto:"):
        u = u[7:]
    if "@" not in u:
        return None
    dom = u.split("@", 1)[1].split("!", 1)[0].strip().lower().rstrip(".")
    return dom or None


def _external_report_domains(uris: list[str], domain: str) -> list[str]:
    """Report destinations whose registrable domain differs from *domain*.

    Uses a suffix comparison (dest is same-org if it equals the domain or is a
    sub/parent label of it); anything else is 'external' and needs an
    authorisation record under RFC 7489 §7.1.
    """
    out: list[str] = []
    for uri in uris:
        dom = _report_domain(uri)
        if not dom:
            continue
        if dom == domain or dom.endswith("." + domain) \
                or domain.endswith("." + dom):
            continue
        if dom not in out:
            out.append(dom)
    return out


def _parse_tags(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dmarc(domain: str, dns_client: DNSClient | None = None) -> dict:
    """
    Returns:
      {
        "control": "dmarc", "present": bool, "valid": bool, "record": str|None,
        "policy": str|None, "subdomain_policy": str|None, "pct": int,
        "rua": [str], "ruf": [str], "adkim": "r"|"s", "aspf": "r"|"s",
        "issues": [str],
      }
    """
    dc = dns_client or DNSClient()
    out = {"control": "dmarc", "present": False, "valid": False,
           "record": None, "policy": None, "subdomain_policy": None,
           "pct": 100, "rua": [], "ruf": [], "adkim": "r", "aspf": "r",
           # BSI TR-03182-06 / ACN alignment + reporting signals
           "strict_alignment": False, "has_ruf": False,
           "external_rua_domains": [], "external_ruf_domains": [],
           "issues": []}

    records = [t for t in dc.txt(f"_dmarc.{domain}")
               if t.lower().replace(" ", "").startswith("v=dmarc1")]
    if not records:
        out["issues"].append("No DMARC record published")
        return out
    out["present"] = True
    if len(records) > 1:
        out["issues"].append(
            f"{len(records)} DMARC records found — receivers ignore all of them")
        out["record"] = records[0]
        return out

    record = records[0]
    out["record"] = record
    tags = _parse_tags(record)

    policy = tags.get("p", "").lower()
    if policy not in _POLICIES:
        out["issues"].append(f"Invalid or missing policy tag (p={policy!r})")
        return out
    out["valid"] = True
    out["policy"] = policy
    out["subdomain_policy"] = tags.get("sp", policy).lower()
    try:
        out["pct"] = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        out["pct"] = 100
    out["rua"] = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    out["ruf"] = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]
    out["adkim"] = tags.get("adkim", "r").lower()
    out["aspf"] = tags.get("aspf", "r").lower()
    out["strict_alignment"] = out["adkim"] == "s" and out["aspf"] == "s"
    out["has_ruf"] = bool(out["ruf"])
    out["external_rua_domains"] = _external_report_domains(out["rua"], domain)
    out["external_ruf_domains"] = _external_report_domains(out["ruf"], domain)

    if not out["strict_alignment"]:
        out["issues"].append(
            "Relaxed alignment (adkim/aspf not both 's') — BSI TR-03182-06 and "
            "ACN recommend strict alignment")
    if out["has_ruf"]:
        out["issues"].append(
            "ruf= (forensic) reporting requested — impermissible under GDPR per "
            "BSI TR-03182-08 (note: ACN recommends it — profile-dependent)")
    if out["external_rua_domains"]:
        out["issues"].append(
            "External rua destination(s) " + ", ".join(out["external_rua_domains"])
            + " require an authorisation record at "
            "<dest>._report._dmarc.<your-domain>")

    if policy == "none":
        out["issues"].append(
            "p=none is monitor-only — spoofed mail is still delivered")
    if policy != "none" and out["pct"] < 100:
        out["issues"].append(
            f"pct={out['pct']} — enforcement applies to only part of the mail flow")
    if out["subdomain_policy"] != policy and \
            _POLICIES.index(out["subdomain_policy"]) < _POLICIES.index(policy):
        out["issues"].append(
            f"Subdomain policy (sp={out['subdomain_policy']}) is weaker than p={policy}")
    if not out["rua"]:
        out["issues"].append(
            "No aggregate reporting address (rua) — no visibility of failures")
    return out
