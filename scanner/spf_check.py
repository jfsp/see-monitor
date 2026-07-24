#!/usr/bin/env python3
"""
SEE-Monitor: SPF Check (RFC 7208 / NIST SP 800-177r1 §4.4)
Fetches and parses the SPF record, evaluates the 'all' qualifier, and counts
DNS-querying mechanisms (include/a/mx/ptr/exists + redirect), recursing into
includes/redirects up to the RFC limit of 10.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import re
import logging

from scanner.dns_client import DNSClient

logger = logging.getLogger(__name__)

MAX_LOOKUPS = 10
_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


def _get_spf_records(domain: str, dc: DNSClient) -> list[str]:
    try:
        return [t for t in dc.txt(domain) if t.lower().startswith("v=spf1")]
    except Exception:
        # A transient DNS failure while resolving an include/redirect must not
        # abort the whole SPF evaluation — treat as "no record here".
        return []


def _count_lookups(record: str, domain: str, dc: DNSClient,
                   seen: set, depth: int = 0) -> int:
    """Count DNS-querying terms, recursing into include:/redirect=."""
    if depth > 10 or domain in seen:
        return 0
    seen.add(domain)
    count = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith(("include:", "exists:")) or t in ("a", "mx", "ptr") \
                or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:")):
            count += 1
            if t.startswith("include:"):
                target = term.split(":", 1)[1]
                sub = _get_spf_records(target, dc)
                if sub:
                    count += _count_lookups(sub[0], target, dc, seen, depth + 1)
        elif t.startswith("redirect="):
            count += 1
            target = term.split("=", 1)[1]
            sub = _get_spf_records(target, dc)
            if sub:
                count += _count_lookups(sub[0], target, dc, seen, depth + 1)
    return count


def check_spf(domain: str, dns_client: DNSClient | None = None) -> dict:
    """
    Returns:
      {
        "control": "spf", "present": bool, "valid": bool,
        "record": str|None, "records": [str],
        "all_qualifier": "+"|"-"|"~"|"?"|None, "all_policy": str|None,
        "has_redirect": bool, "lookup_count": int,
        "exceeds_lookup_limit": bool, "issues": [str],
      }
    """
    dc = dns_client or DNSClient()
    out = {"control": "spf", "present": False, "valid": False,
           "record": None, "records": [], "all_qualifier": None,
           "all_policy": None, "has_redirect": False,
           "lookup_count": 0, "exceeds_lookup_limit": False,
           # BSI TR-03182-01 / ACN notational + hardfail signals
           "all_is_last": None, "uses_ptr": False,
           "ip_mechanisms": 0, "name_mechanisms": 0, "mostly_ip": None,
           "deny_all": False, "issues": []}

    records = _get_spf_records(domain, dc)
    out["records"] = records
    if not records:
        out["issues"].append("No SPF record published")
        return out
    out["present"] = True
    if len(records) > 1:
        # RFC 7208 §3.2: multiple records => permerror, SPF effectively broken
        out["issues"].append(
            f"{len(records)} SPF records found — receivers treat this as "
            "permerror (SPF is void)")
        out["record"] = records[0]
        return out

    record = records[0]
    out["record"] = record
    out["valid"] = True

    # ---- Notational / mechanism analysis (BSI TR-03182-01, ACN) --------
    terms = record.split()[1:]              # drop the leading v=spf1
    non_all = [t for t in terms if t.lstrip("+-~?").lower() != "all"]
    if terms:
        out["all_is_last"] = terms[-1].lstrip("+-~?").lower() == "all"
        if out["all_is_last"] is False and any(
                t.lstrip("+-~?").lower() == "all" for t in terms):
            out["issues"].append(
                "'all' is not the last mechanism — terms after it are ignored "
                "(BSI TR-03182-01)")
    for t in terms:
        bare = t.lstrip("+-~?").lower()
        if bare == "ptr" or bare.startswith("ptr:"):
            out["uses_ptr"] = True
        if bare.startswith(("ip4:", "ip6:")):
            out["ip_mechanisms"] += 1
        elif bare in ("a", "mx") or bare.startswith(("a:", "a/", "mx:", "mx/",
                                                     "include:", "exists:")):
            out["name_mechanisms"] += 1
    if out["uses_ptr"]:
        out["issues"].append(
            "'ptr' mechanism is deprecated (RFC 7208 §5.5) and slow — remove it")
    total_mech = out["ip_mechanisms"] + out["name_mechanisms"]
    if total_mech:
        out["mostly_ip"] = out["ip_mechanisms"] >= out["name_mechanisms"]
    # A pure deny-all policy: 'v=spf1 -all' (no other sources) — the correct
    # posture for a parked / non-sending domain (BSI TR-03182-11).
    out["deny_all"] = (not non_all) and bool(
        re.search(r"(?:^|\s)-all(?:\s|$)", record))

    m = re.search(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", record)
    if m:
        q = m.group(1) or "+"
        out["all_qualifier"] = q
        out["all_policy"] = _QUALIFIERS[q]
        if q == "+":
            out["issues"].append("'+all' allows any sender — SPF is useless")
        elif q == "?":
            out["issues"].append("'?all' is neutral — provides no protection")
        elif q == "~":
            out["issues"].append("'~all' (softfail) — consider hardening to '-all'")
    else:
        out["has_redirect"] = "redirect=" in record.lower()
        if not out["has_redirect"]:
            out["issues"].append("SPF record has no 'all' mechanism")

    out["lookup_count"] = _count_lookups(record, domain, dc, set())
    if out["lookup_count"] > MAX_LOOKUPS:
        out["exceeds_lookup_limit"] = True
        out["issues"].append(
            f"{out['lookup_count']} DNS lookups exceed the RFC 7208 limit of "
            f"{MAX_LOOKUPS} — receivers return permerror")
    return out
