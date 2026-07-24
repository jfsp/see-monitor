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
# RFC 7208 §4.6.4: at most two "void" lookups (NXDOMAIN / empty answer) are
# permitted before the evaluation is a permerror. Dangling include: targets
# are common and blow this limit long before the 10-lookup ceiling is reached.
MAX_VOID_LOOKUPS = 2
_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}

# Shared, multi-tenant sending platforms. Including one of these authorises
# every customer of that platform to send as the domain unless the platform
# additionally enforces per-tenant alignment. Reported, never auto-failed.
_MULTI_TENANT = {
    "sendgrid.net", "spf.protection.outlook.com", "_spf.google.com",
    "mailgun.org", "spf.mandrillapp.com", "servers.mcsv.net",
    "amazonses.com", "spf.mailjet.com", "sendinblue.com", "zoho.com",
    "mktomail.com", "spf.constantcontact.com", "salesforce.com",
    "helpscoutemail.com", "mail.zendesk.com", "spf.sendpulse.com",
}


def _get_spf_records(domain: str, dc: DNSClient) -> list[str]:
    try:
        return [t for t in dc.txt(domain) if t.lower().startswith("v=spf1")]
    except Exception:
        # A transient DNS failure while resolving an include/redirect must not
        # abort the whole SPF evaluation — treat as "no record here".
        return []


def _addr_count(term: str) -> int:
    """Number of addresses authorised by an ip4:/ip6: term (0 if unparsable)."""
    import ipaddress
    value = term.split(":", 1)[1] if ":" in term else ""
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return 0
    return net.num_addresses


def _resolves(name: str, dc: DNSClient, rdtypes=("A", "AAAA")) -> bool:
    return any(dc.query(name, rd) for rd in rdtypes)


def _traverse(record: str, domain: str, dc: DNSClient, state: dict,
              depth: int = 0) -> None:
    """
    Walk the SPF record, recursing into include:/redirect=, accumulating:
      lookups        DNS-querying mechanisms (RFC 7208 §4.6.4 limit: 10)
      void           lookups returning NXDOMAIN / no answer (limit: 2)
      dangling       include/redirect targets with no usable SPF record
      addresses      total IPv4+IPv6 addresses authorised
      multi_tenant   shared sending platforms authorised
      macros         terms using RFC 7208 macro expansion
    """
    if depth > 10 or domain in state["seen"]:
        return
    state["seen"].add(domain)

    for term in record.split()[1:]:
        raw = term.lstrip("+-~?")
        t = raw.lower()

        if "%{" in t:
            state["macros"].append(term)

        if t.startswith(("ip4:", "ip6:")):
            state["addresses"] += _addr_count(t)
            continue

        if t.startswith("include:") or t.startswith("redirect="):
            sep = ":" if t.startswith("include:") else "="
            target = raw.split(sep, 1)[1].strip().rstrip(".").lower()
            state["lookups"] += 1
            if t.startswith("include:"):
                base = target
                for known in _MULTI_TENANT:
                    if base == known or base.endswith("." + known):
                        if known not in state["multi_tenant"]:
                            state["multi_tenant"].append(known)
                        break
            sub = _get_spf_records(target, dc)
            if not sub:
                state["void"] += 1
                if target not in state["dangling"]:
                    state["dangling"].append(target)
                continue
            _traverse(sub[0], target, dc, state, depth + 1)
            continue

        if t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/",
                                                    "ptr:", "exists:")):
            state["lookups"] += 1
            # Only explicit-domain forms are re-resolved; the bare a/mx forms
            # refer to the current domain, which we already know resolves.
            if ":" in t and not t.startswith("ptr"):
                target = raw.split(":", 1)[1].split("/", 1)[0].strip().rstrip(".")
                rdtypes = ("MX",) if t.startswith("mx:") else ("A", "AAAA")
                if target and not _resolves(target, dc, rdtypes):
                    state["void"] += 1
                    if target not in state["dangling"]:
                        state["dangling"].append(target)


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
           "deny_all": False,
           # v0.6.0: RFC 7208 §4.6.4 void limit, dangling targets, breadth of
           # the authorised sender space, shared-platform includes, macros.
           "void_lookups": 0, "exceeds_void_limit": False,
           "dangling_targets": [], "authorised_addresses": 0,
           "multi_tenant_includes": [], "macros": [], "has_exp": False,
           "issues": []}

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

    out["has_exp"] = "exp=" in record.lower()

    state = {"seen": set(), "lookups": 0, "void": 0, "dangling": [],
             "addresses": 0, "multi_tenant": [], "macros": []}
    _traverse(record, domain, dc, state)
    out["lookup_count"] = state["lookups"]
    out["void_lookups"] = state["void"]
    out["dangling_targets"] = state["dangling"]
    out["authorised_addresses"] = state["addresses"]
    out["multi_tenant_includes"] = state["multi_tenant"]
    out["macros"] = state["macros"]

    if out["lookup_count"] > MAX_LOOKUPS:
        out["exceeds_lookup_limit"] = True
        out["issues"].append(
            f"{out['lookup_count']} DNS lookups exceed the RFC 7208 limit of "
            f"{MAX_LOOKUPS} — receivers return permerror")
    if out["void_lookups"] > MAX_VOID_LOOKUPS:
        out["exceeds_void_limit"] = True
        out["issues"].append(
            f"{out['void_lookups']} void lookups exceed the RFC 7208 §4.6.4 "
            f"limit of {MAX_VOID_LOOKUPS} — receivers return permerror and SPF "
            "is void")
    if out["dangling_targets"]:
        out["issues"].append(
            "SPF references target(s) that publish no usable record: "
            + ", ".join(out["dangling_targets"])
            + " — each is a wasted (void) lookup and a stale authorisation")
    if out["multi_tenant_includes"]:
        out["issues"].append(
            "SPF authorises shared sending platform(s): "
            + ", ".join(out["multi_tenant_includes"])
            + " — every tenant of those platforms passes SPF for this domain; "
              "DKIM alignment is what actually constrains them")
    # Roughly a /16 of IPv4 space, or any IPv6 delegation, is a very broad
    # authorisation for a single organisation's mail.
    if out["authorised_addresses"] >= 65536:
        out["issues"].append(
            f"SPF authorises approximately {out['authorised_addresses']:,} "
            "addresses — a hardfail policy over a very large sender space "
            "provides limited assurance")
    if out["macros"]:
        out["issues"].append(
            "SPF uses macro expansion (" + ", ".join(out["macros"][:3])
            + ") — correct but frequently misconfigured and hard to audit")
    return out
