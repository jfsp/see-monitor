#!/usr/bin/env python3
"""
SEE-Monitor: Subdomain Coverage Check

A hardened apex with two hundred unprotected subdomains is not a protected
domain. Attackers spoof `invoices.example.com`, not `example.com`.

Candidate names come from passive sources only (Certificate Transparency via
crt.sh, plus any SecurityTrails intel already gathered by the orchestrator).
Every candidate is then re-confirmed against authoritative DNS before it can
influence anything — HANDOVER invariant 1.

What is actually assessed per subdomain:
  * whether it exists at all (candidates from CT are often long dead)
  * whether it receives mail (MX)
  * whether it publishes its own DMARC record, and whether that record is
    WEAKER than the policy it would otherwise inherit from the apex `sp=`.
    This is the finding that matters: a subdomain-level `p=none` silently
    overrides an apex `sp=reject`.
  * whether a non-sending subdomain publishes the deny-all posture that
    BSI TR-03182-11 asks for (`v=spf1 -all`)

Note on inheritance: DMARC subdomain policy (`sp=`) already covers existing
subdomains, and DMARCbis `np=` covers non-existent ones, so a correct apex
policy protects most of the tree. Coverage therefore measures *gaps* against
that inherited policy rather than demanding a record on every name.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import re

from scanner.dns_client import DNSClient

logger = logging.getLogger(__name__)

_POLICY_ORDER = ["none", "quarantine", "reject"]
_DENY_ALL_RE = re.compile(r"^v=spf1\s+-all\s*$", re.IGNORECASE)

DEFAULT_MAX_SUBDOMAINS = 25


def _policy_rank(policy: str | None) -> int:
    try:
        return _POLICY_ORDER.index((policy or "none").lower())
    except ValueError:
        return 0


def _own_dmarc(name: str, dc: DNSClient) -> str | None:
    """Policy of a DMARC record published directly at *name*, if any."""
    for txt in dc.txt(f"_dmarc.{name}"):
        if not txt.lower().replace(" ", "").startswith("v=dmarc1"):
            continue
        for part in txt.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                return part[2:].strip().lower()
        return "none"
    return None


def check_subdomains(domain: str, candidates: list[str] | None = None,
                     inherited_policy: str | None = None,
                     dns_client: DNSClient | None = None,
                     max_subdomains: int = DEFAULT_MAX_SUBDOMAINS,
                     enabled: bool = True) -> dict:
    """
    inherited_policy: the effective DMARC policy a subdomain would inherit
    from the apex (i.e. `sp=` if present, else `p=`), or None if the apex
    publishes no DMARC at all.

    Returns:
      {
        "control": "subdomains", "enabled": bool, "applicable": bool,
        "candidates": int, "checked": int, "live": int,
        "subdomains": [{"name","exists","has_mx","own_dmarc_policy",
                        "weaker_than_apex","spf_deny_all","spf_present"}],
        "mail_subdomains": [str], "weaker_policy": [str],
        "unprotected": [str], "coverage": float|None,
        "truncated": bool, "issues": [str],
      }
    """
    out = {"control": "subdomains", "enabled": enabled, "applicable": False,
           "candidates": 0, "checked": 0, "live": 0, "subdomains": [],
           "mail_subdomains": [], "weaker_policy": [], "unprotected": [],
           "coverage": None, "truncated": False, "issues": []}
    if not enabled:
        out["issues"].append("Subdomain coverage check disabled in configuration")
        return out

    dc = dns_client or DNSClient()
    names: list[str] = []
    seen = set()
    for raw in (candidates or []):
        name = (raw or "").strip().lower().rstrip(".")
        if not name or name == domain or not name.endswith("." + domain):
            continue
        if name not in seen:
            seen.add(name)
            names.append(name)
    out["candidates"] = len(names)
    if not names:
        out["issues"].append(
            "No subdomain candidates from passive sources — coverage not "
            "assessed (n/a)")
        return out

    # Shortest names first: closest to the apex, most likely to be live and
    # to matter operationally.
    names.sort(key=lambda n: (n.count("."), len(n)))
    if len(names) > max_subdomains:
        out["truncated"] = True
        names = names[:max_subdomains]
    out["checked"] = len(names)
    out["applicable"] = True

    apex_rank = _policy_rank(inherited_policy) if inherited_policy else -1

    for name in names:
        entry = {"name": name, "exists": False, "has_mx": False,
                 "own_dmarc_policy": None, "weaker_than_apex": None,
                 "spf_present": False, "spf_deny_all": False}
        addrs = dc.query(name, "A") or dc.query(name, "AAAA")
        mx = dc.query(name, "MX")
        entry["exists"] = bool(addrs or mx)
        if not entry["exists"]:
            out["subdomains"].append(entry)
            continue
        out["live"] += 1
        entry["has_mx"] = bool(mx)
        if entry["has_mx"]:
            out["mail_subdomains"].append(name)

        spf = [t for t in dc.txt(name) if t.lower().startswith("v=spf1")]
        entry["spf_present"] = bool(spf)
        entry["spf_deny_all"] = bool(spf and _DENY_ALL_RE.match(spf[0].strip()))

        policy = _own_dmarc(name, dc)
        entry["own_dmarc_policy"] = policy
        if policy is not None and apex_rank >= 0:
            entry["weaker_than_apex"] = _policy_rank(policy) < apex_rank
            if entry["weaker_than_apex"]:
                out["weaker_policy"].append(name)

        # Unprotected = no inherited enforcement and no own enforcement.
        own_rank = _policy_rank(policy) if policy is not None else -1
        effective = max(own_rank, apex_rank) if policy is None else own_rank
        if effective < _POLICY_ORDER.index("quarantine"):
            out["unprotected"].append(name)

        out["subdomains"].append(entry)

    if out["live"]:
        protected = out["live"] - len(out["unprotected"])
        out["coverage"] = round(protected / out["live"], 2)

    if out["weaker_policy"]:
        out["issues"].append(
            "Subdomain DMARC weaker than the inherited apex policy: "
            + ", ".join(out["weaker_policy"])
            + " — a subdomain record overrides sp= entirely")
    if out["unprotected"]:
        sample = ", ".join(out["unprotected"][:8])
        more = "" if len(out["unprotected"]) <= 8 \
            else f" (+{len(out['unprotected']) - 8} more)"
        out["issues"].append(
            f"{len(out['unprotected'])} of {out['live']} live subdomains are "
            f"spoofable (no enforcing DMARC, inherited or own): {sample}{more}")
    mail_no_spf = [s["name"] for s in out["subdomains"]
                   if s["has_mx"] and not s["spf_present"]]
    if mail_no_spf:
        out["issues"].append(
            "Mail-receiving subdomain(s) without SPF: " + ", ".join(mail_no_spf))
    if out["truncated"]:
        out["issues"].append(
            f"Subdomain check truncated at {max_subdomains} names of "
            f"{out['candidates']} candidates — raise scanning.max_subdomains "
            "for full coverage")
    return out
