#!/usr/bin/env python3
"""
SEE-Monitor: DNS Hygiene & Infrastructure Resilience

Everything below is DNS-observable and passive — no connection is made to the
assessed domain's mail servers.

Checks:
  * MX target sanity      — targets resolve (A/AAAA); dangling MX; MX pointing
                            at a CNAME (RFC 2181 §10.3 violation, also breaks
                            DANE because the TLSA name must be the canonical
                            MX name)
  * Reverse DNS / FCrDNS  — forward-confirmed reverse DNS on every MX address;
                            missing or non-confirming PTR is a deliverability
                            and hygiene signal that many receivers act on
  * IPv6 readiness        — AAAA on MX; a domain reachable over IPv6 whose SPF
                            has no ip6: term fails authentication over IPv6
  * CAA                   — RFC 8659 issuance constraints on the domain and on
                            the MTA-STS policy host; without CAA any CA can
                            mint a certificate that satisfies MTA-STS
  * Takeover exposure     — mta-sts / autodiscover / autoconfig / _dmarc /
                            MX targets that are CNAMEs to names which no longer
                            resolve. A hijackable mta-sts host is a complete
                            transport-downgrade primitive
  * NS resilience         — nameserver count and provider diversity; a single
                            DNS provider is the shared failure mode behind SPF,
                            DKIM, DMARC, MTA-STS and DANE simultaneously
  * Provider concentration— which organisation actually operates the MX, for
                            sovereignty/concentration reporting

Registrable-domain inference uses a small suffix heuristic rather than the
Public Suffix List; it is used only for grouping/reporting, never for scoring.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging

from scanner.dns_client import DNSClient

logger = logging.getLogger(__name__)

# Two-label public suffixes common enough to matter for provider grouping.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "or.jp", "ne.jp",
    "com.au", "net.au", "org.au", "co.nz", "com.br", "com.mx", "co.za",
    "com.tr", "com.cn", "com.sg", "gob.es", "com.es", "org.es",
}

# Service names that are frequently CNAME'd to a SaaS endpoint and then
# forgotten. Each is a live takeover vector for email security.
_SERVICE_NAMES = ["mta-sts", "autodiscover", "autoconfig", "_dmarc",
                  "_mta-sts", "_smtp._tls"]


def registrable_domain(host: str) -> str:
    """Approximate registrable domain (heuristic, reporting use only)."""
    labels = (host or "").strip().rstrip(".").lower().split(".")
    if len(labels) < 2:
        return host or ""
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _addresses(host: str, dc: DNSClient) -> tuple[list[str], list[str]]:
    v4 = [r.to_text() for r in dc.query(host, "A")]
    v6 = [r.to_text() for r in dc.query(host, "AAAA")]
    return v4, v6


def _ptr_name(ip: str) -> str | None:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return None


def _fcrdns(ip: str, dc: DNSClient) -> dict:
    """Forward-confirmed reverse DNS for one address."""
    out = {"ip": ip, "ptr": None, "confirmed": None}
    name = _ptr_name(ip)
    if not name:
        return out
    ptrs = [r.to_text().rstrip(".").lower() for r in dc.query(name, "PTR")]
    if not ptrs:
        out["confirmed"] = False
        return out
    out["ptr"] = ptrs[0]
    for ptr in ptrs:
        v4, v6 = _addresses(ptr, dc)
        if ip in v4 or ip in v6:
            out["confirmed"] = True
            return out
    out["confirmed"] = False
    return out


def _cname_target(name: str, dc: DNSClient) -> str | None:
    recs = dc.query(name, "CNAME")
    if not recs:
        return None
    return str(recs[0].target).rstrip(".").lower()


def _resolves(name: str, dc: DNSClient) -> bool:
    for rdtype in ("A", "AAAA", "CNAME", "MX", "TXT"):
        if dc.query(name, rdtype):
            return True
    return False


def check_dns_hygiene(domain: str, mx_hosts: list[str] | None = None,
                      dns_client: DNSClient | None = None,
                      do_fcrdns: bool = True) -> dict:
    """
    Returns:
      {
        "control": "dns_hygiene", "mx_addresses": {mx: {...}},
        "mx_ips": [str], "dangling_mx": [str], "mx_is_cname": [str],
        "ipv6_ready": bool|None, "fcrdns": [{...}], "fcrdns_ok": bool|None,
        "caa": {"present": bool, "records": [str], "issue": [str],
                "mta_sts_host_caa": bool|None},
        "takeover_risks": [{"name","cname","reason"}],
        "nameservers": [str], "ns_providers": [str], "ns_diverse": bool|None,
        "mx_providers": [str], "mx_provider_count": int,
        "single_provider": bool|None, "issues": [str],
      }
    """
    dc = dns_client or DNSClient()
    out = {"control": "dns_hygiene", "mx_addresses": {}, "mx_ips": [],
           "dangling_mx": [], "mx_is_cname": [], "ipv6_ready": None,
           "fcrdns": [], "fcrdns_ok": None,
           "caa": {"present": False, "records": [], "issue": [],
                   "mta_sts_host_caa": None},
           "takeover_risks": [], "nameservers": [], "ns_providers": [],
           "ns_diverse": None, "mx_providers": [], "mx_provider_count": 0,
           "single_provider": None, "issues": []}

    mx_hosts = mx_hosts or []

    # ---- MX targets ---------------------------------------------------
    any_v6 = False
    for mx in mx_hosts:
        cname = _cname_target(mx, dc)
        v4, v6 = _addresses(mx, dc)
        out["mx_addresses"][mx] = {"a": v4, "aaaa": v6, "cname": cname}
        out["mx_ips"] += [ip for ip in v4 + v6 if ip not in out["mx_ips"]]
        if v6:
            any_v6 = True
        if not v4 and not v6:
            out["dangling_mx"].append(mx)
        if cname:
            out["mx_is_cname"].append(mx)
    if mx_hosts:
        out["ipv6_ready"] = any_v6
        providers = []
        for mx in mx_hosts:
            reg = registrable_domain(mx)
            if reg and reg not in providers:
                providers.append(reg)
        out["mx_providers"] = providers
        out["mx_provider_count"] = len(providers)
        out["single_provider"] = len(providers) <= 1

    if out["dangling_mx"]:
        out["issues"].append(
            "MX host(s) do not resolve to any address: "
            + ", ".join(out["dangling_mx"])
            + " — mail to this domain will fail, and an unclaimed target is a "
              "takeover vector")
    if out["mx_is_cname"]:
        out["issues"].append(
            "MX target(s) are CNAMEs (RFC 2181 §10.3 violation): "
            + ", ".join(out["mx_is_cname"])
            + " — some senders reject this and DANE TLSA lookups break")
    if mx_hosts and out["ipv6_ready"] is False:
        out["issues"].append(
            "No AAAA on any MX — the domain cannot receive mail over IPv6")
    if out["single_provider"] and len(mx_hosts) > 1:
        out["issues"].append(
            "All MX hosts belong to one provider ("
            + ", ".join(out["mx_providers"])
            + ") — no independent delivery path")

    # ---- Reverse DNS --------------------------------------------------
    if do_fcrdns and out["mx_ips"]:
        results = [_fcrdns(ip, dc) for ip in out["mx_ips"][:16]]
        out["fcrdns"] = results
        checked = [r for r in results if r["confirmed"] is not None]
        if checked:
            out["fcrdns_ok"] = all(r["confirmed"] for r in checked)
            bad = [r["ip"] for r in checked if not r["confirmed"]]
            if bad:
                out["issues"].append(
                    "No forward-confirmed reverse DNS for: " + ", ".join(bad)
                    + " — many receivers penalise or reject such senders")

    # ---- CAA ----------------------------------------------------------
    caa_records = [r.to_text() for r in dc.query(domain, "CAA")]
    out["caa"]["present"] = bool(caa_records)
    out["caa"]["records"] = caa_records[:16]
    out["caa"]["issue"] = [
        r for r in caa_records if " issue " in f" {r} " or "issue " in r]
    if not caa_records:
        out["issues"].append(
            "No CAA record — any public CA may issue a certificate for this "
            "domain, weakening the trust assumption behind MTA-STS")
    mta_sts_host = f"mta-sts.{domain}"
    if _resolves(mta_sts_host, dc):
        out["caa"]["mta_sts_host_caa"] = bool(
            dc.query(mta_sts_host, "CAA")) or bool(caa_records)

    # ---- Takeover-prone names ----------------------------------------
    for label in _SERVICE_NAMES:
        name = f"{label}.{domain}"
        cname = _cname_target(name, dc)
        if not cname:
            continue
        if not _resolves(cname, dc):
            out["takeover_risks"].append(
                {"name": name, "cname": cname,
                 "reason": "CNAME target does not resolve (dangling)"})
    for mx in out["mx_is_cname"]:
        target = out["mx_addresses"][mx]["cname"]
        if target and not _resolves(target, dc):
            out["takeover_risks"].append(
                {"name": mx, "cname": target,
                 "reason": "MX CNAME target does not resolve (dangling)"})
    if out["takeover_risks"]:
        out["issues"].append(
            "Dangling CNAME(s) — subdomain-takeover exposure: "
            + ", ".join(f"{t['name']} -> {t['cname']}"
                        for t in out["takeover_risks"]))

    # ---- Nameservers --------------------------------------------------
    ns = sorted({str(r.target).rstrip(".").lower()
                 for r in dc.query(domain, "NS")})
    out["nameservers"] = ns
    providers = []
    for host in ns:
        reg = registrable_domain(host)
        if reg and reg not in providers:
            providers.append(reg)
    out["ns_providers"] = providers
    if ns:
        out["ns_diverse"] = len(providers) > 1
        if len(ns) < 2:
            out["issues"].append(
                "Only one nameserver published — single point of failure for "
                "every email-security policy record")
        elif not out["ns_diverse"]:
            out["issues"].append(
                "All nameservers are operated by one provider ("
                + ", ".join(providers) + ")")
    return out
