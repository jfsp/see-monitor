#!/usr/bin/env python3
"""
SEE-Monitor: Policy Checks — MTA-STS (RFC 8461), TLS-RPT (RFC 8460),
DNSSEC (RFC 4033-4035), DANE/TLSA (RFC 7672), BIMI.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import fnmatch
import logging

import requests

from scanner.dns_client import DNSClient

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# MTA-STS
# ----------------------------------------------------------------------
def check_mta_sts(domain: str, mx_hosts: list[str] | None = None,
                  dns_client: DNSClient | None = None,
                  timeout: int = 10) -> dict:
    dc = dns_client or DNSClient()
    out = {"control": "mta_sts", "present": False, "record": None,
           "policy_fetched": False, "policy_url": None, "mode": None,
           "max_age": None, "policy_mx": [], "mx_covered": None,
           "issues": []}

    records = [t for t in dc.txt(f"_mta-sts.{domain}")
               if t.lower().replace(" ", "").startswith("v=stsv1")]
    if not records:
        out["issues"].append("No MTA-STS record published")
        return out
    out["present"] = True
    out["record"] = records[0]
    if len(records) > 1:
        out["issues"].append("Multiple MTA-STS records — policy is void")
        return out

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    out["policy_url"] = url
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        resp.raise_for_status()
        text = resp.text[:8192]
    except Exception as exc:
        out["issues"].append(f"MTA-STS policy fetch failed: {exc}")
        return out

    out["policy_fetched"] = True
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "mode":
            out["mode"] = v.lower()
        elif k == "max_age":
            try:
                out["max_age"] = int(v)
            except ValueError:
                pass
        elif k == "mx":
            out["policy_mx"].append(v.lower())

    if out["mode"] == "none":
        out["issues"].append("MTA-STS mode=none — policy disabled")
    elif out["mode"] == "testing":
        out["issues"].append("MTA-STS mode=testing — failures are reported, not enforced")
    elif out["mode"] != "enforce":
        out["issues"].append(f"Unknown MTA-STS mode: {out['mode']!r}")
    if out["max_age"] is not None and out["max_age"] < 86400:
        out["issues"].append(f"MTA-STS max_age={out['max_age']} is very short")

    if mx_hosts and out["policy_mx"]:
        covered = all(
            any(fnmatch.fnmatch(mx, pat) for pat in out["policy_mx"])
            for mx in mx_hosts)
        out["mx_covered"] = covered
        if not covered:
            out["issues"].append("Not all MX hosts are covered by the MTA-STS policy")
    return out


# ----------------------------------------------------------------------
# TLS-RPT
# ----------------------------------------------------------------------
def check_tlsrpt(domain: str, dns_client: DNSClient | None = None) -> dict:
    dc = dns_client or DNSClient()
    out = {"control": "tlsrpt", "present": False, "record": None,
           "rua": [], "issues": []}
    records = [t for t in dc.txt(f"_smtp._tls.{domain}")
               if t.lower().replace(" ", "").startswith("v=tlsrptv1")]
    if not records:
        out["issues"].append("No TLS-RPT record published")
        return out
    out["present"] = True
    out["record"] = records[0]
    for part in records[0].split(";"):
        part = part.strip()
        if part.lower().startswith("rua="):
            out["rua"] = [u.strip() for u in part[4:].split(",") if u.strip()]
    if not out["rua"]:
        out["issues"].append("TLS-RPT record has no rua= destination")
    return out


# ----------------------------------------------------------------------
# DNSSEC
# ----------------------------------------------------------------------
def check_dnssec(domain: str, dns_client: DNSClient | None = None) -> dict:
    dc = dns_client or DNSClient()
    out = {"control": "dnssec", "signed": False, "validated": None,
           "ds_present": False, "dnskey_present": False, "issues": []}
    out["ds_present"] = bool(dc.query(domain, "DS"))
    out["dnskey_present"] = bool(dc.query(domain, "DNSKEY"))
    out["signed"] = out["ds_present"] and out["dnskey_present"]
    out["validated"] = dc.ad_flag(domain)

    if not out["signed"]:
        if out["dnskey_present"] and not out["ds_present"]:
            out["issues"].append(
                "DNSKEY present but no DS at the parent — chain of trust incomplete")
        else:
            out["issues"].append("Zone is not DNSSEC-signed")
    elif out["validated"] is False:
        out["issues"].append(
            "DS/DNSKEY present but validating resolvers do NOT set AD — "
            "possible bogus/broken DNSSEC chain")
    elif out["validated"] is None:
        out["issues"].append("DNSSEC validation could not be confirmed (resolver unreachable)")
    return out


# ----------------------------------------------------------------------
# DANE / TLSA (per MX host, port 25)
# ----------------------------------------------------------------------
def check_dane(mx_hosts: list[str], dnssec_valid: bool,
               dns_client: DNSClient | None = None) -> dict:
    dc = dns_client or DNSClient()
    out = {"control": "dane", "applicable": bool(mx_hosts),
           "mx_with_tlsa": [], "mx_without_tlsa": [],
           "coverage": 0.0, "usable": False, "issues": []}
    if not mx_hosts:
        out["issues"].append("No MX hosts — DANE not applicable")
        return out
    for mx in mx_hosts:
        tlsa = dc.query(f"_25._tcp.{mx}", "TLSA")
        if tlsa:
            out["mx_with_tlsa"].append(
                {"mx": mx, "records": [r.to_text() for r in tlsa][:8]})
        else:
            out["mx_without_tlsa"].append(mx)
    n = len(mx_hosts)
    out["coverage"] = round(len(out["mx_with_tlsa"]) / n, 2) if n else 0.0
    out["usable"] = bool(out["mx_with_tlsa"]) and dnssec_valid

    if not out["mx_with_tlsa"]:
        out["issues"].append("No TLSA records on any MX host")
    else:
        if out["mx_without_tlsa"]:
            out["issues"].append(
                "TLSA missing on: " + ", ".join(out["mx_without_tlsa"]))
        if not dnssec_valid:
            out["issues"].append(
                "TLSA records exist but DNSSEC does not validate — "
                "senders cannot use DANE")
    return out


# ----------------------------------------------------------------------
# BIMI
# ----------------------------------------------------------------------
def check_bimi(domain: str, dns_client: DNSClient | None = None) -> dict:
    dc = dns_client or DNSClient()
    out = {"control": "bimi", "present": False, "record": None,
           "logo_url": None, "vmc_url": None, "issues": []}
    records = [t for t in dc.txt(f"default._bimi.{domain}")
               if t.lower().replace(" ", "").startswith("v=bimi1")]
    if not records:
        out["issues"].append("No BIMI record published (optional control)")
        return out
    out["present"] = True
    out["record"] = records[0]
    for part in records[0].split(";"):
        part = part.strip()
        if part.lower().startswith("l="):
            out["logo_url"] = part[2:].strip()
        elif part.lower().startswith("a="):
            out["vmc_url"] = part[2:].strip()
    if not out["vmc_url"]:
        out["issues"].append(
            "BIMI without a Verified Mark Certificate (a=) — most receivers "
            "will not display the logo")
    return out
