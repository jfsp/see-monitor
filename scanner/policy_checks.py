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

# DNSKEY algorithms no longer considered fit for purpose (RFC 8624).
_DEPRECATED_DNSKEY_ALGS = {1, 3, 5, 6, 7, 12}
_DNSKEY_ALG_NAMES = {
    1: "RSAMD5", 3: "DSA", 5: "RSASHA1", 6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256", 10: "RSASHA512",
    12: "ECC-GOST", 13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384",
    15: "ED25519", 16: "ED448",
}


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
           # v0.6.0: the TXT id, transport-level validity of the policy host,
           # and RFC 8461 §3.2 syntax conformance of the policy file itself.
           "policy_id": None, "cert_error": False, "http_status": None,
           "content_type": None, "version_line": None, "syntax_ok": None,
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
    for part in records[0].split(";"):
        part = part.strip()
        if part.lower().startswith("id="):
            out["policy_id"] = part[3:].strip()
    if not out["policy_id"]:
        out["issues"].append(
            "MTA-STS TXT record has no id= — senders cannot detect policy "
            "changes and will keep a stale cached policy (RFC 8461 §3.1)")

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    out["policy_url"] = url
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        out["http_status"] = resp.status_code
        out["content_type"] = (resp.headers.get("Content-Type") or "").lower()
        if resp.status_code != 200:
            out["issues"].append(
                f"MTA-STS policy returned HTTP {resp.status_code} — RFC 8461 "
                "§3.3 requires a 200 with no redirects; senders treat this as "
                "no policy")
            return out
        text = resp.text[:8192]
    except requests.exceptions.SSLError as exc:
        # A policy served over an untrusted certificate is a HARD failure:
        # senders MUST validate the mta-sts host with PKIX (RFC 8461 §3.3).
        out["cert_error"] = True
        out["issues"].append(
            f"MTA-STS policy host certificate is not valid: {exc} — the policy "
            "is unusable and MTA-STS provides no protection")
        return out
    except Exception as exc:
        out["issues"].append(f"MTA-STS policy fetch failed: {exc}")
        return out

    out["policy_fetched"] = True
    if out["content_type"] and not out["content_type"].startswith("text/plain"):
        out["issues"].append(
            f"MTA-STS policy served as {out['content_type']} — RFC 8461 "
            "requires text/plain")
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "version":
            out["version_line"] = v
        elif k == "mode":
            out["mode"] = v.lower()
        elif k == "max_age":
            try:
                out["max_age"] = int(v)
            except ValueError:
                pass
        elif k == "mx":
            out["policy_mx"].append(v.lower())

    out["syntax_ok"] = bool(out["version_line"] and out["mode"]
                            and out["max_age"] is not None
                            and out["policy_mx"])
    if (out["version_line"] or "").lower() != "stsv1":
        out["issues"].append(
            "MTA-STS policy has no 'version: STSv1' line — the policy is "
            "malformed and will be ignored")
    if not out["policy_mx"]:
        out["issues"].append(
            "MTA-STS policy lists no mx: patterns — no MX host is authorised")
    if out["max_age"] is not None and out["max_age"] > 31557600:
        out["issues"].append(
            f"MTA-STS max_age={out['max_age']} exceeds the RFC 8461 maximum "
            "of 31557600")

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
           "ds_present": False, "dnskey_present": False,
           "dmarc_zone_ad": None,
           # v0.6.0: presence is not quality — a zone signed with RSASHA1 or
           # anchored by a SHA-1 DS digest is signed but not defensible.
           "key_algorithms": [], "weak_algorithms": [],
           "ds_digest_types": [], "weak_ds_digest": False,
           "nsec3_iterations": None, "issues": []}
    ds_records = dc.query(domain, "DS")
    dnskey_records = dc.query(domain, "DNSKEY")
    out["ds_present"] = bool(ds_records)
    out["dnskey_present"] = bool(dnskey_records)
    out["signed"] = out["ds_present"] and out["dnskey_present"]

    for r in dnskey_records:
        alg = getattr(r, "algorithm", None)
        if alg is not None and alg not in out["key_algorithms"]:
            out["key_algorithms"].append(int(alg))
    out["weak_algorithms"] = [a for a in out["key_algorithms"]
                              if a in _DEPRECATED_DNSKEY_ALGS]
    for r in ds_records:
        dt = getattr(r, "digest_type", None)
        if dt is not None and dt not in out["ds_digest_types"]:
            out["ds_digest_types"].append(int(dt))
    out["weak_ds_digest"] = (bool(out["ds_digest_types"])
                             and all(d == 1 for d in out["ds_digest_types"]))
    for r in dc.query(domain, "NSEC3PARAM"):
        it = getattr(r, "iterations", None)
        if it is not None:
            out["nsec3_iterations"] = int(it)
            break

    if out["weak_algorithms"]:
        out["issues"].append(
            "Deprecated DNSSEC signing algorithm(s) in use: "
            + ", ".join(f"{a} ({_DNSKEY_ALG_NAMES.get(a, 'unknown')})"
                        for a in out["weak_algorithms"])
            + " — migrate to algorithm 13 (ECDSAP256SHA256) or 8 (RSASHA256)")
    if out["weak_ds_digest"]:
        out["issues"].append(
            "DS record uses only a SHA-1 digest (type 1) — publish a SHA-256 "
            "(type 2) DS at the parent")
    if out["nsec3_iterations"]:
        out["issues"].append(
            f"NSEC3 iterations = {out['nsec3_iterations']} — RFC 9276 requires "
            "0; non-zero iterations add no security and enable CPU exhaustion")
    out["validated"] = dc.ad_flag(domain)
    # BSI TR-03182: the zone publishing SPF/DKIM/DMARC policies SHOULD be
    # DNSSEC-secured. Record the AD flag on the _dmarc policy name.
    out["dmarc_zone_ad"] = dc.ad_flag(f"_dmarc.{domain}", rdtype="TXT")

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
               dns_client: DNSClient | None = None,
               presented_chains: dict | None = None) -> dict:
    """
    presented_chains: optional {mx_host: [der, ...]} captured by the STARTTLS
    probe on the connection it already made. When supplied, each TLSA record is
    matched against the certificate the server actually presents — a stale
    TLSA that no longer matches breaks delivery from every DANE-validating
    sender, which is strictly worse than publishing no DANE at all.
    """
    dc = dns_client or DNSClient()
    out = {"control": "dane", "applicable": bool(mx_hosts),
           "mx_with_tlsa": [], "mx_without_tlsa": [],
           "coverage": 0.0, "usable": False,
           # v0.6.0: RFC 7672 parameter validity and live match verification
           "parsed_records": {}, "unusable_params": [], "mismatched_mx": [],
           "verified_mx": [], "match_checked": False, "issues": []}
    if not mx_hosts:
        out["issues"].append("No MX hosts — DANE not applicable")
        return out

    from scanner.cert_check import parse_tlsa, match_tlsa

    chains = presented_chains or {}
    for mx in mx_hosts:
        tlsa = dc.query(f"_25._tcp.{mx}", "TLSA")
        if not tlsa:
            out["mx_without_tlsa"].append(mx)
            continue
        texts = [r.to_text() for r in tlsa][:8]
        parsed = [p for p in (parse_tlsa(t) for t in texts) if p]
        out["parsed_records"][mx] = parsed
        out["mx_with_tlsa"].append({"mx": mx, "records": texts})

        for rec in parsed:
            for issue in rec["issues"]:
                out["issues"].append(f"{mx}: {issue}")
        if parsed and not any(r["smtp_usable"] and r["digest_length_ok"]
                              for r in parsed):
            out["unusable_params"].append(mx)

        chain = chains.get(mx) or []
        if chain:
            result = match_tlsa(parsed, chain)
            if result["checked"]:
                out["match_checked"] = True
                if result["matched"]:
                    out["verified_mx"].append(mx)
                else:
                    out["mismatched_mx"].append(mx)

    n = len(mx_hosts)
    out["coverage"] = round(len(out["mx_with_tlsa"]) / n, 2) if n else 0.0
    out["usable"] = bool(out["mx_with_tlsa"]) and dnssec_valid \
        and not out["unusable_params"] and not out["mismatched_mx"]

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
        if out["unusable_params"]:
            out["issues"].append(
                "No usable TLSA record (RFC 7672 requires DANE-TA(2) or "
                "DANE-EE(3) with a correct digest) on: "
                + ", ".join(out["unusable_params"]))
        if out["mismatched_mx"]:
            out["issues"].append(
                "TLSA records do NOT match the certificate presented by: "
                + ", ".join(out["mismatched_mx"])
                + " — DANE-validating senders will refuse to deliver mail")
    return out


# ----------------------------------------------------------------------
# BIMI
# ----------------------------------------------------------------------
def check_bimi(domain: str, dns_client: DNSClient | None = None,
               dmarc: dict | None = None) -> dict:
    """
    dmarc: the result of check_dmarc, used to verify the BIMI prerequisite.
    BIMI requires the domain to be at DMARC enforcement (quarantine or reject);
    a BIMI record on a p=none domain will never render a logo anywhere.
    """
    dc = dns_client or DNSClient()
    out = {"control": "bimi", "present": False, "record": None,
           "logo_url": None, "vmc_url": None,
           "dmarc_enforced": None, "prerequisite_met": None, "issues": []}
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
    if dmarc is not None:
        policy = dmarc.get("effective_policy") or dmarc.get("policy")
        out["dmarc_enforced"] = policy in ("quarantine", "reject")
        out["prerequisite_met"] = bool(out["dmarc_enforced"])
        if not out["prerequisite_met"]:
            out["issues"].append(
                "BIMI published without DMARC enforcement (p=quarantine or "
                "reject) — the prerequisite is unmet and no receiver will "
                "display the logo")
    return out
