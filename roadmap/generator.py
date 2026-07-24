#!/usr/bin/env python3
"""
SEE-Monitor: Roadmap Generator
Turns an assessment into a prioritised improvement plan aligned with
NIST SP 800-177r1: phased activities (Quick wins → Authentication →
Transport → Enforcement), each with concrete actions and target state.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_PHASES = [
    ("P1", "Quick wins (0-1 month)"),
    ("P2", "Sender authentication (1-3 months)"),
    ("P3", "Transport security (3-6 months)"),
    ("P4", "Enforcement & monitoring (6-12 months)"),
]


def _activity(phase, control, title, actions, ref):
    return {"phase": phase, "control": control, "title": title,
            "actions": actions, "reference": ref}


def generate_domain_roadmap(assessment: dict, checks: dict | None = None) -> dict:
    """Return a phased roadmap for one domain from its latest assessment."""
    checks = checks or {}
    cs = assessment.get("control_scores", {})
    acts: list = []

    spf, dmarc = checks.get("spf", {}), checks.get("dmarc", {})
    dkim, sts = checks.get("dkim", {}), checks.get("mta_sts", {})

    # --- SPF -----------------------------------------------------------
    s = cs.get("spf")
    if s == 0:
        acts.append(_activity("P1", "spf", "Publish an SPF record",
            ["Inventory every legitimate outbound mail source",
             "Publish 'v=spf1 … ~all' as an initial policy",
             "Harden to '-all' once DMARC reports confirm coverage"],
            "SP 800-177r1 §4.4"))
    elif s is not None and s < 100:
        a = []
        if spf.get("exceeds_lookup_limit"):
            a.append("Flatten includes to get under the 10-DNS-lookup limit")
        if spf.get("all_qualifier") in ("~", "?", "+") or not spf.get("all_qualifier"):
            a.append("Change the final mechanism to '-all'")
        if len(spf.get("records", [])) > 1:
            a.append("Merge the multiple SPF records into exactly one")
        acts.append(_activity("P1", "spf", "Harden the SPF policy",
                              a or ["Review SPF mechanisms"],
                              "SP 800-177r1 §4.4"))

    # --- DKIM ----------------------------------------------------------
    s = cs.get("dkim")
    if s == 0:
        acts.append(_activity("P2", "dkim", "Deploy DKIM signing",
            ["Enable DKIM on every outbound gateway/ESP",
             "Use RSA >= 2048 bits or Ed25519 keys",
             "Register the selectors in SEE-Monitor for accurate scoring"],
            "SP 800-177r1 §4.5"))
    elif s is not None and s < 100:
        a = []
        if dkim.get("best_status") in ("weak", "very_weak"):
            a.append("Rotate weak RSA keys (<2048 bits) to 2048+ or Ed25519")
        if dkim.get("any_testing"):
            a.append("Remove the t=y testing flag")
        acts.append(_activity("P2", "dkim", "Strengthen DKIM keys",
                              a or ["Review DKIM key inventory"],
                              "SP 800-177r1 §4.5"))

    # --- DMARC ---------------------------------------------------------
    s = cs.get("dmarc")
    if s == 0:
        acts.append(_activity("P2", "dmarc", "Publish DMARC in monitor mode",
            ["Publish 'v=DMARC1; p=none; rua=mailto:…'",
             "Analyse aggregate reports for 4-6 weeks",
             "Fix alignment for every legitimate sender"],
            "SP 800-177r1 §4.6"))
    elif s is not None and s < 100:
        a = []
        p = dmarc.get("policy")
        if p == "none":
            a.append("Move to p=quarantine, then p=reject")
        elif p == "quarantine":
            a.append("Move to p=reject once quarantine causes no losses")
        if dmarc.get("pct", 100) < 100:
            a.append("Raise pct to 100")
        if not dmarc.get("rua"):
            a.append("Add an aggregate reporting address (rua)")
        acts.append(_activity("P4", "dmarc", "Reach DMARC enforcement",
                              a or ["Review DMARC policy"],
                              "SP 800-177r1 §4.6"))

    # --- STARTTLS ------------------------------------------------------
    s = cs.get("starttls")
    if s is not None and s < 100:
        acts.append(_activity("P3", "starttls",
            "Ensure STARTTLS with TLS >= 1.2 on all MX",
            ["Enable STARTTLS on every inbound MX",
             "Disable SSLv3/TLS 1.0/1.1",
             "Deploy valid certificates matching the MX hostnames"],
            "SP 800-177r1 §5.1"))

    # --- DNSSEC --------------------------------------------------------
    s = cs.get("dnssec")
    if s is not None and s < 100:
        acts.append(_activity("P3", "dnssec", "Sign the zone with DNSSEC",
            ["Enable DNSSEC signing at the DNS operator",
             "Publish DS records at the registrar",
             "Monitor validation (this is a prerequisite for DANE)"],
            "SP 800-177r1 §4.1-4.2"))

    # --- DANE / MTA-STS ------------------------------------------------
    if cs.get("dane") is not None and cs.get("dane") < 100:
        acts.append(_activity("P4", "dane", "Publish TLSA records for all MX",
            ["Generate TLSA (3 1 1) records for each MX certificate",
             "Automate TLSA rollover with certificate renewal"],
            "SP 800-177r1 §5.2"))
    s = cs.get("mta_sts")
    if s is not None and s < 100:
        a = ["Publish the _mta-sts TXT record and HTTPS policy file"]
        if sts.get("mode") == "testing":
            a = ["Switch the MTA-STS policy from testing to enforce"]
        elif sts.get("present") and not sts.get("policy_fetched"):
            a = [f"Fix the policy endpoint: {sts.get('policy_url')}"]
        acts.append(_activity("P4", "mta_sts", "Enforce MTA-STS",
                              a, "RFC 8461"))

    # --- TLS-RPT / BIMI -------------------------------------------------
    if cs.get("tlsrpt") is not None and cs.get("tlsrpt") < 100:
        acts.append(_activity("P1", "tlsrpt", "Publish TLS-RPT",
            ["Publish '_smtp._tls' TXT with a rua= destination",
             "Review transport failure reports weekly"], "RFC 8460"))
    if cs.get("bimi") == 0 and (dmarc.get("policy") in ("quarantine", "reject")):
        acts.append(_activity("P4", "bimi", "Optionally adopt BIMI",
            ["Trademark the logo and obtain a VMC",
             "Publish the default._bimi record"], "BIMI WG"))

    # --- National-profile hardening (BSI / ACN / CCN deltas over NIST) ---
    if dkim.get("present") and not dkim.get("has_ed25519"):
        acts.append(_activity("P2", "dkim",
            "Add an Ed25519 DKIM key (dual-sign)",
            ["Generate an ED25519-SHA256 key and publish its selector",
             "Dual-sign every message with RSA-SHA256 + ED25519-SHA256",
             "Keep RSA within 1024–2048 bits; do not advertise SHA-1"],
            "BSI TR-03182-03/04"))
    if dkim.get("any_oversized_rsa"):
        acts.append(_activity("P2", "dkim", "Cap DKIM RSA keys at 2048 bit",
            ["Reissue selectors using RSA keys >2048 bit at 2048 for interop"],
            "BSI TR-03182-03"))
    if dmarc.get("present") and not dmarc.get("strict_alignment"):
        acts.append(_activity("P4", "dmarc", "Enable strict DMARC alignment",
            ["Set adkim=s and aspf=s once all senders align",
             "Confirm no legitimate mail relies on relaxed alignment first"],
            "BSI TR-03182-06 / ACN"))
    if spf.get("uses_ptr"):
        acts.append(_activity("P1", "spf", "Remove the deprecated SPF 'ptr'",
            ["Replace ptr with explicit ip4:/ip6: ranges"],
            "RFC 7208 §5.5"))
    if assessment.get("no_mail") and not (
            spf.get("deny_all") and dmarc.get("policy") == "reject"):
        acts.append(_activity("P1", "spf",
            "Harden this non-sending (parked) domain",
            ["Publish 'v=spf1 -all' (authorise no sender)",
             "Publish DMARC 'p=reject' with an rua address",
             "Ensure a Null MX (RFC 7505) is present"],
            "BSI TR-03182-11"))

    # --- v0.6.0 controls ------------------------------------------------
    hygiene = checks.get("dns_hygiene", {})
    reputation = checks.get("reputation", {})
    subs = checks.get("subdomains", {})
    starttls = checks.get("starttls", {})

    if hygiene.get("dangling_mx") or hygiene.get("takeover_risks"):
        names = list(hygiene.get("dangling_mx") or []) + [
            t["name"] for t in (hygiene.get("takeover_risks") or [])]
        acts.append(_activity("P1", "dns_hygiene",
            "Remove dangling DNS records (takeover exposure)",
            [f"Delete or repoint: {', '.join(names[:6])}",
             "Re-check after every SaaS decommission — a dangling mta-sts or "
             "autodiscover CNAME lets an attacker downgrade or intercept mail"],
            "Operational / RFC 8461 §3.3"))
    if hygiene.get("mx_is_cname"):
        acts.append(_activity("P2", "dns_hygiene",
            "Replace CNAME'd MX targets with A/AAAA records",
            ["Point each MX at a name that has address records directly",
             "Required before DANE TLSA can be published for those hosts"],
            "RFC 2181 §10.3 / RFC 7672"))
    if hygiene and not (hygiene.get("caa") or {}).get("present"):
        acts.append(_activity("P3", "dns_hygiene",
            "Publish a CAA record",
            ["Restrict issuance to the CA(s) actually used",
             "Constrains who can mint a certificate that satisfies MTA-STS"],
            "RFC 8659"))
    if hygiene.get("fcrdns_ok") is False:
        acts.append(_activity("P2", "dns_hygiene",
            "Fix reverse DNS on the mail servers",
            ["Publish a PTR for every MX address",
             "Ensure the PTR name resolves forward to the same address"],
            "Operational deliverability"))
    ns = hygiene.get("nameservers") or []
    if ns and (len(ns) < 2 or hygiene.get("ns_diverse") is False):
        acts.append(_activity("P3", "dns_hygiene",
            "Add nameserver diversity",
            ["Use at least two nameservers across more than one provider",
             "DNS is the shared dependency of SPF, DKIM, DMARC, MTA-STS and "
             "DANE — a single provider outage disables all of them at once"],
            "Operational resilience"))

    if reputation.get("any_listed"):
        acts.append(_activity("P1", "reputation",
            "Resolve blocklist listings",
            ["Identify the compromised host or abusive sender",
             f"Listed: {', '.join(reputation.get('listed_ips') or []) or 'domain'}",
             "Remediate, then request delisting from each operator"],
            "Operational — active abuse indicator"))

    if subs.get("weaker_policy"):
        acts.append(_activity("P2", "subdomains",
            "Remove weaker subdomain DMARC records",
            [f"Raise or delete DMARC at: {', '.join(subs['weaker_policy'][:6])}",
             "A subdomain record overrides the apex sp= entirely"],
            "RFC 7489 §6.6.3"))
    if subs.get("unprotected"):
        acts.append(_activity("P2", "subdomains",
            "Extend DMARC enforcement across the subdomain tree",
            ["Set sp=reject at the apex to cover existing subdomains",
             "Set np=reject to cover names that do not exist (DMARCbis)",
             f"{len(subs['unprotected'])} live subdomain(s) currently spoofable"],
            "DMARCbis"))

    if starttls.get("any_auth_before_tls"):
        acts.append(_activity("P1", "starttls",
            "Stop advertising SMTP AUTH before STARTTLS",
            ["Disable AUTH on the cleartext session (port 25)",
             "Offer authentication only after the TLS handshake"],
            "RFC 4954 §4 / CCN-CERT BP/02"))
    if starttls.get("any_cert_hostname_mismatch") or \
            starttls.get("any_cert_invalid"):
        acts.append(_activity("P1", "starttls",
            "Fix the MX server certificates",
            ["Issue certificates whose SAN covers the MX hostname",
             "Serve the full chain including intermediates",
             "Without this, MTA-STS enforce and DANE both fail"],
            "RFC 8461 §4.1 / RFC 7672"))
    if checks.get("dane", {}).get("mismatched_mx"):
        acts.append(_activity("P1", "dane",
            "Re-publish TLSA records to match the live certificate",
            ["TLSA no longer matches the presented certificate",
             "DANE-validating senders are already refusing delivery",
             "Automate TLSA rollover with the certificate renewal process"],
            "RFC 7672 §8"))

    phases = []
    for pid, label in _PHASES:
        items = [a for a in acts if a["phase"] == pid]
        if items:
            phases.append({"id": pid, "label": label, "activities": items})

    return {
        "domain": assessment.get("domain"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "current_score": assessment.get("score"),
        "current_rating": assessment.get("rating"),
        "target_rating": "very_strong",
        "phases": phases,
        "activity_count": len(acts),
    }


def generate_group_roadmap(assessments: list[dict], scope_label: str) -> dict:
    """Aggregate view: which controls need work across a set of domains."""
    gaps: dict = {}
    for a in assessments:
        for control, score in a.get("control_scores", {}).items():
            if score is None:
                continue
            g = gaps.setdefault(control, {"missing": 0, "partial": 0,
                                          "complete": 0})
            if score == 0:
                g["missing"] += 1
            elif score < 100:
                g["partial"] += 1
            else:
                g["complete"] += 1
    priorities = sorted(
        gaps.items(),
        key=lambda kv: (kv[1]["missing"] * 2 + kv[1]["partial"]),
        reverse=True)
    return {
        "scope": scope_label,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domains": len(assessments),
        "control_gaps": {k: v for k, v in priorities},
        "priority_order": [k for k, _ in priorities],
    }
