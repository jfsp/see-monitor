#!/usr/bin/env python3
"""
SEE-Monitor: Email Security Assessor
Converts scan results into per-control scores (0-100), a weighted domain
score, and a rating: not_implemented / medium / strong / very_strong.

All weights, rating bands and the very-strong enforcement requirements come
from guidelines/nist_800_177r1.json and can be overridden via config.yaml:

    scoring:
      weights: {dmarc: 0.25, ...}
      rating_bands: [...]

Lesson carried over from PQC-Monitor: if a domain has no MX and refuses mail
(null MX), transport controls are 'na' and never silently scored as failures.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import logging
import os

logger = logging.getLogger(__name__)

_GUIDELINE_DIR = os.path.join(os.path.dirname(__file__), "..", "guidelines")

DEFAULT_GUIDELINE = "nist_800_177r1"
RATING_ORDER = ["not_implemented", "medium", "strong", "very_strong"]


def _guideline_path(guideline_id: str) -> str:
    return os.path.join(_GUIDELINE_DIR, f"{guideline_id}.json")


def available_guidelines() -> list[str]:
    """Guideline profile ids installed under guidelines/*.json."""
    try:
        return sorted(
            f[:-5] for f in os.listdir(_GUIDELINE_DIR) if f.endswith(".json"))
    except OSError:
        return [DEFAULT_GUIDELINE]


def load_guideline(config: dict | None = None,
                   guideline_id: str = DEFAULT_GUIDELINE) -> dict:
    with open(_guideline_path(guideline_id), encoding="utf-8") as fh:
        guideline = json.load(fh)
    # config overrides apply only to the default guideline, so per-profile
    # weights in the JSON files are never silently clobbered.
    overrides = (config or {}).get("scoring") or {}
    if guideline_id == DEFAULT_GUIDELINE and overrides:
        if "weights" in overrides:
            guideline["weights"].update(overrides["weights"])
        if "rating_bands" in overrides:
            guideline["rating_bands"] = overrides["rating_bands"]
        if "very_strong_requirements" in overrides:
            guideline.setdefault("very_strong_requirements", {}).update(
                overrides["very_strong_requirements"])
    return guideline


# ----------------------------------------------------------------------
# Named compliance predicates (profile 'required_signals' entries).
# Each returns True (met), False (unmet) or None (not applicable -> treated
# as met for gating; never blocks a rating).
# ----------------------------------------------------------------------
def _sig(checks: dict, no_mail: bool):
    spf = checks.get("spf", {})
    dkim = checks.get("dkim", {})
    dmarc = checks.get("dmarc", {})
    dnssec = checks.get("dnssec", {})
    starttls = checks.get("starttls", {})
    client = checks.get("client_tls", {})

    def dmarc_ok():
        return dmarc.get("present") and dmarc.get("valid")

    return {
        # SPF
        "spf_softfail_or_fail": (spf.get("all_qualifier") in ("-", "~"))
        if spf.get("present") else False,
        "spf_hardfail": (spf.get("all_qualifier") == "-")
        if spf.get("present") else False,
        "spf_all_last": spf.get("all_is_last") if spf.get("present") else False,
        "spf_no_ptr": (not spf.get("uses_ptr")) if spf.get("present") else None,
        # DMARC
        "dmarc_quarantine_or_reject":
            (dmarc.get("policy") in ("quarantine", "reject"))
            if dmarc_ok() else False,
        "dmarc_reject": (dmarc.get("policy") == "reject")
        if dmarc_ok() else False,
        "dmarc_sp_reject": (dmarc.get("subdomain_policy") == "reject")
        if dmarc_ok() else False,
        "dmarc_strict_alignment": bool(dmarc.get("strict_alignment"))
        if dmarc_ok() else False,
        "dmarc_rua": bool(dmarc.get("rua")) if dmarc_ok() else False,
        "dmarc_no_ruf": (not dmarc.get("has_ruf")) if dmarc_ok() else False,
        "dmarc_ruf": bool(dmarc.get("has_ruf")) if dmarc_ok() else False,
        # DKIM
        "dkim_present": bool(dkim.get("present")),
        "dkim_ed25519": bool(dkim.get("has_ed25519"))
        if dkim.get("present") else False,
        "dkim_rsa_bounded": (not dkim.get("any_oversized_rsa"))
        if dkim.get("has_rsa") else None,
        "dkim_no_sha1": (not dkim.get("any_sha1_hash"))
        if dkim.get("present") else None,
        "dkim_strong": (dkim.get("best_status") == "strong")
        if dkim.get("present") else False,
        # Transport / DNSSEC
        "dnssec_valid": bool(dnssec.get("signed")
                             and dnssec.get("validated") is True),
        "starttls_all_mx": None if (no_mail or not starttls.get("applicable"))
        else bool(starttls.get("all_starttls")),
        "client_tls_all": None if not client.get("applicable")
        else bool(client.get("all_tls")),
        # Parked / non-sending domains (BSI TR-03182-11)
        "parked_hardened": (bool(spf.get("deny_all"))
                            and dmarc.get("policy") == "reject")
        if no_mail else None,
    }


_SIGNAL_LABELS = {
    "spf_softfail_or_fail": "SPF must end in ~all or -all",
    "spf_hardfail": "SPF must end in -all (hardfail)",
    "spf_all_last": "SPF 'all' must be the final mechanism",
    "spf_no_ptr": "SPF must not use the deprecated 'ptr' mechanism",
    "dmarc_quarantine_or_reject": "DMARC policy must be quarantine or reject",
    "dmarc_reject": "DMARC policy must be reject",
    "dmarc_sp_reject": "DMARC subdomain policy (sp) must be reject",
    "dmarc_strict_alignment": "DMARC must use strict alignment (adkim=s; aspf=s)",
    "dmarc_rua": "DMARC must publish an aggregate report address (rua)",
    "dmarc_no_ruf": "DMARC must not request forensic reports (ruf) — GDPR",
    "dmarc_ruf": "DMARC should request forensic reports (ruf)",
    "dkim_present": "DKIM signing must be deployed",
    "dkim_ed25519": "DKIM must include an Ed25519 key (dual RSA + Ed25519)",
    "dkim_rsa_bounded": "DKIM RSA keys must not exceed 2048 bits",
    "dkim_no_sha1": "DKIM must not advertise SHA-1",
    "dkim_strong": "DKIM key must be strong (RSA>=2048 or Ed25519)",
    "dnssec_valid": "Zone must be DNSSEC-signed and validate",
    "starttls_all_mx": "All MX hosts must offer STARTTLS",
    "client_tls_all": "Submission/retrieval services must enforce TLS",
    "parked_hardened": "Parked domain must publish 'v=spf1 -all' and DMARC reject",
}


# ----------------------------------------------------------------------
# Per-control scoring (0-100, or None => not applicable)
# ----------------------------------------------------------------------
def _score_spf(c: dict) -> int:
    if not c.get("present"):
        return 0
    if not c.get("valid"):
        return 10                       # multiple records => permerror
    q = c.get("all_qualifier")
    base = {"-": 100, "~": 70, "?": 40, "+": 20}.get(q, 0)
    if base == 0 and c.get("has_redirect"):
        base = 60                       # policy delegated via redirect
    if c.get("exceeds_lookup_limit"):
        base = min(base, 30)            # permerror in practice
    return base


def _score_dkim(c: dict) -> int:
    status = c.get("best_status")
    if not c.get("present") or status is None:
        return 0
    base = {"strong": 100, "weak": 40, "very_weak": 10, "revoked": 0}[status]
    if c.get("any_testing"):
        base = min(base, 60)
    return base


def _score_dmarc(c: dict) -> int:
    if not c.get("present"):
        return 0
    if not c.get("valid"):
        return 10
    p = c.get("policy")
    has_rua = bool(c.get("rua"))
    if p == "reject":
        base = 100
    elif p == "quarantine":
        base = 70
    else:                               # none
        base = 40 if has_rua else 20
    if p in ("quarantine", "reject"):
        if c.get("pct", 100) < 100:
            base -= 10
        if not has_rua:
            base -= 5
        sp = c.get("subdomain_policy") or p
        if ("none", "quarantine", "reject").index(sp) < \
                ("none", "quarantine", "reject").index(p):
            base -= 10
    return max(0, base)


def _score_dnssec(c: dict) -> int:
    if not c.get("signed"):
        return 0
    if c.get("validated") is False:
        return 10                       # bogus chain is worse than useless
    if c.get("validated") is None:
        return 70                       # signed, validation unconfirmed
    return 100


def _score_dane(c: dict) -> int | None:
    if not c.get("applicable"):
        return None
    if not c.get("mx_with_tlsa"):
        return 0
    cov = c.get("coverage", 0.0)
    base = 100 if cov >= 1.0 else 50
    if not c.get("usable"):
        base = min(base, 30)            # TLSA without valid DNSSEC
    return base


def _score_mta_sts(c: dict) -> int:
    if not c.get("present"):
        return 0
    if not c.get("policy_fetched"):
        return 20
    mode = c.get("mode")
    base = {"enforce": 100, "testing": 60, "none": 10}.get(mode, 20)
    if base == 100 and c.get("mx_covered") is False:
        base = 70
    return base


def _score_tlsrpt(c: dict) -> int:
    if not c.get("present"):
        return 0
    return 100 if c.get("rua") else 60


def _score_starttls(c: dict) -> int | None:
    if not c.get("applicable"):
        return None
    if c.get("supported_count", 0) == 0:
        return 0
    base = 100 if c.get("all_starttls") else 50
    if c.get("any_weak_tls"):
        base = min(base, 60)
    return base


def _score_bimi(c: dict) -> int:
    if not c.get("present"):
        return 0
    return 100 if c.get("vmc_url") else 70


def _score_client_tls(c: dict) -> int | None:
    # CCN-CERT BP/02 submission/retrieval TLS. n/a unless RFC 6186 SRV records
    # advertise the services.
    if not c.get("applicable"):
        return None
    if c.get("advertised_count", 0) == 0:
        return None
    base = 100 if c.get("all_tls") else round(
        100 * c.get("tls_ok_count", 0) / c["advertised_count"])
    if c.get("any_weak_tls"):
        base = min(base, 60)
    return base


_SCORERS = {
    "spf": _score_spf, "dkim": _score_dkim, "dmarc": _score_dmarc,
    "dnssec": _score_dnssec, "dane": _score_dane, "mta_sts": _score_mta_sts,
    "tlsrpt": _score_tlsrpt, "starttls": _score_starttls, "bimi": _score_bimi,
    "client_tls": _score_client_tls,
}


# ----------------------------------------------------------------------
# Domain-level assessment
# ----------------------------------------------------------------------
def _meets_very_strong(checks: dict, reqs: dict) -> bool:
    spf, dkim, dmarc = checks.get("spf", {}), checks.get("dkim", {}), \
        checks.get("dmarc", {})
    if spf.get("all_qualifier") != reqs.get("spf_all_qualifier", "-"):
        return False
    if dmarc.get("policy") != reqs.get("dmarc_policy", "reject"):
        return False
    if dkim.get("best_status") != reqs.get("dkim_min_status", "strong"):
        return False
    st = checks.get("starttls", {})
    if reqs.get("starttls_all_mx", True) and st.get("applicable") \
            and not st.get("all_starttls"):
        return False
    channel_ok = False
    for opt in reqs.get("channel_enforcement_any_of", []):
        if opt == "mta_sts_enforce" and \
                checks.get("mta_sts", {}).get("mode") == "enforce":
            channel_ok = True
        if opt == "dane_full":
            dane = checks.get("dane", {})
            if dane.get("usable") and dane.get("coverage", 0) >= 1.0:
                channel_ok = True
    return channel_ok


def assess_domain(scan: dict, config: dict | None = None,
                  guideline_id: str = DEFAULT_GUIDELINE) -> dict:
    """
    Input: output of ScanOrchestrator.scan_domain().
    Scores the domain against a single guideline profile (default: NIST).
    Returns:
      {
        "domain", "assessed_at", "guideline", "score" (0-100 float),
        "rating", "control_scores": {control: int|None},
        "findings": [{"control", "severity", "message"}],
        "compliance": {signal: bool|None}, "compliant": bool|None,
        "no_mail": bool,
      }
    """
    guideline = load_guideline(config, guideline_id)
    checks = scan.get("checks", {})
    mx = checks.get("mx", {})
    no_mail = (not mx.get("has_mx")) or mx.get("null_mx", False)
    weights = guideline["weights"]

    control_scores: dict = {}
    findings: list = []
    for control, scorer in _SCORERS.items():
        c = checks.get(control, {})
        score = scorer(c)
        # Domains that do not receive mail: transport controls are n/a
        if no_mail and control in ("starttls", "dane", "mta_sts", "tlsrpt",
                                   "client_tls"):
            score = None
        control_scores[control] = score
        # Only surface issues for controls this profile actually weighs, so a
        # BSI report is not cluttered with (unweighted) BIMI notes, etc.
        if float(weights.get(control, 0)) <= 0 and control not in (
                "spf", "dkim", "dmarc"):
            continue
        for issue in c.get("issues", []):
            sev = "info"
            if score is not None:
                sev = "critical" if score == 0 else \
                      "warning" if score < 70 else "info"
            findings.append(
                {"control": control, "severity": sev, "message": issue})

    if mx.get("invalid_records"):
        findings.append({
            "control": "mx", "severity": "warning",
            "message": "Malformed MX records ignored: "
                       + ", ".join(mx["invalid_records"])})

    num = den = 0.0
    for control, score in control_scores.items():
        if score is None:
            continue
        w = float(weights.get(control, 0))
        num += w * score
        den += w
    total = round(num / den, 1) if den > 0 else 0.0

    bands = sorted(guideline["rating_bands"], key=lambda b: b["min_score"])
    rating = bands[0]["rating"] if bands else "not_implemented"
    for band in bands:
        if total >= band["min_score"]:
            rating = band["rating"]
    top_rating = bands[-1]["rating"] if bands else rating
    demote_to = bands[-2]["rating"] if len(bands) >= 2 else rating

    # ---- Compliance gating -------------------------------------------
    # Legacy NIST path (weighted 'very_strong' enforcement requirements).
    compliance: dict = {}
    compliant = None
    if "required_signals" in guideline:
        sigs = _sig(checks, no_mail)
        required = guideline["required_signals"]
        compliance = {name: sigs.get(name) for name in required}
        unmet = [n for n in required if compliance.get(n) is False]
        compliant = not unmet
        for n in unmet:
            findings.append({
                "control": "profile", "severity": "warning",
                "message": _SIGNAL_LABELS.get(n, n)})
        if not compliant and rating == top_rating:
            rating = demote_to
    elif "very_strong_requirements" in guideline:
        if rating == top_rating and not _meets_very_strong(
                checks, guideline["very_strong_requirements"]):
            rating = demote_to

    return {
        "domain": scan.get("domain"),
        "assessed_at": scan.get("scanned_at"),
        "guideline": guideline["id"],
        "score": total,
        "rating": rating,
        "control_scores": control_scores,
        "findings": findings,
        "compliance": compliance,
        "compliant": compliant,
        "no_mail": no_mail,
    }


def assess_all_profiles(scan: dict, config: dict | None = None,
                        guideline_ids: list[str] | None = None) -> dict:
    """Assess one scan against several profiles. Returns {guideline_id: assessment}."""
    ids = guideline_ids or available_guidelines()
    out = {}
    for gid in ids:
        try:
            out[gid] = assess_domain(scan, config, gid)
        except FileNotFoundError:
            logger.warning("Guideline profile not found: %s", gid)
    return out
