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

_GUIDELINE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guidelines", "nist_800_177r1.json")

RATING_ORDER = ["not_implemented", "medium", "strong", "very_strong"]


def load_guideline(config: dict | None = None) -> dict:
    with open(_GUIDELINE_PATH, encoding="utf-8") as fh:
        guideline = json.load(fh)
    overrides = (config or {}).get("scoring") or {}
    if "weights" in overrides:
        guideline["weights"].update(overrides["weights"])
    if "rating_bands" in overrides:
        guideline["rating_bands"] = overrides["rating_bands"]
    if "very_strong_requirements" in overrides:
        guideline["very_strong_requirements"].update(
            overrides["very_strong_requirements"])
    return guideline


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


_SCORERS = {
    "spf": _score_spf, "dkim": _score_dkim, "dmarc": _score_dmarc,
    "dnssec": _score_dnssec, "dane": _score_dane, "mta_sts": _score_mta_sts,
    "tlsrpt": _score_tlsrpt, "starttls": _score_starttls, "bimi": _score_bimi,
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


def assess_domain(scan: dict, config: dict | None = None) -> dict:
    """
    Input: output of ScanOrchestrator.scan_domain().
    Returns:
      {
        "domain", "assessed_at", "guideline", "score" (0-100 float),
        "rating", "control_scores": {control: int|None},
        "findings": [{"control", "severity", "message"}],
        "no_mail": bool,
      }
    """
    guideline = load_guideline(config)
    checks = scan.get("checks", {})
    mx = checks.get("mx", {})
    no_mail = (not mx.get("has_mx")) or mx.get("null_mx", False)

    control_scores: dict = {}
    findings: list = []
    for control, scorer in _SCORERS.items():
        c = checks.get(control, {})
        score = scorer(c)
        # Domains that do not receive mail: transport controls are n/a
        if no_mail and control in ("starttls", "dane", "mta_sts", "tlsrpt"):
            score = None
        control_scores[control] = score
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

    weights = guideline["weights"]
    num = den = 0.0
    for control, score in control_scores.items():
        if score is None:
            continue
        w = float(weights.get(control, 0))
        num += w * score
        den += w
    total = round(num / den, 1) if den > 0 else 0.0

    rating = "not_implemented"
    for band in sorted(guideline["rating_bands"], key=lambda b: b["min_score"]):
        if total >= band["min_score"]:
            rating = band["rating"]
    if rating == "very_strong" and not _meets_very_strong(
            checks, guideline["very_strong_requirements"]):
        rating = "strong"

    return {
        "domain": scan.get("domain"),
        "assessed_at": scan.get("scanned_at"),
        "guideline": guideline["id"],
        "score": total,
        "rating": rating,
        "control_scores": control_scores,
        "findings": findings,
        "no_mail": no_mail,
    }
