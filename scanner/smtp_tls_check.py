#!/usr/bin/env python3
"""
SEE-Monitor: SMTP TLS Check

Determines STARTTLS support per MX host with a passive-first strategy:
  1. Shodan (if configured)
  2. Censys (if configured, as alternative)
  3. Active SMTP probe on port 25 (only if passive sources gave no answer
     and active probing is enabled)

THREE-STATE RESULT (v0.6.0)
---------------------------
Earlier versions collapsed "the server refuses TLS" and "we could not find
out" into a single false verdict, so a firewalled probe or a disabled active
scan manufactured findings identical to a genuine failure. Every host now
carries an explicit status:

    ok       TLS confirmed
    no_tls   STARTTLS confirmed absent or refused
    unknown  no evidence either way — never scored as a failure

`confidence` drops to "low" whenever any host is unknown, and the assessor
scores the control n/a when nothing at all could be determined.

Certificate analysis and the EHLO capability list come from the single
connection the probe already makes; no extra traffic is generated.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging

from scanner.starttls_probe import probe_smtp_starttls, _WEAK_TLS
from scanner.cert_check import analyse_certificate, certificate_issues

logger = logging.getLogger(__name__)


def _blank_verdict(source: str, error: str) -> dict:
    return {"source": source, "status": "unknown", "reachable": False,
            "starttls_ok": False, "tls_version": "", "cipher_suite": "",
            "weak_tls": False, "pkix_valid": None, "cert": None,
            "auth_before_tls": None, "banner": "", "software": None,
            "software_version": None, "error": error}


def _from_passive(info: dict) -> dict | None:
    """Convert a Shodan/Censys host_smtp_info dict to a per-host verdict."""
    if not info.get("found"):
        return None
    p25 = info["ports"].get(25)
    if p25 is None or p25.get("starttls") is None:
        return None
    starttls = bool(p25["starttls"])
    verdict = _blank_verdict(info["source"], "")
    verdict.update({
        "status": "ok" if starttls else "no_tls",
        "reachable": True,
        "starttls_ok": starttls,
        "tls_version": p25.get("tls_version", ""),
        "cipher_suite": p25.get("cipher_suite", ""),
        "weak_tls": p25.get("tls_version", "") in _WEAK_TLS,
    })
    return verdict


def _from_active(mx: str, timeout: int, verify_cert: bool) -> tuple:
    probe = probe_smtp_starttls(mx, 25, timeout=timeout,
                                verify_cert=verify_cert)
    chain = probe.pop("_chain_der", []) or []

    if probe["starttls_ok"]:
        status = "ok"
    elif probe["reachable"] and (probe["starttls_advertised"] is False
                                 or "refused" in (probe["error"] or "")):
        status = "no_tls"
    elif probe["reachable"] and probe["error"].startswith("TLS handshake"):
        status = "no_tls"
    else:
        status = "unknown"

    cert = None
    if chain:
        cert = analyse_certificate(chain, mx, probe.get("pkix_valid"),
                                   probe.get("cert_verify_error", ""))

    verdict = {
        "source": "active",
        "status": status,
        "reachable": probe["reachable"],
        "starttls_ok": probe["starttls_ok"],
        "tls_version": probe["tls_version"],
        "cipher_suite": probe["cipher_suite"],
        "weak_tls": probe["weak_tls"],
        "pkix_valid": probe.get("pkix_valid"),
        "cert": cert,
        "auth_before_tls": probe.get("auth_before_tls"),
        "banner": probe.get("banner", ""),
        "software": probe.get("software"),
        "software_version": probe.get("software_version"),
        "error": probe["error"],
    }
    return verdict, chain


def check_starttls(mx_hosts: list[str],
                   shodan_client=None, censys_client=None,
                   active: bool = True, timeout: int = 10,
                   verify_cert: bool = True) -> dict:
    """
    Returns:
      {
        "control": "starttls", "applicable": bool,
        "hosts": {mx: verdict},
        "supported_count": int, "no_tls_count": int, "unknown_count": int,
        "total": int, "coverage": float|None, "all_starttls": bool|None,
        "any_weak_tls": bool, "any_auth_before_tls": bool,
        "any_cert_invalid": bool, "any_cert_hostname_mismatch": bool,
        "confidence": "high"|"low", "software": {mx: str},
        "_chains": {mx: [der]},        # stripped before persistence
        "issues": [str],
      }
    """
    out = {"control": "starttls", "applicable": bool(mx_hosts),
           "hosts": {}, "supported_count": 0, "no_tls_count": 0,
           "unknown_count": 0, "total": len(mx_hosts or []),
           "coverage": None, "all_starttls": None, "any_weak_tls": False,
           "any_auth_before_tls": False, "any_cert_invalid": False,
           "any_cert_hostname_mismatch": False, "confidence": "high",
           "software": {}, "_chains": {}, "issues": []}
    if not mx_hosts:
        out["issues"].append("No MX hosts — STARTTLS not applicable")
        return out

    for mx in mx_hosts:
        verdict = None
        for client in (shodan_client, censys_client):
            if client is not None and getattr(client, "available", False):
                try:
                    verdict = _from_passive(client.host_smtp_info(mx))
                except Exception as exc:   # passive source must never abort
                    logger.warning("Passive lookup failed for %s: %s", mx, exc)
                    verdict = None
                if verdict:
                    break
        if verdict is None and active:
            verdict, chain = _from_active(mx, timeout, verify_cert)
            if chain:
                out["_chains"][mx] = chain
        if verdict is None:
            verdict = _blank_verdict(
                "none", "no passive data and active probing disabled")

        out["hosts"][mx] = verdict
        if verdict["status"] == "ok":
            out["supported_count"] += 1
        elif verdict["status"] == "no_tls":
            out["no_tls_count"] += 1
        else:
            out["unknown_count"] += 1
        if verdict["weak_tls"]:
            out["any_weak_tls"] = True
        if verdict.get("auth_before_tls"):
            out["any_auth_before_tls"] = True
        if verdict.get("software"):
            out["software"][mx] = " ".join(
                x for x in (verdict["software"], verdict["software_version"])
                if x)
        cert = verdict.get("cert") or {}
        if cert:
            if cert.get("pkix_valid") is False or cert.get("expired") \
                    or cert.get("self_signed"):
                out["any_cert_invalid"] = True
            if cert.get("hostname_match") is False:
                out["any_cert_hostname_mismatch"] = True
            for issue in certificate_issues(cert, mx):
                out["issues"].append(issue)

    known = out["supported_count"] + out["no_tls_count"]
    out["coverage"] = round(out["supported_count"] / known, 2) if known else None
    if out["unknown_count"]:
        out["confidence"] = "low"
    out["all_starttls"] = (out["supported_count"] == out["total"]
                           and out["total"] > 0)

    no_tls = [mx for mx, v in out["hosts"].items() if v["status"] == "no_tls"]
    unknown = [mx for mx, v in out["hosts"].items() if v["status"] == "unknown"]
    if no_tls:
        out["issues"].append(
            "STARTTLS not offered by: " + ", ".join(no_tls)
            + " — mail to these hosts crosses the Internet in cleartext")
    if unknown:
        out["issues"].append(
            "STARTTLS status could not be determined for: " + ", ".join(unknown)
            + " (scored as unknown, not as a failure)")
    if out["any_weak_tls"]:
        weak = [mx for mx, v in out["hosts"].items() if v["weak_tls"]]
        out["issues"].append(
            "Deprecated TLS version (<1.2) on: " + ", ".join(weak))
    if out["any_auth_before_tls"]:
        hosts = [mx for mx, v in out["hosts"].items()
                 if v.get("auth_before_tls")]
        out["issues"].append(
            "SMTP AUTH advertised on the cleartext session by: "
            + ", ".join(hosts)
            + " — a client that does not insist on STARTTLS will send "
              "credentials in the clear")
    disclosed = {mx: s for mx, s in out["software"].items() if s}
    if disclosed:
        out["issues"].append(
            "MTA software and version disclosed in the SMTP banner: "
            + ", ".join(f"{mx} ({s})" for mx, s in disclosed.items()))
    return out
