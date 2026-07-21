#!/usr/bin/env python3
"""
SEE-Monitor: SMTP TLS Check
Determines STARTTLS support per MX host with a passive-first strategy:
  1. Shodan (if configured)
  2. Censys (if configured, as alternative)
  3. Active SMTP probe on port 25 (only if passive sources gave no answer
     and active probing is enabled)

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging

from scanner.starttls_probe import probe_smtp_starttls, _WEAK_TLS

logger = logging.getLogger(__name__)


def _from_passive(info: dict) -> dict | None:
    """Convert a Shodan/Censys host_smtp_info dict to a per-host verdict."""
    if not info.get("found"):
        return None
    p25 = info["ports"].get(25)
    if p25 is None or p25.get("starttls") is None:
        return None
    return {
        "source": info["source"],
        "reachable": True,
        "starttls_ok": bool(p25["starttls"]),
        "tls_version": p25.get("tls_version", ""),
        "cipher_suite": p25.get("cipher_suite", ""),
        "weak_tls": p25.get("tls_version", "") in _WEAK_TLS,
        "error": "",
    }


def check_starttls(mx_hosts: list[str],
                   shodan_client=None, censys_client=None,
                   active: bool = True, timeout: int = 10) -> dict:
    """
    Returns:
      {
        "control": "starttls", "applicable": bool,
        "hosts": {mx: {"source", "reachable", "starttls_ok", "tls_version",
                       "cipher_suite", "weak_tls", "error"}},
        "supported_count": int, "total": int, "coverage": float,
        "all_starttls": bool, "any_weak_tls": bool, "issues": [str],
      }
    """
    out = {"control": "starttls", "applicable": bool(mx_hosts),
           "hosts": {}, "supported_count": 0, "total": len(mx_hosts or []),
           "coverage": 0.0, "all_starttls": False, "any_weak_tls": False,
           "issues": []}
    if not mx_hosts:
        out["issues"].append("No MX hosts — STARTTLS not applicable")
        return out

    for mx in mx_hosts:
        verdict = None
        for client in (shodan_client, censys_client):
            if client is not None and getattr(client, "available", False):
                try:
                    verdict = _from_passive(client.host_smtp_info(mx))
                except Exception as exc:      # passive source must never abort scan
                    logger.warning("Passive lookup failed for %s: %s", mx, exc)
                    verdict = None
                if verdict:
                    break
        if verdict is None and active:
            probe = probe_smtp_starttls(mx, 25, timeout=timeout)
            verdict = {
                "source": "active",
                "reachable": probe["reachable"],
                "starttls_ok": probe["starttls_ok"],
                "tls_version": probe["tls_version"],
                "cipher_suite": probe["cipher_suite"],
                "weak_tls": probe["weak_tls"],
                "error": probe["error"],
            }
        if verdict is None:
            verdict = {"source": "none", "reachable": False,
                       "starttls_ok": False, "tls_version": "",
                       "cipher_suite": "", "weak_tls": False,
                       "error": "no passive data and active probing disabled"}
        out["hosts"][mx] = verdict
        if verdict["starttls_ok"]:
            out["supported_count"] += 1
        if verdict["weak_tls"]:
            out["any_weak_tls"] = True

    n = out["total"]
    out["coverage"] = round(out["supported_count"] / n, 2) if n else 0.0
    out["all_starttls"] = out["supported_count"] == n and n > 0

    missing = [mx for mx, v in out["hosts"].items() if not v["starttls_ok"]]
    unknown = [mx for mx, v in out["hosts"].items()
               if not v["reachable"] and v["source"] == "none"]
    if missing:
        if set(missing) == set(unknown):
            out["issues"].append(
                "STARTTLS status unknown for: " + ", ".join(unknown))
        else:
            out["issues"].append(
                "STARTTLS not confirmed on: " + ", ".join(missing))
    if out["any_weak_tls"]:
        weak = [mx for mx, v in out["hosts"].items() if v["weak_tls"]]
        out["issues"].append(
            "Deprecated TLS version (<1.2) on: " + ", ".join(weak))
    return out
