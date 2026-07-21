#!/usr/bin/env python3
"""
SEE-Monitor: DKIM Check (RFC 6376 / NIST SP 800-177r1 §4.5)
DKIM selectors cannot be enumerated from DNS alone, so discovery combines:
  1. registered selectors (stored per-domain by analysts/orgs), and
  2. a wordlist of common selectors (ESP defaults).
For every selector found, the public key is parsed for type/length and the
testing flag.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import base64
import logging

from scanner.dns_client import DNSClient

logger = logging.getLogger(__name__)

# Common selectors used by major ESPs and mail platforms.
COMMON_SELECTORS = [
    "default", "selector1", "selector2",          # generic / Microsoft 365
    "google", "20161025", "20230601",             # Google Workspace
    "k1", "k2", "k3",                             # Mailchimp/Mandrill
    "s1", "s2", "smtp",                           # SendGrid / generic
    "mail", "dkim", "email", "key1", "key2",
    "mx", "mta", "m1",
    "zendesk1", "zendesk2",
    "amazonses", "ses",
    "mandrill", "mailjet", "sig1",
    "protonmail", "protonmail2", "protonmail3",
    "zoho", "zmail",
    "cm", "sm", "pm", "krs",
    "sendinblue", "mailgun", "mg",
    "everlytickey1", "everlytickey2",
    "dyn", "spop1024", "postfix",
]

_MIN_RSA_BITS = 2048
_WEAK_RSA_BITS = 1024


def _rsa_bits_from_p(p_b64: str) -> int | None:
    """Estimate RSA modulus size from the base64 SubjectPublicKeyInfo."""
    try:
        der = base64.b64decode("".join(p_b64.split()))
    except Exception:
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = load_der_public_key(der)
        if isinstance(key, rsa.RSAPublicKey):
            return key.key_size
        return None
    except Exception:
        # Fallback heuristic: DER length correlates with modulus size
        n = len(der)
        if n >= 526:
            return 4096
        if n >= 270:
            return 2048
        if n >= 140:
            return 1024
        return 512


def _parse_dkim_record(txt: str) -> dict:
    tags = {}
    for part in txt.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    key_type = tags.get("k", "rsa").lower()
    p = tags.get("p", "")
    rec = {
        "key_type": key_type,
        "revoked": p == "",
        "testing": "y" in tags.get("t", "").lower(),
        "key_bits": None,
    }
    if key_type == "rsa" and p:
        rec["key_bits"] = _rsa_bits_from_p(p)
    elif key_type == "ed25519" and p:
        rec["key_bits"] = 256
    return rec


def _selector_status(rec: dict) -> str:
    if rec["revoked"]:
        return "revoked"
    if rec["key_type"] == "ed25519":
        return "strong"
    bits = rec["key_bits"] or 0
    if bits >= _MIN_RSA_BITS:
        return "strong"
    if bits >= _WEAK_RSA_BITS:
        return "weak"
    return "very_weak"


def check_dkim(domain: str, registered_selectors: list[str] | None = None,
               dns_client: DNSClient | None = None,
               use_wordlist: bool = True,
               passive_selectors: list[str] | None = None) -> dict:
    """
    Discovery order (highest confidence first): per-domain registered
    selectors, selectors surfaced by passive sources (e.g. DNSDumpster), then
    the common-selector wordlist. Every candidate — whatever its source — is
    confirmed with an authoritative TXT lookup before it counts.

    Returns:
      {
        "control": "dkim", "present": bool,
        "selectors": [
          {"selector": str, "source": "registered"|"dnsdumpster"|"wordlist",
           "record": str, "key_type": str, "key_bits": int|None,
           "testing": bool, "revoked": bool, "status": str}
        ],
        "best_status": "strong"|"weak"|"very_weak"|"revoked"|None,
        "any_testing": bool, "issues": [str],
      }
    """
    dc = dns_client or DNSClient()
    out = {"control": "dkim", "present": False, "selectors": [],
           "best_status": None, "any_testing": False, "issues": []}

    candidates: list[tuple[str, str]] = []
    seen = set()
    for s in (registered_selectors or []):
        s = s.strip().lower()
        if s and s not in seen:
            candidates.append((s, "registered"))
            seen.add(s)
    for s in (passive_selectors or []):
        s = s.strip().lower()
        if s and s not in seen:
            candidates.append((s, "dnsdumpster"))
            seen.add(s)
    if use_wordlist:
        for s in COMMON_SELECTORS:
            if s not in seen:
                candidates.append((s, "wordlist"))
                seen.add(s)

    order = {"strong": 3, "weak": 2, "very_weak": 1, "revoked": 0}
    for selector, source in candidates:
        name = f"{selector}._domainkey.{domain}"
        for txt in dc.txt(name):
            low = txt.lower().replace(" ", "")
            if "p=" not in low and "v=dkim1" not in low:
                continue
            rec = _parse_dkim_record(txt)
            status = _selector_status(rec)
            out["selectors"].append({
                "selector": selector, "source": source,
                "record": txt if len(txt) < 600 else txt[:600] + "…",
                "key_type": rec["key_type"], "key_bits": rec["key_bits"],
                "testing": rec["testing"], "revoked": rec["revoked"],
                "status": status,
            })
            if rec["testing"]:
                out["any_testing"] = True
            if not rec["revoked"]:
                out["present"] = True
            if (out["best_status"] is None
                    or order[status] > order[out["best_status"]]):
                out["best_status"] = status
            break  # first TXT at this name is the key record

    if not out["selectors"]:
        out["issues"].append(
            "No DKIM selectors found (wordlist + registered). If the domain "
            "signs mail, register its selectors for accurate scoring.")
    else:
        weak = [s["selector"] for s in out["selectors"]
                if s["status"] in ("weak", "very_weak") and not s["revoked"]]
        if weak:
            out["issues"].append(
                f"Weak DKIM keys (<{_MIN_RSA_BITS} bit RSA): {', '.join(weak)}")
        if out["any_testing"]:
            out["issues"].append(
                "DKIM testing flag (t=y) set — receivers may ignore signatures")
    return out
