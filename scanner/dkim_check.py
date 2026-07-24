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
    # h= is an optional colon-separated list of ACCEPTABLE hash algorithms.
    hashes = [h.strip().lower() for h in tags.get("h", "").split(":")
              if h.strip()]
    rec = {
        "key_type": key_type,
        "revoked": p == "",
        "testing": "y" in tags.get("t", "").lower(),
        "key_bits": None,
        "hash_algorithms": hashes,
        "allows_sha1": "sha1" in hashes,   # BSI TR-03182-05: SHA-1 discontinued
        "oversized_rsa": False,            # BSI TR-03182-03: RSA must be <= 2048
    }
    if key_type == "rsa" and p:
        rec["key_bits"] = _rsa_bits_from_p(p)
        rec["oversized_rsa"] = bool(rec["key_bits"] and rec["key_bits"] > 2048)
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
           "best_status": None, "any_testing": False,
           # v0.6.0: DKIM selectors cannot be enumerated from DNS, so the
           # absence of a wordlist hit is NOT evidence that a domain does not
           # sign. status/confidence let the assessor score "unknown" instead
           # of punishing a domain for using a private selector name.
           "status": "unknown", "confidence": "low", "evidence": "none",
           "registered_selectors": len(registered_selectors or []),
           # BSI TR-03182-03/04/05 algorithm-agility signals (non-revoked keys)
           "algorithms": [], "has_rsa": False, "has_ed25519": False,
           "any_oversized_rsa": False, "any_sha1_hash": False, "issues": []}

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
                "hash_algorithms": rec["hash_algorithms"],
                "allows_sha1": rec["allows_sha1"],
                "oversized_rsa": rec["oversized_rsa"],
                "status": status,
            })
            if rec["testing"]:
                out["any_testing"] = True
            if not rec["revoked"]:
                out["present"] = True
                if rec["key_type"] == "ed25519":
                    out["has_ed25519"] = True
                elif rec["key_type"] == "rsa":
                    out["has_rsa"] = True
                if rec["oversized_rsa"]:
                    out["any_oversized_rsa"] = True
                if rec["allows_sha1"]:
                    out["any_sha1_hash"] = True
            if (out["best_status"] is None
                    or order[status] > order[out["best_status"]]):
                out["best_status"] = status
            break  # first TXT at this name is the key record

    algs = []
    if out["has_rsa"]:
        algs.append("rsa")
    if out["has_ed25519"]:
        algs.append("ed25519")
    out["algorithms"] = algs

    # ---- Evidence quality --------------------------------------------
    sources = {s["source"] for s in out["selectors"]}
    if out["selectors"]:
        if "registered" in sources:
            out["evidence"], out["confidence"] = "registered", "high"
        elif sources & {"dnsdumpster", "securitytrails"}:
            out["evidence"], out["confidence"] = "passive", "medium"
        else:
            out["evidence"], out["confidence"] = "wordlist", "medium"
        out["status"] = "present" if out["present"] else "revoked"
    elif registered_selectors:
        # Selectors were asserted for this domain and none of them resolve:
        # that is a genuine, high-confidence negative.
        out["evidence"], out["confidence"] = "registered", "high"
        out["status"] = "absent"
    else:
        out["evidence"], out["confidence"] = "none", "low"
        out["status"] = "unknown"

    if not out["selectors"]:
        if out["status"] == "absent":
            out["issues"].append(
                "None of the registered DKIM selectors resolve — the domain "
                "does not publish a usable DKIM key")
        else:
            out["issues"].append(
                "No DKIM selectors found by wordlist or passive discovery. "
                "Selectors are not enumerable from DNS, so this is NOT proof "
                "that the domain does not sign — DKIM is scored as unknown. "
                "Register the domain's selectors for a conclusive result.")
    else:
        weak = [s["selector"] for s in out["selectors"]
                if s["status"] in ("weak", "very_weak") and not s["revoked"]]
        if weak:
            out["issues"].append(
                f"Weak DKIM keys (<{_MIN_RSA_BITS} bit RSA): {', '.join(weak)}")
        if out["any_testing"]:
            out["issues"].append(
                "DKIM testing flag (t=y) set — receivers may ignore signatures")
        if out["present"] and not out["has_ed25519"]:
            out["issues"].append(
                "No Ed25519 (ED25519-SHA256) key alongside RSA — BSI TR-03182-04 "
                "requires dual RSA-SHA256 + ED25519-SHA256 signing")
        if out["any_oversized_rsa"]:
            out["issues"].append(
                "RSA key exceeds 2048 bit — BSI TR-03182-03 caps RSA at 2048 for "
                "interoperability")
        if out["any_sha1_hash"]:
            out["issues"].append(
                "DKIM key advertises SHA-1 (h=sha1) — discontinued (RFC 8301)")
    return out
