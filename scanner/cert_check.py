#!/usr/bin/env python3
"""
SEE-Monitor: X.509 Certificate Analysis + DANE/TLSA matching

Evaluates the certificate presented by a mail server on a connection that has
ALREADY been established by starttls_probe (no additional connections are made
here — everything below is offline analysis of DER bytes).

Signals produced:
  - hostname match (SAN dNSName, wildcard-aware; CN fallback is reported but
    not treated as a match: RFC 6125 / CA-B Forum deprecated CN matching)
  - validity window (expired / not yet valid / days remaining)
  - self-signed (issuer == subject and single-element chain)
  - signature algorithm (SHA-1 and MD5 flagged) and public-key strength
  - chain completeness (leaf only vs leaf + intermediates)

MTA-STS 'enforce' (RFC 8461 §4.1) requires a PKIX-valid certificate whose
identity matches the MX host, so these signals decide whether a published
MTA-STS policy would actually work in practice.

DANE (RFC 7672): TLSA parsing, usability rules and digest matching against the
certificate chain actually presented by the server.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import hashlib
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Signature algorithms considered obsolete for publicly trusted certificates.
_WEAK_SIGALGS = ("md5", "sha1")

# RFC 7672 §3.1.3: only DANE-TA(2) and DANE-EE(3) are usable for SMTP.
TLSA_USAGE = {0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE"}
TLSA_SELECTOR = {0: "full-cert", 1: "spki"}
TLSA_MATCHING = {0: "exact", 1: "sha256", 2: "sha512"}
_DIGEST_LEN = {1: 32, 2: 64}


# ----------------------------------------------------------------------
# Certificate parsing
# ----------------------------------------------------------------------
def _load(der: bytes):
    from cryptography import x509
    return x509.load_der_x509_certificate(der)


def _san_names(cert) -> list[str]:
    from cryptography import x509
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
        return [n.lower().rstrip(".")
                for n in ext.value.get_values_for_type(x509.DNSName)]
    except Exception:
        return []


def _common_name(cert) -> str | None:
    from cryptography.x509.oid import NameOID
    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value.lower().rstrip(".") if attrs else None
    except Exception:
        return None


def _name_matches(host: str, pattern: str) -> bool:
    """RFC 6125 hostname matching: one leading wildcard label only."""
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if not pattern:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]                    # ".example.com"
        if not host.endswith(suffix):
            return False
        left = host[: -len(suffix)]
        return bool(left) and "." not in left   # wildcard spans one label
    return False


def _key_info(cert) -> tuple[str, int | None]:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            return "rsa", pub.key_size
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return "ecdsa", pub.curve.key_size
        if isinstance(pub, ed25519.Ed25519PublicKey):
            return "ed25519", 256
        return type(pub).__name__.lower(), None
    except Exception:
        return "unknown", None


def analyse_certificate(chain_der: list[bytes], hostname: str,
                        pkix_valid=None, pkix_error: str = "") -> dict:
    """
    Offline analysis of a presented certificate chain.

    chain_der: [leaf, intermediate, ...] as DER bytes (may be a single entry).
    pkix_valid: authoritative PKIX result from the live handshake, when the
      probe performed a verifying handshake. Offline path validation is only
      attempted as a fallback, and only when a full chain was captured —
      validating a leaf-only chain would manufacture false "untrusted"
      findings on servers that are in fact correctly configured.
    Returns a dict of signals; 'error' is set when the leaf cannot be parsed.
    """
    out = {"parsed": False, "subject": "", "issuer": "", "chain_length": 0,
           "san": [], "common_name": None, "hostname_match": None,
           "matched_name": None, "wildcard": False,
           "not_before": None, "not_after": None, "expired": None,
           "not_yet_valid": None, "days_remaining": None,
           "self_signed": None, "signature_algorithm": None,
           "weak_signature": None, "key_type": None, "key_bits": None,
           "weak_key": None, "chain_incomplete": None,
           "pkix_valid": None, "pkix_error": "", "error": ""}
    if not chain_der:
        out["error"] = "no certificate presented"
        return out
    try:
        leaf = _load(chain_der[0])
    except Exception as exc:
        out["error"] = f"certificate parse failed: {exc}"
        return out

    out["parsed"] = True
    out["chain_length"] = len(chain_der)
    try:
        out["subject"] = leaf.subject.rfc4514_string()
        out["issuer"] = leaf.issuer.rfc4514_string()
    except Exception:
        pass

    san = _san_names(leaf)
    out["san"] = san[:32]
    out["common_name"] = _common_name(leaf)
    host = (hostname or "").lower().rstrip(".")
    if host:
        for pattern in san:
            if _name_matches(host, pattern):
                out["hostname_match"] = True
                out["matched_name"] = pattern
                out["wildcard"] = pattern.startswith("*.")
                break
        else:
            out["hostname_match"] = False

    now = datetime.now(timezone.utc)
    try:
        nb = leaf.not_valid_before_utc
        na = leaf.not_valid_after_utc
    except AttributeError:                      # cryptography < 42
        nb = leaf.not_valid_before.replace(tzinfo=timezone.utc)
        na = leaf.not_valid_after.replace(tzinfo=timezone.utc)
    out["not_before"] = nb.isoformat()
    out["not_after"] = na.isoformat()
    out["expired"] = na < now
    out["not_yet_valid"] = nb > now
    out["days_remaining"] = int((na - now).total_seconds() // 86400)

    out["self_signed"] = (leaf.issuer == leaf.subject)
    try:
        alg = (leaf.signature_algorithm_oid._name or "").lower()
    except Exception:
        alg = ""
    out["signature_algorithm"] = alg or None
    out["weak_signature"] = any(w in alg for w in _WEAK_SIGALGS)

    ktype, kbits = _key_info(leaf)
    out["key_type"] = ktype
    out["key_bits"] = kbits
    if ktype == "rsa" and kbits:
        out["weak_key"] = kbits < 2048
    elif ktype == "ecdsa" and kbits:
        out["weak_key"] = kbits < 256
    else:
        out["weak_key"] = False

    # A server that sends only the leaf forces the client to build the chain
    # itself; many MTAs will fail PKIX validation as a result.
    out["chain_incomplete"] = (len(chain_der) < 2 and not out["self_signed"])

    if pkix_valid is not None:
        out["pkix_valid"] = bool(pkix_valid)
        out["pkix_error"] = pkix_error
    elif host and len(chain_der) > 1:
        valid, err = verify_chain_pkix(chain_der, host)
        out["pkix_valid"] = valid
        out["pkix_error"] = err
    else:
        out["pkix_valid"] = None
        out["pkix_error"] = pkix_error or "chain not captured in full"
    return out


_ca_store = None
_ca_store_loaded = False


def _system_store():
    """Load the system trust store once (cryptography >= 42)."""
    global _ca_store, _ca_store_loaded
    if _ca_store_loaded:
        return _ca_store
    _ca_store_loaded = True
    try:
        import ssl
        from cryptography import x509
        from cryptography.x509.verification import Store
        cafile = ssl.get_default_verify_paths().cafile
        if not cafile:
            return None
        with open(cafile, "rb") as fh:
            certs = x509.load_pem_x509_certificates(fh.read())
        _ca_store = Store(certs)
    except Exception as exc:                    # pragma: no cover
        logger.debug("System trust store unavailable: %s", exc)
        _ca_store = None
    return _ca_store


def verify_chain_pkix(chain_der: list[bytes], hostname: str) -> tuple:
    """
    Offline PKIX path validation of a presented chain against the system trust
    store. No network access and no extra TLS connection — the chain captured
    by the STARTTLS probe is all that is needed.

    Returns (valid, error): valid is True/False, or None when validation could
    not be attempted (old cryptography, no CA bundle). None must never be
    scored as a failure.
    """
    if not chain_der or not hostname:
        return None, "no chain or hostname"
    store = _system_store()
    if store is None:
        return None, "system trust store unavailable"
    try:
        from cryptography import x509
        from cryptography.x509.verification import PolicyBuilder
        from cryptography.x509.general_name import DNSName
    except Exception:
        try:
            from cryptography import x509
            from cryptography.x509.verification import PolicyBuilder
            from cryptography.x509 import DNSName
        except Exception as exc:
            return None, f"verification API unavailable: {exc}"
    try:
        leaf = x509.load_der_x509_certificate(chain_der[0])
        intermediates = [x509.load_der_x509_certificate(d)
                         for d in chain_der[1:]]
        verifier = PolicyBuilder().store(store).build_server_verifier(
            DNSName(hostname))
        verifier.verify(leaf, intermediates)
        return True, ""
    except Exception as exc:
        return False, str(exc)


def certificate_issues(info: dict, hostname: str) -> list[str]:
    """Human-readable findings for one MX certificate."""
    issues: list[str] = []
    if not info.get("parsed"):
        if info.get("error"):
            issues.append(f"{hostname}: {info['error']}")
        return issues
    if info.get("expired"):
        issues.append(f"{hostname}: certificate expired ({info['not_after']})")
    elif info.get("not_yet_valid"):
        issues.append(f"{hostname}: certificate not yet valid")
    elif (info.get("days_remaining") is not None
            and info["days_remaining"] < 30):
        issues.append(
            f"{hostname}: certificate expires in {info['days_remaining']} days")
    if info.get("hostname_match") is False:
        issues.append(
            f"{hostname}: certificate does not match the MX hostname "
            f"(SAN: {', '.join(info.get('san') or []) or 'none'}) — MTA-STS "
            "enforce and RFC 8689 strict transport would fail")
    if info.get("self_signed"):
        issues.append(
            f"{hostname}: self-signed certificate — not PKIX-trustworthy "
            "(usable only via DANE-EE)")
    if info.get("weak_signature"):
        issues.append(
            f"{hostname}: weak certificate signature algorithm "
            f"({info.get('signature_algorithm')})")
    if info.get("weak_key"):
        issues.append(
            f"{hostname}: weak certificate key "
            f"({info.get('key_type')} {info.get('key_bits')} bit)")
    if info.get("pkix_valid") is False and not info.get("self_signed"):
        issues.append(
            f"{hostname}: certificate does not chain to a trusted root "
            f"({info.get('pkix_error') or 'PKIX validation failed'}) — "
            "MTA-STS enforce would reject this server")
    if info.get("chain_incomplete"):
        issues.append(
            f"{hostname}: server sent no intermediate certificates — "
            "chain building may fail on strict senders")
    return issues


# ----------------------------------------------------------------------
# DANE / TLSA
# ----------------------------------------------------------------------
def parse_tlsa(rdata_text: str) -> dict | None:
    """Parse a TLSA rdata string: '<usage> <selector> <matching> <hex>'."""
    parts = rdata_text.split()
    if len(parts) < 4:
        return None
    try:
        usage, selector, matching = int(parts[0]), int(parts[1]), int(parts[2])
    except ValueError:
        return None
    digest = "".join(parts[3:]).replace(":", "").lower()
    rec = {
        "usage": usage, "selector": selector, "matching": matching,
        "usage_name": TLSA_USAGE.get(usage, f"unknown({usage})"),
        "selector_name": TLSA_SELECTOR.get(selector, f"unknown({selector})"),
        "matching_name": TLSA_MATCHING.get(matching, f"unknown({matching})"),
        "digest": digest,
        # RFC 7672 §3.1.3: PKIX-TA(0)/PKIX-EE(1) are not usable for SMTP.
        "smtp_usable": usage in (2, 3),
        "digest_length_ok": True,
        "issues": [],
    }
    expected = _DIGEST_LEN.get(matching)
    if expected is not None:
        rec["digest_length_ok"] = len(digest) == expected * 2
        if not rec["digest_length_ok"]:
            rec["issues"].append(
                f"TLSA {usage} {selector} {matching}: digest is "
                f"{len(digest) // 2} bytes, expected {expected}")
    elif matching == 0:
        rec["issues"].append(
            "TLSA matching type 0 (full certificate) — RFC 7672 recommends "
            "SHA-256 (1); full certs bloat the response and break on renewal")
    else:
        rec["issues"].append(f"Unknown TLSA matching type {matching}")
    if not rec["smtp_usable"]:
        rec["issues"].append(
            f"TLSA usage {usage} ({rec['usage_name']}) is not usable for SMTP "
            "— RFC 7672 requires DANE-TA(2) or DANE-EE(3)")
    if selector not in TLSA_SELECTOR:
        rec["issues"].append(f"Unknown TLSA selector {selector}")
    return rec


def _tlsa_digest(der: bytes, selector: int, matching: int) -> str | None:
    """Compute the TLSA association data for a certificate."""
    try:
        if selector == 0:
            data = der
        elif selector == 1:
            from cryptography.hazmat.primitives import serialization
            cert = _load(der)
            data = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            return None
    except Exception:
        return None
    if matching == 0:
        return data.hex()
    if matching == 1:
        return hashlib.sha256(data).hexdigest()
    if matching == 2:
        return hashlib.sha512(data).hexdigest()
    return None


def match_tlsa(records: list[dict], chain_der: list[bytes]) -> dict:
    """
    Compare parsed TLSA records against the presented chain.

    DANE-EE(3) must match the leaf; DANE-TA(2) must match a CA in the chain.
    Returns {"checked": bool, "matched": bool|None, "matched_record": str|None}.
    'matched' is None when no chain was captured (cannot be judged).
    """
    out = {"checked": False, "matched": None, "matched_record": None,
           "incomplete_chain": False}
    if not records or not chain_der:
        return out
    out["checked"] = True
    unevaluable = False
    for rec in records:
        if not rec.get("smtp_usable"):
            continue
        if rec["usage"] == 2 and len(chain_der) < 2:
            # DANE-TA(2) associates a CA certificate. With only the leaf
            # captured we cannot decide, and must not report a mismatch.
            unevaluable = True
            continue
        candidates = chain_der[:1] if rec["usage"] == 3 else chain_der
        for der in candidates:
            digest = _tlsa_digest(der, rec["selector"], rec["matching"])
            if digest and digest == rec["digest"]:
                out["matched"] = True
                out["matched_record"] = (
                    f"{rec['usage']} {rec['selector']} {rec['matching']}")
                return out
    if unevaluable:
        out["incomplete_chain"] = True
        out["matched"] = None
    else:
        out["matched"] = False
    return out
