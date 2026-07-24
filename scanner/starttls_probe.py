#!/usr/bin/env python3
"""
SEE-Monitor: Active SMTP STARTTLS Probe (RFC 3207 / NIST SP 800-177r1 §5.1)

Non-intrusive: EHLO, STARTTLS, TLS handshake, QUIT. No mail transaction is ever
started (no MAIL FROM / RCPT TO), no authentication is attempted and no
additional SMTP verbs are issued.

Everything the assessment needs is derived from that single exchange:
  * whether STARTTLS is advertised and accepted
  * the negotiated TLS version and cipher
  * whether PKIX validation of the server certificate succeeds
  * the certificate itself, for hostname/expiry/algorithm analysis and for
    DANE/TLSA matching
  * the greeting banner (software and version disclosure)
  * the EHLO capability list, in particular AUTH offered BEFORE STARTTLS,
    which exposes credentials to any on-path observer

Connection budget: one connection per host. A second connection is made only
when PKIX validation fails, in order to retrieve the certificate that the
aborted handshake did not deliver.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import re
import socket
import ssl
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_WEAK_TLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")

# Banner software fingerprints. Version disclosure is not itself a
# vulnerability, but it tells an attacker which exploit to try and is a decent
# proxy for patch discipline. Version->CVE mapping is deliberately NOT done
# here (see README "Future features").
_MTA_HINTS = ("postfix", "exim", "sendmail", "microsoft", "exchange",
              "zimbra", "opensmtpd", "haraka", "mdaemon", "postal", "halon",
              "proofpoint", "mimecast", "barracuda", "smtpd")
_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)*)\b")


def _fingerprint(banner: str) -> tuple:
    """Return (software, version) guessed from the SMTP greeting."""
    low = (banner or "").lower()
    software = next((h for h in _MTA_HINTS if h in low), None)
    match = _VERSION_RE.search(banner or "")
    return software, (match.group(1) if match else None)


def _recv_multiline(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """Read a (possibly multi-line) SMTP response. Final line: '<code> …'."""
    buf = b""
    sock.settimeout(timeout)
    while True:
        line = b""
        while not line.endswith(b"\n"):
            try:
                c = sock.recv(1)
            except socket.timeout:
                return buf
            if not c:
                return buf
            line += c
        buf += line
        if len(line) >= 4 and line[3:4] == b" ":
            return buf
        if len(line) < 4:
            return buf


def _context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    if verify:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
        except Exception:                        # pragma: no cover
            pass
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _session(host: str, port: int, timeout: int, helo_name: str,
             verify: bool, out: dict) -> str:
    """
    One connect → banner → EHLO → STARTTLS → handshake exchange.

    Populates *out* in place and returns "":
      ok           handshake completed
      cert         handshake failed PKIX validation
      no_starttls  STARTTLS not offered or refused
      error        transport/protocol failure (out["error"] is set)
    """
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        out["reachable"] = True
        banner = _recv_multiline(sock, timeout)
        out["banner"] = banner.decode("utf-8", "replace").strip()[:300]
        out["software"], out["software_version"] = _fingerprint(out["banner"])
        out["version_disclosed"] = bool(out["software_version"])
        if not banner.startswith(b"220"):
            out["error"] = f"Unexpected banner: {banner[:80]!r}"
            return "error"

        sock.sendall(f"EHLO {helo_name}\r\n".encode())
        ehlo = _recv_multiline(sock, timeout)
        ehlo_text = ehlo.decode("utf-8", "replace")
        caps = []
        for line in ehlo_text.splitlines():
            if len(line) > 4 and line[:3].isdigit():
                caps.append(line[4:].strip())
        out["ehlo_capabilities"] = caps[:32]
        out["starttls_advertised"] = b"STARTTLS" in ehlo.upper()
        for cap in caps:
            if cap.upper().startswith("AUTH"):
                out["auth_before_tls"] = True
                out["auth_mechanisms"] = cap.split()[1:][:8]
                break
        if not out["starttls_advertised"]:
            out["error"] = "STARTTLS not advertised"
            return "no_starttls"

        sock.sendall(b"STARTTLS\r\n")
        resp = _recv_multiline(sock, timeout)
        if not resp.startswith(b"220"):
            out["error"] = f"STARTTLS refused: {resp[:80]!r}"
            return "no_starttls"

        tls = _context(verify).wrap_socket(sock, server_hostname=host)
        sock = None
        out["starttls_ok"] = True
        out["error"] = ""
        out["tls_version"] = tls.version() or ""
        cip = tls.cipher()
        if cip:
            out["cipher_suite"], _, out["cipher_bits"] = cip
        out["weak_tls"] = out["tls_version"] in _WEAK_TLS
        try:
            der = tls.getpeercert(binary_form=True)
            out["_chain_der"] = [der] if der else []
            if der:
                from cryptography import x509
                cert = x509.load_der_x509_certificate(der)
                out["cert_subject"] = cert.subject.rfc4514_string()
                out["cert_expired"] = (
                    cert.not_valid_after_utc < datetime.now(timezone.utc))
        except Exception:
            pass
        try:
            tls.sendall(b"QUIT\r\n")
        except OSError:
            pass
        tls.close()
        return "ok"
    except ssl.SSLCertVerificationError as exc:
        out["cert_verify_error"] = str(exc)
        return "cert"
    except ssl.SSLError as exc:
        out["error"] = f"TLS handshake failed: {exc}"
        return "error"
    except (socket.timeout, ConnectionError, OSError) as exc:
        out["error"] = str(exc)
        return "error"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_smtp_starttls(host: str, port: int = 25, timeout: int = 10,
                        helo_name: str = "see-monitor.invalid",
                        verify_cert: bool = True) -> dict:
    """
    Returns:
      {"host", "port", "timestamp", "source", "reachable",
       "starttls_advertised", "starttls_ok", "tls_version", "cipher_suite",
       "cipher_bits", "weak_tls", "cert_subject", "cert_expired",
       "pkix_valid", "cert_verify_error", "banner", "software",
       "software_version", "version_disclosed", "ehlo_capabilities",
       "auth_before_tls", "auth_mechanisms", "_chain_der", "error"}

    "_chain_der" holds raw DER bytes for offline certificate and DANE analysis.
    It is stripped by the orchestrator before anything is persisted.
    """
    ts = datetime.now(timezone.utc).isoformat()
    out = {"host": host, "port": port, "timestamp": ts, "source": "active",
           "reachable": False, "starttls_advertised": False,
           "starttls_ok": False, "tls_version": "", "cipher_suite": "",
           "cipher_bits": 0, "weak_tls": False, "cert_subject": "",
           "cert_expired": None, "pkix_valid": None, "cert_verify_error": "",
           "banner": "", "software": None, "software_version": None,
           "version_disclosed": False, "ehlo_capabilities": [],
           "auth_before_tls": False, "auth_mechanisms": [],
           "_chain_der": [], "error": ""}

    result = _session(host, port, timeout, helo_name, verify_cert, out)
    if result == "ok":
        out["pkix_valid"] = True if verify_cert else None
        return out
    if result == "cert":
        # The verified handshake was aborted before we could see the
        # certificate; reconnect once, without verification, to retrieve it.
        out["pkix_valid"] = False
        _session(host, port, timeout, helo_name, False, out)
    return out
