#!/usr/bin/env python3
"""
SEE-Monitor: Active SMTP STARTTLS Probe (RFC 3207 / NIST SP 800-177r1 §5.1)
Non-intrusive: EHLO, STARTTLS, TLS handshake, QUIT. Records whether STARTTLS
is advertised/accepted and the negotiated TLS version + cipher.

Adapted from PQC-Monitor's starttls_probe (protocol-based dispatch lesson).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import socket
import ssl
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_WEAK_TLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


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


def probe_smtp_starttls(host: str, port: int = 25, timeout: int = 10,
                        helo_name: str = "see-monitor.invalid") -> dict:
    """
    Returns:
      {"host", "port", "timestamp", "reachable", "starttls_advertised",
       "starttls_ok", "tls_version", "cipher_suite", "cipher_bits",
       "weak_tls", "cert_subject", "cert_expired", "error"}
    """
    ts = datetime.now(timezone.utc).isoformat()
    out = {"host": host, "port": port, "timestamp": ts, "source": "active",
           "reachable": False, "starttls_advertised": False,
           "starttls_ok": False, "tls_version": "", "cipher_suite": "",
           "cipher_bits": 0, "weak_tls": False, "cert_subject": "",
           "cert_expired": None, "error": ""}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        out["reachable"] = True
        banner = _recv_multiline(sock, timeout)
        if not banner.startswith(b"220"):
            out["error"] = f"Unexpected banner: {banner[:80]!r}"
            return out
        sock.sendall(f"EHLO {helo_name}\r\n".encode())
        ehlo = _recv_multiline(sock, timeout)
        out["starttls_advertised"] = b"STARTTLS" in ehlo.upper()
        sock.sendall(b"STARTTLS\r\n")
        resp = _recv_multiline(sock, timeout)
        if not resp.startswith(b"220"):
            out["error"] = f"STARTTLS refused: {resp[:80]!r}"
            return out

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        tls = ctx.wrap_socket(sock, server_hostname=host)
        out["starttls_ok"] = True
        out["tls_version"] = tls.version() or ""
        cip = tls.cipher()
        if cip:
            out["cipher_suite"], _, out["cipher_bits"] = cip
        out["weak_tls"] = out["tls_version"] in _WEAK_TLS
        try:
            der = tls.getpeercert(binary_form=True)
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
        sock = None
    except (socket.timeout, ConnectionError, OSError) as exc:
        out["error"] = str(exc)
    except ssl.SSLError as exc:
        out["error"] = f"TLS handshake failed: {exc}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return out
