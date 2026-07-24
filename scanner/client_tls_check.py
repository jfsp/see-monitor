#!/usr/bin/env python3
"""
SEE-Monitor: Client-facing TLS Check (submission + retrieval)

CCN-CERT BP/02 recommends that users' mail submission and retrieval always run
over TLS: SMTP submission on 587 (STARTTLS) or 465 (implicit TLS), IMAP over
TLS on 993, POP3 over TLS on 995 — and that the cleartext variants (25-auth,
143, 110) are avoided.

Unlike inbound MX (which is discoverable from the MX RRset), submission and
retrieval hosts are client configuration. The only DNS-observable, standards-
based way to locate them is RFC 6186 SRV records:
    _submission._tcp   (587, STARTTLS)
    _submissions._tcp  (465, implicit TLS)
    _imaps._tcp        (993, implicit TLS)
    _pop3s._tcp        (995, implicit TLS)

This check is therefore APPLICABLE only when such SRV records exist. When they
do, each advertised host:port is probed for a working TLS session. Absence of
SRV records => applicable=False => the control is scored n/a (never a failure),
consistent with the no-mail transport-control convention.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import socket
import ssl
import logging
from datetime import datetime, timezone

from scanner.dns_client import DNSClient
from scanner.starttls_probe import _recv_multiline, _WEAK_TLS

logger = logging.getLogger(__name__)

# service -> (SRV name, default port, mode)   mode: "starttls" | "implicit"
# Conventional client-endpoint names. Almost no domain publishes RFC 6186 SRV
# records, so SRV-only discovery makes this control n/a nearly everywhere. The
# presence of these names is DNS-observable and is reported as ATTACK SURFACE;
# their TLS posture is not probed here (that needs connections to submission/
# IMAP/POP ports — see README "Future features").
_CONVENTIONAL_NAMES = ["mail", "smtp", "imap", "pop", "pop3", "webmail",
                       "autodiscover", "autoconfig", "owa", "exchange"]

_SRV_SERVICES = {
    "submission":  ("_submission._tcp",  587, "starttls"),
    "submissions": ("_submissions._tcp", 465, "implicit"),
    "imaps":       ("_imaps._tcp",       993, "implicit"),
    "pop3s":       ("_pop3s._tcp",       995, "implicit"),
}


def _srv_targets(domain: str, srv_name: str, dc: DNSClient) -> list[tuple]:
    """Return [(host, port)] for an SRV RRset, skipping the '.' (no service)."""
    targets = []
    for r in dc.query(f"{srv_name}.{domain}", "SRV"):
        try:
            host = str(r.target).rstrip(".").lower()
            port = int(r.port)
        except Exception:
            continue
        if host and host != ".":
            targets.append((host, port))
    return targets


def _probe_implicit_tls(host: str, port: int, timeout: int) -> dict:
    out = {"reachable": False, "tls_ok": False, "tls_version": "",
           "weak_tls": False, "error": ""}
    sock = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        sock = socket.create_connection((host, port), timeout=timeout)
        out["reachable"] = True
        tls = ctx.wrap_socket(sock, server_hostname=host)
        out["tls_ok"] = True
        out["tls_version"] = tls.version() or ""
        out["weak_tls"] = out["tls_version"] in _WEAK_TLS
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


def _probe_starttls_submission(host: str, port: int, timeout: int) -> dict:
    """EHLO -> STARTTLS -> handshake on the submission port (587)."""
    out = {"reachable": False, "tls_ok": False, "tls_version": "",
           "weak_tls": False, "error": ""}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        out["reachable"] = True
        banner = _recv_multiline(sock, timeout)
        if not banner.startswith(b"220"):
            out["error"] = f"Unexpected banner: {banner[:80]!r}"
            return out
        sock.sendall(b"EHLO see-monitor.invalid\r\n")
        ehlo = _recv_multiline(sock, timeout)
        if b"STARTTLS" not in ehlo.upper():
            out["error"] = "STARTTLS not advertised on submission port"
            return out
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
        out["tls_ok"] = True
        out["tls_version"] = tls.version() or ""
        out["weak_tls"] = out["tls_version"] in _WEAK_TLS
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


def check_client_tls(domain: str, dns_client: DNSClient | None = None,
                     active: bool = True, timeout: int = 10) -> dict:
    """
    Returns:
      {
        "control": "client_tls", "applicable": bool,
        "services": {name: {"host","port","mode","reachable","tls_ok",
                            "tls_version","weak_tls","error"}},
        "advertised": [name], "tls_ok_count": int, "advertised_count": int,
        "all_tls": bool, "any_weak_tls": bool, "issues": [str],
      }
    applicable=False when the domain advertises no RFC 6186 SRV records.
    """
    dc = dns_client or DNSClient()
    out = {"control": "client_tls", "applicable": False, "services": {},
           "advertised": [], "tls_ok_count": 0, "advertised_count": 0,
           "all_tls": False, "any_weak_tls": False,
           # v0.6.0: passive discovery of conventional client endpoints
           "conventional_hosts": [], "autodiscover": False,
           "autoconfig": False, "srv_published": False,
           "checked_at": datetime.now(timezone.utc).isoformat(), "issues": []}

    for label in _CONVENTIONAL_NAMES:
        name = f"{label}.{domain}"
        if dc.query(name, "A") or dc.query(name, "AAAA") \
                or dc.query(name, "CNAME"):
            out["conventional_hosts"].append(name)
            if label == "autodiscover":
                out["autodiscover"] = True
            elif label == "autoconfig":
                out["autoconfig"] = True

    discovered = {}
    for name, (srv, _port, mode) in _SRV_SERVICES.items():
        targets = _srv_targets(domain, srv, dc)
        if targets:
            discovered[name] = (targets[0][0], targets[0][1], mode)

    if not discovered:
        out["issues"].append(
            "No RFC 6186 SRV records (_submission/_imaps/_pop3s) — client "
            "TLS posture not DNS-advertised (n/a)")
        if out["conventional_hosts"]:
            out["issues"].append(
                "Client mail endpoints exist under conventional names ("
                + ", ".join(out["conventional_hosts"])
                + ") but publish no RFC 6186 SRV records: clients must be "
                  "configured manually, and their TLS enforcement cannot be "
                  "verified without connecting to submission/IMAP/POP ports")
        if out["autodiscover"]:
            out["issues"].append(
                f"autodiscover.{domain} is published — verify it is not a "
                "stale CNAME to a third party; Autodiscover endpoints have "
                "been used to harvest client credentials")
        return out

    out["srv_published"] = True
    out["applicable"] = True
    out["advertised"] = sorted(discovered)
    out["advertised_count"] = len(discovered)

    for name, (host, port, mode) in discovered.items():
        if not active:
            out["services"][name] = {"host": host, "port": port, "mode": mode,
                                     "reachable": False, "tls_ok": False,
                                     "tls_version": "", "weak_tls": False,
                                     "error": "active probing disabled"}
            continue
        if mode == "starttls":
            r = _probe_starttls_submission(host, port, timeout)
        else:
            r = _probe_implicit_tls(host, port, timeout)
        r.update({"host": host, "port": port, "mode": mode})
        out["services"][name] = r
        if r["tls_ok"]:
            out["tls_ok_count"] += 1
        if r["weak_tls"]:
            out["any_weak_tls"] = True

    out["all_tls"] = (out["tls_ok_count"] == out["advertised_count"]
                      and out["advertised_count"] > 0)
    failed = [n for n, s in out["services"].items() if not s["tls_ok"]]
    if failed:
        out["issues"].append("Client TLS not confirmed on: " + ", ".join(failed))
    if out["any_weak_tls"]:
        weak = [n for n, s in out["services"].items() if s["weak_tls"]]
        out["issues"].append("Deprecated TLS (<1.2) on: " + ", ".join(weak))
    return out
