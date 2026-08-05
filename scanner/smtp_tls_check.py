#!/usr/bin/env python3
"""
SEE-Monitor: SMTP Transport TLS Check

Determines the TLS posture of a domain's SMTP transport across three ports per
MX host:

    25   inbound MTA-to-MTA STARTTLS   (RFC 3207 / NIST SP 800-177r1 §5.1)
    587  submission STARTTLS           (RFC 8314) — folded in from v0.7.0
    465  submission implicit TLS       (RFC 8314) — folded in from v0.7.0

Evidence is gathered from up to four sources and reconciled:

    local active   our own STARTTLS handshake from this host (richest: TLS
                   version, cipher, certificate, EHLO caps, AUTH-before-TLS)
    passive        Shodan / Censys historical banner scans
    remote active  MXToolbox SMTP lookup (egress-independent: sees the target
                   even when our host cannot open port 25 outbound)

RECONCILE (strategy = "reconcile", the default; v0.7.0)
-------------------------------------------------------
Every configured source is consulted and votes are combined by precedence:

  1. A positive STARTTLS observation from ANY active source (local OR remote)
     confirms the control -> ok. A successful handshake is hard to fake; a
     negative can be network-specific.
  2. Otherwise a reachable local active probe that saw STARTTLS absent/refused
     -> no_tls.
  3. Otherwise a reachable remote active (MXToolbox) negative -> no_tls.
  4. Otherwise passive banner evidence -> ok / no_tls (lower confidence).
  5. Otherwise unknown (never scored as a failure).

When sources disagree the active result wins and an informational issue records
the disagreement (a stale-passive-intel signal). Other strategies:
active_first, passive_first (legacy), active_only, passive_only.

EGRESS-25 DETECTION
-------------------
If active probing is enabled but every inbound (port 25) local connection fails
at the transport layer, that is almost certainly this host's own outbound-25
filtering rather than N independently broken servers. The check flags
egress25_blocked and (where a remote/passive source rescued the verdict) still
scores; where nothing rescued it, the host is unknown, not a failure.

Certificate analysis and the EHLO capability list come from the single MX:25
connection the probe already makes; 587/465 add one connection each per host.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging

from scanner.starttls_probe import (probe_smtp_starttls,
                                     probe_submission_starttls,
                                     probe_implicit_tls, _WEAK_TLS)
from scanner.cert_check import analyse_certificate, certificate_issues

logger = logging.getLogger(__name__)

_INBOUND_PORT = 25
_SUBMISSION_PORTS = (587,)
_IMPLICIT_PORTS = (465,)

# Egress-25 is a HOST condition, not a per-domain one: warn once per process so
# a community-wide scan does not emit the same WARNING hundreds of times.
_EGRESS_WARNED = False


def _warn_egress_once():
    global _EGRESS_WARNED
    if not _EGRESS_WARNED:
        logger.warning(
            "Outbound TCP port 25 appears BLOCKED on this host — every local "
            "SMTP connection failed at the transport layer. Inbound STARTTLS "
            "verdicts will rely on passive (Shodan/Censys) and, if configured, "
            "remote-active (MXToolbox) sources. On GCP this block is permanent "
            "and cannot be lifted; see HANDOVER for egress-independent options.")
        _EGRESS_WARNED = True


def _blank_verdict(source: str, error: str, port: int, role: str) -> dict:
    return {"source": source, "status": "unknown", "reachable": False,
            "starttls_ok": False, "tls_version": "", "cipher_suite": "",
            "weak_tls": False, "pkix_valid": None, "cert": None,
            "auth_before_tls": None, "banner": "", "software": None,
            "software_version": None, "port": port, "role": role,
            "sources": [], "disagreement": False, "error": error}


def _passive_port(info: dict, port: int):
    """Return starttls bool|None + (tls_version, cipher) for a port, or None."""
    if not info or not info.get("found"):
        return None
    p = info.get("ports", {}).get(port)
    if p is None or p.get("starttls") is None:
        return None
    return (bool(p["starttls"]), p.get("tls_version", ""),
            p.get("cipher_suite", ""))


def _passive_verdict(clients, mx: str, port: int, role: str):
    """First usable Shodan/Censys verdict for (mx, port), else None."""
    for client in clients:
        if client is None or not getattr(client, "available", False):
            continue
        try:
            info = client.host_smtp_info(mx)
        except Exception as exc:
            logger.warning("Passive lookup failed for %s:%d: %s", mx, port, exc)
            continue
        got = _passive_port(info, port)
        if got is not None:
            starttls, ver, cipher = got
            v = _blank_verdict(info.get("source", "passive"), "", port, role)
            v.update({"status": "ok" if starttls else "no_tls",
                      "reachable": True, "starttls_ok": starttls,
                      "tls_version": ver, "cipher_suite": cipher,
                      "weak_tls": ver in _WEAK_TLS})
            return v
    return None


def _active_inbound(mx: str, timeout: int, verify_cert: bool,
                    helo_name: str) -> tuple:
    """Local active MX:25 probe -> (verdict, chain, transport_failed)."""
    probe = probe_smtp_starttls(mx, _INBOUND_PORT, timeout=timeout,
                                helo_name=helo_name, verify_cert=verify_cert)
    chain = probe.pop("_chain_der", []) or []
    err = probe.get("error") or ""

    if probe["starttls_ok"]:
        status = "ok"
    elif probe["reachable"] and (probe["starttls_advertised"] is False
                                 or "refused" in err):
        status = "no_tls"
    elif probe["reachable"] and err.startswith("TLS handshake"):
        status = "no_tls"
    else:
        status = "unknown"

    # transport_failed => connection never established (egress-25 signal)
    transport_failed = (not probe["reachable"])

    cert = None
    if chain:
        cert = analyse_certificate(chain, mx, probe.get("pkix_valid"),
                                   probe.get("cert_verify_error", ""))
    verdict = {
        "source": "active", "status": status, "reachable": probe["reachable"],
        "starttls_ok": probe["starttls_ok"], "tls_version": probe["tls_version"],
        "cipher_suite": probe["cipher_suite"], "weak_tls": probe["weak_tls"],
        "pkix_valid": probe.get("pkix_valid"), "cert": cert,
        "auth_before_tls": probe.get("auth_before_tls"),
        "banner": probe.get("banner", ""), "software": probe.get("software"),
        "software_version": probe.get("software_version"),
        "port": _INBOUND_PORT, "role": "inbound", "sources": [],
        "disagreement": False, "error": err}
    return verdict, chain, transport_failed


def _mxt_status(v: dict) -> str:
    if not v.get("reachable"):
        return "unknown"
    if v.get("starttls") is True:
        return "ok"
    if v.get("starttls") is False:
        return "no_tls"
    return "unknown"


def _reconcile_inbound(mx, active_v, remote_votes, passive_v, strategy):
    """
    Combine votes for MX:25 into one verdict.

    active_v      local active probe verdict (richest; carries cert/EHLO) or None
    remote_votes  list of remote-active votes (mxtoolbox/ssltools/internetnl),
                  each {"source","status","tls_version","weak_tls"}
    passive_v     first Shodan/Censys verdict or None
    """
    # Unified vote list. Local + remote testers are the "active" tier (they all
    # actually connect on 25); Shodan/Censys are "passive". Lower prio wins ties.
    votes = []
    if active_v is not None:
        votes.append({"source": "active", "tier": "active",
                      "status": active_v["status"], "prio": 0, "v": active_v})
    for i, rv in enumerate(remote_votes or []):
        votes.append({"source": rv["source"], "tier": "active",
                      "status": rv.get("status", "unknown"),
                      "prio": 5 + i, "v": rv})
    if passive_v is not None:
        votes.append({"source": passive_v["source"], "tier": "passive",
                      "status": passive_v["status"], "prio": 20, "v": passive_v})

    active_votes = sorted((x for x in votes if x["tier"] == "active"),
                          key=lambda x: x["prio"])
    passive_votes = [x for x in votes if x["tier"] == "passive"]

    def _pick(seq, want):
        for x in seq:
            if x["status"] == want:
                return x
        return None

    def _first_definite(seq):
        for x in seq:
            if x["status"] in ("ok", "no_tls"):
                return x
        return None

    def _decide():
        if strategy == "active_only":
            return (_first_definite(active_votes)
                    or {"status": "unknown", "source": "none"})
        if strategy == "passive_only":
            return (_first_definite(passive_votes)
                    or {"status": "unknown", "source": "none"})
        if strategy == "passive_first":
            return (_first_definite(passive_votes)
                    or _first_definite(active_votes)
                    or {"status": "unknown", "source": "none"})
        if strategy == "active_first":
            return (_first_definite(active_votes)
                    or _first_definite(passive_votes)
                    or {"status": "unknown", "source": "none"})
        # default reconcile: a positive active observation wins (hard to fake),
        # then any active negative, then passive.
        return (_pick(active_votes, "ok")
                or _pick(active_votes, "no_tls")
                or _first_definite(passive_votes)
                or {"status": "unknown", "source": "none"})

    win = _decide()
    status = win["status"]
    determined_by = win["source"]

    definite = {x["source"]: x["status"] for x in votes
                if x["status"] in ("ok", "no_tls")}
    disagreement = len(set(definite.values())) > 1

    base = active_v or (win.get("v") if isinstance(win.get("v"), dict) else None) \
        or _blank_verdict("none", "no evidence", _INBOUND_PORT, "inbound")
    out = dict(base)
    out["status"] = status
    out["determined_by"] = determined_by
    out["sources"] = [{"source": x["source"], "status": x["status"]}
                      for x in votes]
    out["disagreement"] = disagreement
    # If a non-local source decided the verdict, reflect its TLS details.
    if determined_by not in ("active", "none") and isinstance(win.get("v"), dict):
        wv = win["v"]
        out["starttls_ok"] = (status == "ok")
        out["tls_version"] = wv.get("tls_version", "") or out.get("tls_version", "")
        out["weak_tls"] = wv.get("weak_tls", out.get("weak_tls", False))
        out["source"] = determined_by
    return out


def _submission_entry(mx, port, timeout, helo_name, passive_clients):
    """Local active submission (587) probe with passive fallback."""
    r = probe_submission_starttls(mx, port, timeout=timeout,
                                  helo_name=helo_name)
    if r["reachable"]:
        status = "ok" if r["starttls_ok"] else "no_tls"
        src = "active"
    else:
        pv = _passive_verdict(passive_clients, mx, port, "submission")
        if pv is not None:
            return {**pv, "port": port, "role": "submission",
                    "determined_by": pv["source"]}
        status, src = "unknown", "active"
    v = _blank_verdict(src, r.get("error", ""), port, "submission")
    v.update({"status": status, "reachable": r["reachable"],
              "starttls_ok": r["starttls_ok"], "tls_version": r["tls_version"],
              "weak_tls": r["weak_tls"], "determined_by": src})
    return v


def _implicit_entry(mx, port, timeout, passive_clients):
    """Local active implicit-TLS (465) probe with passive fallback."""
    r = probe_implicit_tls(mx, port, timeout=timeout)
    if r["reachable"]:
        status = "ok" if r["starttls_ok"] else "no_tls"
        src = "active"
    else:
        pv = _passive_verdict(passive_clients, mx, port, "implicit")
        if pv is not None:
            return {**pv, "port": port, "role": "implicit",
                    "determined_by": pv["source"]}
        status, src = "unknown", "active"
    v = _blank_verdict(src, r.get("error", ""), port, "implicit")
    v.update({"status": status, "reachable": r["reachable"],
              "starttls_ok": r["starttls_ok"], "tls_version": r["tls_version"],
              "weak_tls": r["weak_tls"], "determined_by": src})
    return v


def check_starttls(mx_hosts, shodan_client=None, censys_client=None,
                   active=True, timeout=10, verify_cert=True,
                   helo_name="escbmail.eu", strategy="reconcile",
                   mxtoolbox_client=None, domain=None,
                   ssltools_client=None, internetnl_result=None,
                   submission_ports=_SUBMISSION_PORTS,
                   implicit_ports=_IMPLICIT_PORTS) -> dict:
    """
    Returns a control result. Counts are blended across 25/587/465 (they drive
    the score); all_starttls is computed over inbound (25) hosts only (it drives
    the "all MX offer STARTTLS" requirement). Keys of note:

      hosts: {label: verdict}  label is bare MX for :25, "mx:port" otherwise
      supported_count/no_tls_count/unknown_count/total/coverage  (blended)
      mx_count      distinct MX hosts probed
      by_port       {25:{ok,no_tls,unknown}, 587:{...}, 465:{...}}
      all_starttls  inbound-only
      egress25_blocked  heuristic: every local :25 connect failed at transport
      _chains       {mx: [der]}  (stripped before persistence)
    """
    strategy = (strategy or "reconcile").lower()
    passive_clients = (shodan_client, censys_client)
    passive_enabled = strategy not in ("active_only",)
    active_enabled = active and strategy not in ("passive_only",)

    out = {"control": "starttls", "applicable": bool(mx_hosts),
           "strategy": strategy, "helo_name": helo_name,
           "hosts": {}, "supported_count": 0, "no_tls_count": 0,
           "unknown_count": 0, "total": 0, "mx_count": len(mx_hosts or []),
           "coverage": None, "all_starttls": None, "any_weak_tls": False,
           "any_auth_before_tls": False, "any_cert_invalid": False,
           "any_cert_hostname_mismatch": False, "confidence": "high",
           "software": {}, "_chains": {},
           "by_port": {}, "egress25_blocked": False, "issues": []}
    if not mx_hosts:
        out["issues"].append("No MX hosts — SMTP transport TLS not applicable")
        return out

    mxt_enabled = (mxtoolbox_client is not None
                   and getattr(mxtoolbox_client, "available", False)
                   and strategy not in ("passive_only",))
    mxt_mode = getattr(mxtoolbox_client, "mode", "off") if mxt_enabled else "off"

    # ssl-tools is per-DOMAIN: fetch once, then match MX hosts to its rows.
    ssltools_enabled = (ssltools_client is not None
                        and getattr(ssltools_client, "available", False)
                        and strategy not in ("passive_only",) and domain)
    ssltools_mode = getattr(ssltools_client, "mode", "off") \
        if ssltools_enabled else "off"
    ssltools_info = None
    if ssltools_enabled:
        try:
            ssltools_info = ssltools_client.mailserver_info(domain)
            if ssltools_info.get("stale"):
                out["issues"].append(
                    "ssl-tools report is stale and could not be refreshed — "
                    "not used for scoring")
        except Exception as exc:                       # noqa: BLE001
            logger.warning("ssltools lookup failed for %s: %s", domain, exc)

    # internet.nl is per-DOMAIN and precomputed (scheduled batch cache). The
    # caller passes the cached verdict (freshness already applied) or None.
    inl_status = None
    if internetnl_result and strategy not in ("passive_only",):
        inl_status = internetnl_result.get("starttls")   # "ok"|"no_tls"|None

    def _remote_votes(mx, local_unknown):
        votes = []
        # MXToolbox (per-host)
        if mxt_enabled and (mxt_mode == "always"
                            or (mxt_mode == "fallback" and local_unknown)):
            try:
                mv = mxtoolbox_client.smtp_info(mx)
                votes.append({"source": "mxtoolbox", "status": _mxt_status(mv),
                              "tls_version": mv.get("tls_version", ""),
                              "weak_tls": mv.get("weak_tls", False)})
            except Exception as exc:                   # noqa: BLE001
                logger.warning("MXToolbox lookup failed for %s: %s", mx, exc)
        # ssl-tools (per-host, from the single per-domain fetch)
        if ssltools_info and not ssltools_info.get("stale") \
                and (ssltools_mode == "always"
                     or (ssltools_mode == "fallback" and local_unknown)):
            srv = (ssltools_info.get("servers") or {}).get(mx.rstrip(".").lower())
            if srv is not None:
                st = srv.get("starttls")
                votes.append({"source": "ssltools",
                              "status": "ok" if st is True
                              else "no_tls" if st is False else "unknown",
                              "tls_version": srv.get("tls_version", ""),
                              "weak_tls": srv.get("weak_tls", False)})
        # internet.nl (domain-level, applied to every inbound MX)
        if inl_status is not None:
            votes.append({"source": "internetnl", "status": inl_status,
                          "tls_version": (internetnl_result or {}).get(
                              "tls_version", ""),
                          "weak_tls": False})
        return votes

    inbound_labels = []
    active_attempts = 0
    active_transport_fail = 0
    disagreements = []

    for mx in mx_hosts:
        # ---- inbound :25 (reconciled) ---------------------------------
        active_v = None
        if active_enabled:
            active_attempts += 1
            active_v, chain, transport_failed = _active_inbound(
                mx, timeout, verify_cert, helo_name)
            if transport_failed:
                active_transport_fail += 1
            if chain:
                out["_chains"][mx] = chain
        passive_v = (_passive_verdict(passive_clients, mx, _INBOUND_PORT,
                                      "inbound") if passive_enabled else None)
        local_unknown = (active_v is None or active_v["status"] == "unknown")
        remote_votes = _remote_votes(mx, local_unknown)

        verdict = _reconcile_inbound(mx, active_v, remote_votes, passive_v,
                                     strategy)
        if verdict.get("disagreement"):
            disagreements.append(mx)
        out["hosts"][mx] = verdict
        inbound_labels.append(mx)

        # ---- submission 587 (STARTTLS) --------------------------------
        if active_enabled or passive_enabled:
            for port in submission_ports:
                out["hosts"][f"{mx}:{port}"] = _submission_entry(
                    mx, port, timeout, helo_name, passive_clients)
            # ---- submission 465 (implicit) ----------------------------
            for port in implicit_ports:
                out["hosts"][f"{mx}:{port}"] = _implicit_entry(
                    mx, port, timeout, passive_clients)

    # ---- tally (blended over all entries) ----------------------------
    by_port = {}
    for label, v in out["hosts"].items():
        port = v.get("port", _INBOUND_PORT)
        bp = by_port.setdefault(port, {"ok": 0, "no_tls": 0, "unknown": 0})
        st = v["status"]
        if st == "ok":
            out["supported_count"] += 1
            bp["ok"] += 1
        elif st == "no_tls":
            out["no_tls_count"] += 1
            bp["no_tls"] += 1
        else:
            out["unknown_count"] += 1
            bp["unknown"] += 1
        if v.get("weak_tls"):
            out["any_weak_tls"] = True
        if v.get("auth_before_tls"):
            out["any_auth_before_tls"] = True
        if v.get("software"):
            out["software"][label] = " ".join(
                x for x in (v["software"], v["software_version"]) if x)
        cert = v.get("cert") or {}
        if cert:
            if cert.get("pkix_valid") is False or cert.get("expired") \
                    or cert.get("self_signed"):
                out["any_cert_invalid"] = True
            if cert.get("hostname_match") is False:
                out["any_cert_hostname_mismatch"] = True
            for issue in certificate_issues(cert, label):
                out["issues"].append(issue)

    out["total"] = len(out["hosts"])
    out["by_port"] = by_port
    known = out["supported_count"] + out["no_tls_count"]
    out["coverage"] = round(out["supported_count"] / known, 2) if known else None
    if out["unknown_count"]:
        out["confidence"] = "low"

    # all_starttls: inbound (:25) hosts only — the true "all MX offer STARTTLS"
    inbound = [out["hosts"][m] for m in inbound_labels]
    inbound_known = [h for h in inbound if h["status"] in ("ok", "no_tls")]
    out["all_starttls"] = (bool(inbound_known)
                           and all(h["status"] == "ok" for h in inbound_known)
                           and not any(h["status"] == "unknown" for h in inbound))

    # egress-25 heuristic: active tried on every MX and every :25 connect failed
    if active_enabled and active_attempts > 0 \
            and active_transport_fail == active_attempts:
        out["egress25_blocked"] = True
        _warn_egress_once()
        out["issues"].append(
            "Every local port-25 connection failed at the transport layer — "
            "this is almost certainly outbound port 25 blocked on the "
            "SEE-Monitor host, not the target servers. STARTTLS verdicts here "
            "rely on passive/remote sources; enable MXToolbox (remote active) "
            "for an egress-independent result.")

    # ---- issues ------------------------------------------------------
    no_tls = [m for m in inbound_labels if out["hosts"][m]["status"] == "no_tls"]
    unknown = [m for m in inbound_labels if out["hosts"][m]["status"] == "unknown"]
    if no_tls:
        out["issues"].append(
            "STARTTLS not offered by: " + ", ".join(no_tls)
            + " — mail to these hosts crosses the Internet in cleartext")
    if unknown:
        out["issues"].append(
            "STARTTLS status could not be determined for: " + ", ".join(unknown)
            + " (scored as unknown, not as a failure)")
    # submission/implicit problems, reported per port
    for port in list(submission_ports) + list(implicit_ports):
        bad = [lbl for lbl, v in out["hosts"].items()
               if v.get("port") == port and v["status"] == "no_tls"]
        if bad:
            kind = "STARTTLS" if port in submission_ports else "implicit TLS"
            out["issues"].append(
                f"Submission port {port} does not offer {kind} on: "
                + ", ".join(b.split(':')[0] for b in bad))
    if disagreements:
        out["issues"].append(
            "Source disagreement on STARTTLS (active result used) for: "
            + ", ".join(disagreements)
            + " — passive intel may be stale")
    if out["any_weak_tls"]:
        weak = [lbl for lbl, v in out["hosts"].items() if v.get("weak_tls")]
        out["issues"].append(
            "Deprecated TLS version (<1.2) on: " + ", ".join(weak))
    if out["any_auth_before_tls"]:
        hosts = [lbl for lbl, v in out["hosts"].items()
                 if v.get("auth_before_tls")]
        out["issues"].append(
            "SMTP AUTH advertised on the cleartext session by: "
            + ", ".join(hosts)
            + " — a client that does not insist on STARTTLS will send "
              "credentials in the clear")
    disclosed = {lbl: s for lbl, s in out["software"].items() if s}
    if disclosed:
        out["issues"].append(
            "MTA software and version disclosed in the SMTP banner: "
            + ", ".join(f"{lbl} ({s})" for lbl, s in disclosed.items()))
    return out
