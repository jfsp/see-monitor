#!/usr/bin/env python3
"""
SEE-Monitor: DMARC Check (RFC 7489 + DMARCbis / NIST SP 800-177r1 §4.6)

Beyond parsing the record at _dmarc.<domain>, this check performs:

  * Organizational-domain discovery by TREE WALK. RFC 7489 resolved a
    subdomain's policy through the Public Suffix List; DMARCbis replaces that
    with a bounded walk up the DNS tree. Without it, `mail.example.com` is
    reported as having no DMARC even though it inherits `sp=reject` from the
    apex — a false negative that inverts the score.
  * DMARCbis tags: `np=` (policy for NON-EXISTENT subdomains — the cheapest
    anti-spoofing control a domain can deploy) and `psd=` (public suffix
    operator records, which must not be inherited by ordinary domains).
  * External destination authorisation. RFC 7489 §7.1 requires the RECEIVING
    domain to publish `<sender-domain>._report._dmarc.<destination-domain>`.
    This is queried rather than merely warned about — an unauthorised rua is
    silently discarded by every reporter, so the domain gets no visibility at
    all while appearing correctly configured.
  * Reporting-loop sanity: the rua destination domain must actually resolve
    and accept mail.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging

from scanner.dns_client import DNSClient

logger = logging.getLogger(__name__)

_POLICIES = ("none", "quarantine", "reject")

# DMARCbis bounds the tree walk; 5 ancestor lookups is the specified ceiling.
MAX_TREE_WALK = 5

_KNOWN_TAGS = {"v", "p", "sp", "np", "pct", "rua", "ruf", "adkim", "aspf",
               "fo", "rf", "ri", "psd", "t"}


def _report_domain(uri: str) -> str | None:
    """Extract the domain part of a 'mailto:user@domain[!size]' DMARC URI."""
    u = uri.strip()
    if u.lower().startswith("mailto:"):
        u = u[7:]
    if "@" not in u:
        return None
    dom = u.split("@", 1)[1].split("!", 1)[0].strip().lower().rstrip(".")
    return dom or None


def _external_report_domains(uris: list[str], domain: str) -> list[str]:
    """Report destinations outside the assessed domain's own tree."""
    out: list[str] = []
    for uri in uris:
        dom = _report_domain(uri)
        if not dom:
            continue
        if dom == domain or dom.endswith("." + domain) \
                or domain.endswith("." + dom):
            continue
        if dom not in out:
            out.append(dom)
    return out


def _parse_tags(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _fetch_dmarc(name: str, dc: DNSClient) -> list[str]:
    return [t for t in dc.txt(f"_dmarc.{name}")
            if t.lower().replace(" ", "").startswith("v=dmarc1")]


def _tree_walk(domain: str, dc: DNSClient) -> tuple:
    """
    Find the policy record governing *domain*.

    Returns (policy_domain, records, inherited). policy_domain is None when no
    applicable record exists anywhere up the tree. A record carrying `psd=y`
    belongs to a public-suffix operator and is NOT inherited by the domain
    below it, so the walk reports no policy in that case.
    """
    records = _fetch_dmarc(domain, dc)
    if records:
        return domain, records, False

    labels = domain.split(".")
    for i in range(1, min(MAX_TREE_WALK + 1, len(labels) - 1)):
        parent = ".".join(labels[i:])
        if parent.count(".") < 1:
            break
        found = _fetch_dmarc(parent, dc)
        if not found:
            continue
        if _parse_tags(found[0]).get("psd", "").lower() == "y":
            logger.debug("psd=y record at %s is not inherited by %s",
                         parent, domain)
            return None, [], False
        return parent, found, True
    return None, [], False


def _check_external_authorisation(domain: str, destinations: list[str],
                                  dc: DNSClient) -> dict:
    """
    RFC 7489 §7.1: the destination must publish
        <domain>._report._dmarc.<destination>   IN TXT "v=DMARC1"
    Returns {destination: True|False}.
    """
    out: dict = {}
    for dest in destinations:
        name = f"{domain}._report._dmarc.{dest}"
        authorised = any(
            t.lower().replace(" ", "").startswith("v=dmarc1")
            for t in dc.txt(name))
        if not authorised:
            # A wildcard authorisation record is also permitted.
            authorised = any(
                t.lower().replace(" ", "").startswith("v=dmarc1")
                for t in dc.txt(f"*._report._dmarc.{dest}"))
        out[dest] = authorised
    return out


def check_dmarc(domain: str, dns_client: DNSClient | None = None,
                verify_reporting: bool = True) -> dict:
    """
    Returns (additions to the 0.5.x shape are marked NEW):
      {
        "control": "dmarc", "present", "valid", "record", "policy",
        "subdomain_policy", "np_policy" (NEW), "psd" (NEW), "pct",
        "rua", "ruf", "adkim", "aspf", "strict_alignment", "has_ruf",
        "policy_domain" (NEW), "inherited" (NEW), "effective_policy" (NEW),
        "external_rua_domains", "external_ruf_domains",
        "external_authorised" (NEW), "rua_destination_ok" (NEW),
        "unknown_tags" (NEW), "issues",
      }
    """
    dc = dns_client or DNSClient()
    out = {"control": "dmarc", "present": False, "valid": False,
           "record": None, "policy": None, "subdomain_policy": None,
           "np_policy": None, "psd": None,
           "pct": 100, "rua": [], "ruf": [], "adkim": "r", "aspf": "r",
           "strict_alignment": False, "has_ruf": False,
           "policy_domain": None, "inherited": False,
           "effective_policy": None,
           "external_rua_domains": [], "external_ruf_domains": [],
           "external_authorised": {}, "rua_destination_ok": None,
           "unknown_tags": [], "issues": []}

    policy_domain, records, inherited = _tree_walk(domain, dc)
    if not records:
        out["issues"].append(
            "No DMARC record published (and none inherited from a parent "
            "domain)")
        return out

    out["present"] = True
    out["policy_domain"] = policy_domain
    out["inherited"] = inherited
    if len(records) > 1:
        out["issues"].append(
            f"{len(records)} DMARC records found at _dmarc.{policy_domain} — "
            "receivers ignore all of them")
        out["record"] = records[0]
        return out

    record = records[0]
    out["record"] = record
    tags = _parse_tags(record)
    out["unknown_tags"] = sorted(k for k in tags if k not in _KNOWN_TAGS)

    policy = tags.get("p", "").lower()
    if policy not in _POLICIES:
        out["issues"].append(f"Invalid or missing policy tag (p={policy!r})")
        return out
    out["valid"] = True
    out["policy"] = policy
    out["subdomain_policy"] = tags.get("sp", policy).lower()
    np_policy = tags.get("np")
    out["np_policy"] = np_policy.lower() if np_policy else None
    out["psd"] = tags.get("psd", "").lower() or None

    # The policy that actually applies to the domain we were asked about.
    out["effective_policy"] = out["subdomain_policy"] if inherited else policy

    try:
        out["pct"] = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        out["pct"] = 100
    out["rua"] = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    out["ruf"] = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]
    out["adkim"] = tags.get("adkim", "r").lower()
    out["aspf"] = tags.get("aspf", "r").lower()
    out["strict_alignment"] = out["adkim"] == "s" and out["aspf"] == "s"
    out["has_ruf"] = bool(out["ruf"])

    ref_domain = policy_domain or domain
    out["external_rua_domains"] = _external_report_domains(out["rua"], ref_domain)
    out["external_ruf_domains"] = _external_report_domains(out["ruf"], ref_domain)

    # ---- Reporting-loop verification ----------------------------------
    if verify_reporting:
        externals = sorted(set(out["external_rua_domains"]
                               + out["external_ruf_domains"]))
        if externals:
            out["external_authorised"] = _check_external_authorisation(
                ref_domain, externals, dc)
            unauthorised = [d for d, ok in out["external_authorised"].items()
                            if not ok]
            if unauthorised:
                out["issues"].append(
                    "External report destination(s) " + ", ".join(unauthorised)
                    + " publish no authorisation record at "
                    f"{ref_domain}._report._dmarc.<destination> (RFC 7489 §7.1)"
                    " — reports are discarded and the domain is blind")
        if out["rua"]:
            dests = {d for d in (_report_domain(u) for u in out["rua"]) if d}
            reachable = []
            for dest in sorted(dests):
                if dc.query(dest, "MX") or dc.query(dest, "A") \
                        or dc.query(dest, "AAAA"):
                    reachable.append(True)
                else:
                    reachable.append(False)
                    out["issues"].append(
                        f"DMARC rua destination {dest} does not resolve — "
                        "aggregate reports cannot be delivered")
            out["rua_destination_ok"] = all(reachable) if reachable else None

    # ---- Policy findings ----------------------------------------------
    if inherited:
        out["issues"].append(
            f"No DMARC record at _dmarc.{domain}; policy inherited from "
            f"{policy_domain} (sp={out['subdomain_policy']})")
    if not out["strict_alignment"]:
        out["issues"].append(
            "Relaxed alignment (adkim/aspf not both 's') — BSI TR-03182-06 and "
            "ACN recommend strict alignment")
    if out["has_ruf"]:
        out["issues"].append(
            "ruf= (forensic) reporting requested — impermissible under GDPR per "
            "BSI TR-03182-08 (note: ACN recommends it — profile-dependent)")
    if policy == "none":
        out["issues"].append(
            "p=none is monitor-only — spoofed mail is still delivered")
    if policy != "none" and out["pct"] < 100:
        out["issues"].append(
            f"pct={out['pct']} — enforcement applies to only part of the mail flow")
    if out["subdomain_policy"] != policy and \
            _POLICIES.index(out["subdomain_policy"]) < _POLICIES.index(policy):
        out["issues"].append(
            f"Subdomain policy (sp={out['subdomain_policy']}) is weaker than p={policy}")
    if out["np_policy"] is None:
        out["issues"].append(
            "No np= tag — non-existent subdomains fall back to sp=/p=. "
            "Publishing np=reject (DMARCbis) blocks spoofing of names that do "
            "not exist, which is where most impersonation happens")
    elif out["np_policy"] in _POLICIES and \
            _POLICIES.index(out["np_policy"]) < _POLICIES.index(policy):
        out["issues"].append(
            f"np={out['np_policy']} is weaker than p={policy} — non-existent "
            "subdomains are the easiest names to spoof")
    if not out["rua"]:
        out["issues"].append(
            "No aggregate reporting address (rua) — no visibility of failures")
    if out["unknown_tags"]:
        out["issues"].append(
            "Unrecognised DMARC tag(s): " + ", ".join(out["unknown_tags"]))
    return out
