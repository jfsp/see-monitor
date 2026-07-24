#!/usr/bin/env python3
"""
SEE-Monitor: Scan Orchestrator
Runs the complete email-security check suite for a domain:
MX → SPF → DKIM → DMARC → DNSSEC → DANE → MTA-STS → TLS-RPT → STARTTLS → BIMI

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
from datetime import datetime, timezone

from scanner.dns_client import DNSClient
from scanner.mx_resolver import resolve_mx
from scanner.spf_check import check_spf
from scanner.dkim_check import check_dkim
from scanner.dmarc_check import check_dmarc
from scanner.policy_checks import (
    check_mta_sts, check_tlsrpt, check_dnssec, check_dane, check_bimi)
from scanner.smtp_tls_check import check_starttls
from scanner.client_tls_check import check_client_tls
from scanner.dns_hygiene import check_dns_hygiene
from scanner.dnsbl_check import check_dnsbl
from scanner.subdomain_check import check_subdomains
from scanner.crtsh_client import CrtShClient
from scanner.shodan_client import ShodanClient
from scanner.censys_client import CensysClient
from scanner.dnsdumpster_client import DNSDumpsterClient
from scanner.securitytrails_client import SecurityTrailsClient

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self, config: dict | None = None, db=None):
        cfg = config or {}
        self.cfg = cfg
        self.db = db
        scan_cfg = cfg.get("scanning", {})
        self.timeout = int(scan_cfg.get("timeout", 10))
        self.active_smtp = bool(scan_cfg.get("active_smtp", True))
        self.dkim_wordlist = bool(scan_cfg.get("dkim_wordlist", True))
        nameservers = scan_cfg.get("nameservers") or None
        self.dns = DNSClient(nameservers=nameservers)

        self.shodan = ShodanClient(
            (cfg.get("shodan") or {}).get("api_key"))
        censys_cfg = cfg.get("censys") or {}
        self.censys = CensysClient(
            censys_cfg.get("api_id"), censys_cfg.get("api_secret"))
        self.dnsdumpster = DNSDumpsterClient(
            (cfg.get("dnsdumpster") or {}).get("api_key"))
        self.securitytrails = SecurityTrailsClient(
            (cfg.get("securitytrails") or {}).get("api_key"))

        # ---- v0.6.0 options ------------------------------------------
        self.verify_mx_certs = bool(scan_cfg.get("verify_mx_certs", True))
        self.do_fcrdns = bool(scan_cfg.get("fcrdns", True))
        self.subdomain_scan = bool(scan_cfg.get("subdomain_check", True))
        self.max_subdomains = int(scan_cfg.get("max_subdomains", 25))
        self.verify_reporting = bool(scan_cfg.get("verify_reporting", True))
        dnsbl_cfg = cfg.get("dnsbl") or {}
        self.dnsbl_enabled = bool(dnsbl_cfg.get("enabled", True))
        self.dnsbl_ip_zones = dnsbl_cfg.get("ip_zones")
        self.dnsbl_domain_zones = dnsbl_cfg.get("domain_zones")
        self.crtsh = CrtShClient(
            enabled=bool((cfg.get("crtsh") or {}).get("enabled", True)))

    # ------------------------------------------------------------------
    def scan_domain(self, domain: str,
                    registered_selectors: list[str] | None = None) -> dict:
        """
        Run every control check. If a DB handle is present and no selectors
        were passed, registered selectors are loaded from it.

        Returns {"domain", "scanned_at", "checks": {control: result}}.
        """
        domain = domain.strip().lower().rstrip(".")
        started = datetime.now(timezone.utc).isoformat()
        logger.info("Scanning %s", domain)

        if registered_selectors is None and self.db is not None:
            try:
                registered_selectors = self.db.get_dkim_selectors(domain)
            except Exception:
                registered_selectors = []

        checks: dict = {}

        mx = resolve_mx(domain, self.dns)
        checks["mx"] = mx
        mx_hosts = [m["host"] for m in mx["mx_hosts"]]

        checks["spf"] = self._safe(check_spf, domain, self.dns)

        # ---- Passive DKIM-selector discovery (candidates only) -----------
        passive_selectors: list[str] = []
        dd_error = st_error = None
        dd_count = 0
        st_intel = {"available": self.securitytrails.available, "mx": [],
                    "selectors": [], "mail_hosts": [], "subdomain_count": 0,
                    "error": None}
        if self.dnsdumpster.available:
            try:
                dd = self.dnsdumpster.discover_selectors(domain)
                dd_count = len(dd)
                passive_selectors += dd
            except Exception as exc:
                dd_error = str(exc)
        if self.securitytrails.available:
            try:
                st_intel = self.securitytrails.gather(domain)
                st_error = st_intel.get("error")
                passive_selectors += st_intel.get("selectors", [])
            except Exception as exc:
                st_error = str(exc)
        # de-dup preserving order
        seen = set()
        passive_selectors = [s for s in passive_selectors
                             if not (s in seen or seen.add(s))]
        checks["intel"] = {"securitytrails": st_intel}

        checks["dkim"] = self._safe(
            check_dkim, domain, registered_selectors, self.dns,
            self.dkim_wordlist, passive_selectors)
        checks["dmarc"] = self._safe(
            check_dmarc, domain, self.dns, self.verify_reporting)
        checks["dnssec"] = self._safe(check_dnssec, domain, self.dns)
        dnssec_valid = bool(checks["dnssec"].get("signed")
                            and checks["dnssec"].get("validated"))

        # STARTTLS runs before DANE: the certificate chain captured by that
        # single connection is what makes live TLSA matching possible without
        # opening another one.
        checks["starttls"] = self._safe(
            check_starttls, mx_hosts, self.shodan, self.censys,
            self.active_smtp, self.timeout, self.verify_mx_certs)
        chains = checks["starttls"].pop("_chains", {}) or {}

        checks["dane"] = self._safe(
            check_dane, mx_hosts, dnssec_valid, self.dns, chains)
        checks["mta_sts"] = self._safe(
            check_mta_sts, domain, mx_hosts, self.dns, self.timeout)
        checks["tlsrpt"] = self._safe(check_tlsrpt, domain, self.dns)
        checks["client_tls"] = self._safe(
            check_client_tls, domain, self.dns, self.active_smtp, self.timeout)
        checks["bimi"] = self._safe(
            check_bimi, domain, self.dns, checks["dmarc"])

        # ---- DNS hygiene, reputation, subdomain coverage --------------
        checks["dns_hygiene"] = self._safe(
            check_dns_hygiene, domain, mx_hosts, self.dns, self.do_fcrdns)
        mx_ips = checks["dns_hygiene"].get("mx_ips", []) or []
        checks["reputation"] = self._safe(
            check_dnsbl, domain, mx_ips, self.dns, self.dnsbl_ip_zones,
            self.dnsbl_domain_zones, self.dnsbl_enabled)

        sub_candidates: list[str] = []
        ct_count = 0
        ct_error = None
        if self.subdomain_scan:
            if self.crtsh.available:
                try:
                    found = self.crtsh.discover_subdomains(domain)
                    ct_count = len(found)
                    sub_candidates += found
                except Exception as exc:
                    ct_error = str(exc)
            for name in st_intel.get("mail_hosts", []) or []:
                if name not in sub_candidates:
                    sub_candidates.append(name)
        dmarc_res = checks["dmarc"]
        inherited = dmarc_res.get("subdomain_policy") or dmarc_res.get("policy")
        checks["subdomains"] = self._safe(
            check_subdomains, domain, sub_candidates, inherited, self.dns,
            self.max_subdomains, self.subdomain_scan)

        # Persist newly discovered wordlist selectors so future scans keep them
        if self.db is not None:
            for sel in checks["dkim"].get("selectors", []):
                try:
                    self.db.record_dkim_selector(
                        domain, sel["selector"], source=sel["source"])
                except Exception:
                    pass

        # ---- Which external services were used, and what they yielded -----
        st_hosts = checks.get("starttls", {}).get("hosts", {}) or {}
        src_counts: dict = {}
        for v in st_hosts.values():
            src_counts[v.get("source")] = src_counts.get(v.get("source"), 0) + 1
        mx_total = checks.get("starttls", {}).get("total", 0)
        services = {
            "shodan": {"available": self.shodan.available,
                       "used": src_counts.get("shodan", 0) > 0,
                       "mx_covered": src_counts.get("shodan", 0),
                       "mx_total": mx_total},
            "censys": {"available": self.censys.available,
                       "used": src_counts.get("censys", 0) > 0,
                       "mx_covered": src_counts.get("censys", 0),
                       "mx_total": mx_total},
            "active_smtp": {"enabled": self.active_smtp,
                            "used": src_counts.get("active", 0) > 0,
                            "mx_covered": src_counts.get("active", 0),
                            "mx_total": mx_total},
            "dnsdumpster": {"available": self.dnsdumpster.available,
                            "selectors": dd_count, "error": dd_error},
            "crtsh": {"available": self.crtsh.available,
                      "subdomains": ct_count, "error": ct_error},
            "securitytrails": {"available": self.securitytrails.available,
                               "mx": len(st_intel.get("mx", [])),
                               "selectors": len(st_intel.get("selectors", [])),
                               "subdomains": st_intel.get("subdomain_count", 0),
                               "mail_hosts": len(st_intel.get("mail_hosts", [])),
                               "error": st_error},
        }

        return {"domain": domain, "scanned_at": started, "checks": checks,
                "services": services}

    @staticmethod
    def _safe(fn, *args) -> dict:
        try:
            return fn(*args)
        except Exception as exc:
            logger.exception("Check %s failed", fn.__name__)
            return {"control": fn.__name__.replace("check_", ""),
                    "error": str(exc), "issues": [f"Check failed: {exc}"]}
