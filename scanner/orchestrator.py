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
from scanner.shodan_client import ShodanClient
from scanner.censys_client import CensysClient
from scanner.dnsdumpster_client import DNSDumpsterClient

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
        passive_selectors = []
        if self.dnsdumpster.available:
            try:
                passive_selectors = self.dnsdumpster.discover_selectors(domain)
            except Exception:
                logger.debug("DNSDumpster selector discovery failed", exc_info=True)
        checks["dkim"] = self._safe(
            check_dkim, domain, registered_selectors, self.dns,
            self.dkim_wordlist, passive_selectors)
        checks["dmarc"] = self._safe(check_dmarc, domain, self.dns)
        checks["dnssec"] = self._safe(check_dnssec, domain, self.dns)
        dnssec_valid = bool(checks["dnssec"].get("signed")
                            and checks["dnssec"].get("validated"))
        checks["dane"] = self._safe(check_dane, mx_hosts, dnssec_valid, self.dns)
        checks["mta_sts"] = self._safe(
            check_mta_sts, domain, mx_hosts, self.dns, self.timeout)
        checks["tlsrpt"] = self._safe(check_tlsrpt, domain, self.dns)
        checks["starttls"] = self._safe(
            check_starttls, mx_hosts, self.shodan, self.censys,
            self.active_smtp, self.timeout)
        checks["bimi"] = self._safe(check_bimi, domain, self.dns)

        # Persist newly discovered wordlist selectors so future scans keep them
        if self.db is not None:
            for sel in checks["dkim"].get("selectors", []):
                try:
                    self.db.record_dkim_selector(
                        domain, sel["selector"], source=sel["source"])
                except Exception:
                    pass

        return {"domain": domain, "scanned_at": started, "checks": checks}

    @staticmethod
    def _safe(fn, *args) -> dict:
        try:
            return fn(*args)
        except Exception as exc:
            logger.exception("Check %s failed", fn.__name__)
            return {"control": fn.__name__.replace("check_", ""),
                    "error": str(exc), "issues": [f"Check failed: {exc}"]}
