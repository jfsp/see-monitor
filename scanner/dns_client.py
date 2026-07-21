#!/usr/bin/env python3
"""
SEE-Monitor: DNS Client
Shared DNS helper for all email-security checks. Wraps dnspython with:
  - configurable resolvers and timeouts
  - TXT record convenience (joined character-strings)
  - AD-flag queries through a validating resolver (DNSSEC signal)

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
from typing import Optional

import dns.resolver
import dns.message
import dns.query
import dns.flags
import dns.rdatatype
import dns.exception

logger = logging.getLogger(__name__)

# Public validating resolvers used for the AD-flag (DNSSEC) signal.
DEFAULT_VALIDATING_RESOLVERS = ["8.8.8.8", "1.1.1.1"]

DEFAULT_TIMEOUT = 5.0
DEFAULT_LIFETIME = 8.0


class DNSClient:
    def __init__(self, nameservers: Optional[list] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 lifetime: float = DEFAULT_LIFETIME):
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Basic lookups
    # ------------------------------------------------------------------
    def query(self, name: str, rdtype: str) -> list:
        """
        Return rdata list, or [] on NXDOMAIN/NoAnswer/timeout.
        Timeouts are treated as "no answer" so that a single slow lookup does
        not abort an entire control check during bulk scanning; callers that
        must distinguish (e.g. DNSSEC AD flag) use ad_flag() instead.
        """
        try:
            ans = self.resolver.resolve(name, rdtype)
            return list(ans)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers):
            return []
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
            logger.debug("DNS timeout for %s/%s: %s", name, rdtype, exc)
            return []

    def txt(self, name: str) -> list[str]:
        """All TXT records at *name*, each with character-strings joined."""
        out = []
        for r in self.query(name, "TXT"):
            try:
                out.append(b"".join(r.strings).decode("utf-8", "replace"))
            except Exception:
                out.append(str(r))
        return out

    def exists(self, name: str) -> bool:
        for rdtype in ("A", "AAAA", "MX", "TXT", "CNAME", "SOA", "NS"):
            if self.query(name, rdtype):
                return True
        return False

    # ------------------------------------------------------------------
    # DNSSEC signal (AD flag via validating resolver)
    # ------------------------------------------------------------------
    def ad_flag(self, name: str, rdtype: str = "SOA",
                resolvers: Optional[list] = None) -> Optional[bool]:
        """
        Query *name* through a validating resolver with DO set and report
        whether the AD (Authenticated Data) flag came back.
        Returns True/False, or None if no resolver answered.
        """
        for server in (resolvers or DEFAULT_VALIDATING_RESOLVERS):
            try:
                q = dns.message.make_query(
                    name, dns.rdatatype.from_text(rdtype), want_dnssec=True)
                q.flags |= dns.flags.AD
                resp = dns.query.udp(q, server, timeout=self.timeout)
                if resp.flags & dns.flags.TC:
                    resp = dns.query.tcp(q, server, timeout=self.timeout)
                return bool(resp.flags & dns.flags.AD)
            except (dns.exception.Timeout, OSError) as exc:
                logger.debug("AD query via %s failed: %s", server, exc)
                continue
        return None
