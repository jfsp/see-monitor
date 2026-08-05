#!/usr/bin/env python3
"""
SEE-Monitor: Internet.nl scheduled batch runner

Internet.nl's batch API is asynchronous (submit -> poll -> results, minutes per
batch), so it is consumed out-of-band from scanning: this runner submits ALL
known mail domains as one batch on a cadence, waits for completion, and caches
each domain's STARTTLS/DANE verdict in the `internetnl_results` table. The
scanner's reconciler then reads that cache at scan time (see
ScanOrchestrator._internetnl_cached), applying the configured freshness TTL.

Safe to run from the scheduler daemon or manually
(`see_monitor.py internetnl-refresh`). No-op when no credentials are set.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
from datetime import datetime, timezone

from scanner.internetnl_client import InternetNLClient

logger = logging.getLogger(__name__)


def run_internetnl_batch(cfg: dict, db, domains=None) -> dict:
    """Submit a mail batch for all known mail domains and cache the results.

    Returns a summary dict: {submitted, stored, request_id, error, skipped}.
    """
    inl_cfg = cfg.get("internetnl") or {}
    client = InternetNLClient(
        inl_cfg.get("username"), inl_cfg.get("password"),
        base_url=inl_cfg.get("base_url",
                             "https://batch.internet.nl/api/batch/v2"),
        timeout=int(inl_cfg.get("timeout", 30)))
    out = {"submitted": 0, "stored": 0, "request_id": None,
           "error": "", "skipped": False}
    if not client.available:
        out["skipped"] = True
        out["error"] = "internet.nl credentials not configured"
        return out

    if domains is None:
        domains = db.get_all_known_domains() if db is not None else []
    domains = sorted({d.strip().lower().rstrip(".") for d in domains if d})
    if not domains:
        out["skipped"] = True
        out["error"] = "no domains to submit"
        return out

    poll_interval = int(inl_cfg.get("poll_interval_seconds", 30))
    max_wait = int(inl_cfg.get("max_wait_seconds", 3600))
    name = "see-monitor-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    logger.info("internet.nl batch: submitting %d domain(s)", len(domains))
    out["submitted"] = len(domains)

    res = client.run_batch(domains, name, poll_interval=poll_interval,
                           max_wait=max_wait)
    out["request_id"] = res.get("request_id")
    if res.get("error"):
        out["error"] = res["error"]
        logger.warning("internet.nl batch failed: %s", res["error"])
        return out

    if db is not None:
        for domain, verdict in (res.get("domains") or {}).items():
            try:
                db.upsert_internetnl_result(
                    domain.strip().lower().rstrip("."),
                    verdict.get("starttls"), verdict.get("dane"),
                    verdict.get("tls_version", ""), out["request_id"])
                out["stored"] += 1
            except Exception as exc:                   # noqa: BLE001
                logger.warning("internet.nl cache write failed for %s: %s",
                               domain, exc)
    logger.info("internet.nl batch %s: stored %d verdict(s)",
                out["request_id"], out["stored"])
    return out
