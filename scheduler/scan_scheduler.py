#!/usr/bin/env python3
"""
SEE-Monitor: Scan Scheduler
APScheduler-based periodic scan management (default: every 7 days / 168h).
Each scheduled job resolves a domain list, scans every domain with the
orchestrator, assesses it, and persists the results as a run.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

logger = logging.getLogger(__name__)

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    HAS_APSCHEDULER = True
except ImportError:
    HAS_APSCHEDULER = False
    logger.warning("APScheduler not installed. Scheduling unavailable.")

DEFAULT_INTERVAL_HOURS = 168  # weekly


class ScanScheduler:
    """Manages periodic scan jobs stored in the scheduled_scans table."""

    def __init__(self, orchestrator, db, config=None):
        self.orchestrator = orchestrator
        self.db = db
        self.config = config or {}
        self.scheduler = None
        if HAS_APSCHEDULER:
            self.scheduler = BackgroundScheduler()
            self._load_saved_schedules()

    def start(self):
        if self.scheduler:
            self.scheduler.start()
            logger.info("Scheduler started")

    def stop(self):
        if self.scheduler and self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Scheduler stopped")

    def add_schedule(self, name, domain_list_id,
                     interval_hours=DEFAULT_INTERVAL_HOURS):
        next_run = (datetime.now(timezone.utc)
                    + timedelta(hours=interval_hours)).isoformat()
        with self.db._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scheduled_scans "
                "(name, domain_list_id, interval_hours, enabled, next_run_at) "
                "VALUES (?,?,?,1,?)",
                (name, domain_list_id, interval_hours, next_run))
            schedule_id = cur.lastrowid
        if self.scheduler:
            self._register_job(schedule_id, name, domain_list_id,
                               interval_hours)
        logger.info("Schedule added: '%s' every %sh", name, interval_hours)
        return schedule_id

    def _register_job(self, schedule_id, name, domain_list_id, interval_hours):
        if not self.scheduler:
            return
        self.scheduler.add_job(
            func=self._run_scheduled_scan,
            trigger=IntervalTrigger(hours=interval_hours),
            id=f"scan_{schedule_id}", name=name,
            kwargs={"schedule_id": schedule_id,
                    "domain_list_id": domain_list_id},
            replace_existing=True, misfire_grace_time=3600)

    def _run_scheduled_scan(self, schedule_id, domain_list_id):
        from scanner.assessor import assess_domain
        domains = self.db.get_domain_list_by_id(domain_list_id)
        if not domains:
            logger.warning("No domains for schedule %s", schedule_id)
            return
        logger.info("Running scheduled scan (schedule_id=%s, %d domains)",
                    schedule_id, len(domains))
        run_id = self.db.create_run(domains, trigger=f"schedule:{schedule_id}")
        status = "completed"
        for d in domains:
            try:
                scan = self.orchestrator.scan_domain(d)
                self.db.save_scan_result(run_id, scan)
                self.db.save_assessment(run_id, assess_domain(scan, self.config))
            except Exception:
                logger.exception("Scheduled scan failed for %s", d)
                status = "completed_with_errors"
            finally:
                self.db.bump_run_progress(run_id)
        self.db.finish_run(run_id, status)
        ts = datetime.now(timezone.utc).isoformat()
        with self.db._connect() as conn:
            conn.execute(
                "UPDATE scheduled_scans SET last_run_at=? WHERE id=?",
                (ts, schedule_id))
        logger.info("Scheduled scan complete: run_id=%s", run_id)

    def _load_saved_schedules(self):
        if not self.scheduler:
            return
        try:
            with self.db._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM scheduled_scans WHERE enabled=1").fetchall()
            for row in rows:
                self._register_job(
                    row["id"], row["name"], row["domain_list_id"],
                    row["interval_hours"])
        except Exception as exc:
            logger.error("Failed to load saved schedules: %s", exc)

    def list_schedules(self):
        with self.db._connect() as conn:
            rows = conn.execute("SELECT * FROM scheduled_scans").fetchall()
        return [dict(r) for r in rows]

    def delete_schedule(self, schedule_id):
        with self.db._connect() as conn:
            cur = conn.execute("DELETE FROM scheduled_scans WHERE id=?",
                               (schedule_id,))
        if self.scheduler:
            try:
                self.scheduler.remove_job(f"scan_{schedule_id}")
            except Exception:
                pass
        return cur.rowcount > 0
