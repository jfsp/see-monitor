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

DEFAULT_INTERVAL_HOURS = 168      # weekly
DEFAULT_RELOAD_MINUTES = 60       # how often the daemon re-reads the DB


class ScanScheduler:
    """Manages periodic scan jobs stored in the scheduled_scans table."""

    def __init__(self, orchestrator, db, config=None):
        self.orchestrator = orchestrator
        self.db = db
        self.config = config or {}
        sched_cfg = (self.config.get("scheduling") or {})
        # Assess against every installed profile, matching the CLI. Before
        # 0.6.1 scheduled runs wrote only the default profile, so the national
        # dashboards went stale while scheduling appeared to work.
        self.profiles = sched_cfg.get("profiles") or None
        # Post-run integrity gate: a scan that leaves the database inconsistent
        # is worse than a scan that did not run, because it is invisible.
        self.post_run_db_check = bool(
            sched_cfg.get("post_run_db_check", True))
        self.reload_minutes = int(
            sched_cfg.get("reload_interval_minutes", DEFAULT_RELOAD_MINUTES))
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
        from scanner.assessor import assess_all_profiles, available_guidelines
        domains = self.db.get_domain_list_by_id(domain_list_id)
        if not domains:
            logger.warning("No domains for schedule %s", schedule_id)
            self._record_run_times(schedule_id)
            return
        gids = self.profiles or available_guidelines()
        logger.info("Running scheduled scan (schedule_id=%s, %d domains, "
                    "%d profile(s))", schedule_id, len(domains), len(gids))
        run_id = self.db.create_run(domains, trigger=f"schedule:{schedule_id}")
        status = "completed"
        for d in domains:
            try:
                scan = self.orchestrator.scan_domain(d)
                self.db.save_scan_result(run_id, scan)
                for a in assess_all_profiles(scan, self.config, gids).values():
                    self.db.save_assessment(run_id, a)
            except Exception:
                logger.exception("Scheduled scan failed for %s", d)
                status = "completed_with_errors"
            finally:
                self.db.bump_run_progress(run_id)

        if self.post_run_db_check and self._db_check_failed():
            status = "completed_with_errors"

        self.db.finish_run(run_id, status)
        self._record_run_times(schedule_id)
        logger.info("Scheduled scan complete: run_id=%s status=%s",
                    run_id, status)
        return run_id

    def _db_check_failed(self) -> bool:
        """
        Run the read-only consistency audit after a scan. Returns True if any
        error-level issue was found. Never raises: a broken health check must
        not lose the scan results that were just written.
        """
        try:
            from scripts.db_check import run_checks
            issues = run_checks(self.db.db_path)
        except Exception as exc:
            logger.warning("Post-run DB check could not be executed: %s", exc)
            return False
        errors = [i for i in issues if getattr(i, "level", "") == "error"]
        for issue in errors:
            logger.error("DB consistency error after scheduled scan: %s (%s)",
                         getattr(issue, "detail", issue),
                         getattr(issue, "check", "?"))
        if errors:
            logger.error("Post-run DB check found %d error(s); run "
                         "scripts/db_check.py for the full report", len(errors))
        return bool(errors)

    def _record_run_times(self, schedule_id):
        """Persist last_run_at and a truthful next_run_at."""
        now = datetime.now(timezone.utc)
        next_run = None
        if self.scheduler:
            job = self.scheduler.get_job(f"scan_{schedule_id}")
            nrt = getattr(job, "next_run_time", None) if job else None
            if nrt is not None:
                next_run = nrt.isoformat()
        if next_run is None:
            with self.db._connect() as conn:
                row = conn.execute(
                    "SELECT interval_hours FROM scheduled_scans WHERE id=?",
                    (schedule_id,)).fetchone()
            hours = (row["interval_hours"] if row else None) \
                or DEFAULT_INTERVAL_HOURS
            next_run = (now + timedelta(hours=hours)).isoformat()
        with self.db._connect() as conn:
            conn.execute(
                "UPDATE scheduled_scans SET last_run_at=?, next_run_at=? "
                "WHERE id=?", (now.isoformat(), next_run, schedule_id))

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

    def reload(self):
        """
        Re-read `scheduled_scans` and reconcile the registered jobs.

        Without this, a schedule inserted by scripts/schedule_audit.py (or by
        another process) is invisible until the daemon restarts. Jobs removed
        from the database are unregistered here too.
        """
        if not self.scheduler:
            return 0
        try:
            with self.db._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM scheduled_scans WHERE enabled=1").fetchall()
        except Exception as exc:
            logger.error("Schedule reload failed: %s", exc)
            return 0
        wanted = {}
        for row in rows:
            wanted[f"scan_{row['id']}"] = row
        for job in list(self.scheduler.get_jobs()):
            if job.id.startswith("scan_") and job.id not in wanted:
                self.scheduler.remove_job(job.id)
                logger.info("Schedule removed: %s", job.id)
        for job_id, row in wanted.items():
            existing = self.scheduler.get_job(job_id)
            if existing is not None and not self._job_changed(existing, row):
                continue        # leave the running timer alone
            # CRITICAL: _register_job uses replace_existing=True, which makes
            # APScheduler recompute next_run_time from now. Re-registering an
            # unchanged 168h job on every hourly reload would reset its clock
            # every hour and it would never fire. Only touch changed or new
            # jobs.
            if existing is None:
                logger.info("Schedule picked up: '%s' every %sh",
                            row["name"], row["interval_hours"])
            else:
                logger.info("Schedule changed, re-registering: '%s'",
                            row["name"])
            self._register_job(row["id"], row["name"], row["domain_list_id"],
                               row["interval_hours"])
        return len(wanted)

    @staticmethod
    def _job_changed(job, row) -> bool:
        """True if the stored definition differs from the registered job."""
        try:
            interval_hours = job.trigger.interval.total_seconds() / 3600.0
        except Exception:
            return True
        if abs(interval_hours - (row["interval_hours"] or 0)) > 1e-6:
            return True
        kwargs = getattr(job, "kwargs", {}) or {}
        return kwargs.get("domain_list_id") != row["domain_list_id"]

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
