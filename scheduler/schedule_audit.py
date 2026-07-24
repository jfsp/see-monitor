#!/usr/bin/env python3
"""
SEE-Monitor: Schedule Audit & Repair

Answers the operational question the scheduler itself never asks: *which of the
domains this platform knows about are actually being rescanned, and how often?*

The scheduler executes rows in `scheduled_scans`, each bound to exactly one
`domain_lists` row. Nothing keeps those lists in step with the domains that
accumulate in the database through ad-hoc scans, organisation assignment or
imports, so coverage silently decays: a domain scanned once from the CLI and
never added to a list is never looked at again.

This module reports that gap and can close it by maintaining a single
auto-managed list containing every domain in the database, driven by one weekly
schedule.

Everything here is DB-level. It deliberately does not construct a
ScanOrchestrator, so it is safe to run from a cron job or a maintenance shell
without touching the network.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_HOURS = 168                      # weekly
AUTO_LIST_NAME = "All known domains (auto-managed)"
AUTO_SCHEDULE_NAME = "Weekly — all known domains"

# A schedule is called overdue once this much slack past its interval has
# elapsed. Generous, because a long scan legitimately delays the next start.
OVERDUE_GRACE_HOURS = 6


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


# ----------------------------------------------------------------------
# Audit
# ----------------------------------------------------------------------
def audit_schedules(db) -> dict:
    """
    Returns:
      {
        "generated_at": iso,
        "known_domains": int,
        "schedules": [{id, name, enabled, interval_hours, domain_list_id,
                       list_name, domain_count, last_run_at, next_run_at,
                       overdue, never_run, problems: [str]}],
        "covered": [str], "uncovered": [str],
        "coverage": float|None,
        "duplicated": {domain: [schedule_name, ...]},
        "orphan_schedules": [str], "disabled_schedules": [str],
        "problems": [str], "recommendations": [str],
      }
    """
    known = set(db.get_all_known_domains())
    lists = {row["id"]: row for row in db.get_domain_lists()}

    with db._connect() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM scheduled_scans ORDER BY id").fetchall()]

    out = {"generated_at": _now().isoformat(),
           "known_domains": len(known), "schedules": [],
           "covered": [], "uncovered": [], "coverage": None,
           "duplicated": {}, "orphan_schedules": [], "disabled_schedules": [],
           "problems": [], "recommendations": []}

    covered: set = set()
    seen_by: dict = {}

    for row in rows:
        entry = {"id": row["id"], "name": row["name"],
                 "enabled": bool(row["enabled"]),
                 "interval_hours": row["interval_hours"],
                 "domain_list_id": row["domain_list_id"],
                 "list_name": None, "domain_count": 0,
                 "last_run_at": row["last_run_at"],
                 "next_run_at": row["next_run_at"],
                 "overdue": False, "never_run": not row["last_run_at"],
                 "problems": []}

        lst = lists.get(row["domain_list_id"])
        if lst is None:
            entry["problems"].append(
                f"domain_list_id={row['domain_list_id']} does not exist — "
                "this schedule runs and scans nothing")
            out["orphan_schedules"].append(row["name"])
        else:
            entry["list_name"] = lst["name"]
            domains = lst["domains"]
            entry["domain_count"] = len(domains)
            if not domains:
                entry["problems"].append("domain list is empty")
                out["orphan_schedules"].append(row["name"])
            if entry["enabled"]:
                for d in domains:
                    covered.add(d)
                    seen_by.setdefault(d, []).append(row["name"])

        if not entry["enabled"]:
            out["disabled_schedules"].append(row["name"])
            entry["problems"].append("disabled — it will never run")

        last = _parse(row["last_run_at"])
        if entry["enabled"] and last is not None:
            due = last + timedelta(hours=(row["interval_hours"] or
                                          DEFAULT_INTERVAL_HOURS)
                                   + OVERDUE_GRACE_HOURS)
            if _now() > due:
                entry["overdue"] = True
                entry["problems"].append(
                    f"overdue — last run {row['last_run_at']}, interval "
                    f"{row['interval_hours']}h")
        elif entry["enabled"] and last is None:
            entry["problems"].append(
                "has never run — note that APScheduler fires one full interval "
                "after the daemon starts, so a restarted daemon resets the "
                "clock")

        out["schedules"].append(entry)

    out["covered"] = sorted(covered & known)
    out["uncovered"] = sorted(known - covered)
    out["coverage"] = (round(len(out["covered"]) / len(known), 3)
                       if known else None)
    out["duplicated"] = {d: names for d, names in sorted(seen_by.items())
                         if len(names) > 1}

    stale = sorted(covered - known)
    if stale:
        out["problems"].append(
            f"{len(stale)} domain(s) are scheduled but unknown to the rest of "
            f"the database (e.g. {', '.join(stale[:5])})")
    if not rows:
        out["problems"].append(
            "No schedules exist — nothing is being rescanned automatically")
    if out["uncovered"]:
        out["problems"].append(
            f"{len(out['uncovered'])} of {len(known)} known domain(s) are in "
            "no enabled schedule and will never be rescanned")
    if out["duplicated"]:
        out["problems"].append(
            f"{len(out['duplicated'])} domain(s) appear in more than one "
            "enabled schedule — they are scanned repeatedly for no benefit")
    if out["orphan_schedules"]:
        out["problems"].append(
            "Schedule(s) bound to a missing or empty domain list: "
            + ", ".join(sorted(set(out["orphan_schedules"])))
            + " — they run and scan nothing")
    overdue = [s["name"] for s in out["schedules"] if s["overdue"]]
    if overdue:
        out["problems"].append(
            "Overdue schedule(s): " + ", ".join(overdue)
            + " — check the scheduler daemon is running "
              "(systemctl status see-monitor-scheduler)")

    if out["uncovered"] or not rows:
        out["recommendations"].append(
            "Run with --create-weekly to maintain one auto-managed list of "
            "every known domain, driven by a single weekly schedule")
    if out["orphan_schedules"]:
        out["recommendations"].append(
            "Delete or repoint the schedules whose domain list is missing or "
            "empty")
    if out["duplicated"]:
        out["recommendations"].append(
            "Consolidate overlapping schedules, or accept the duplication if "
            "the intervals differ deliberately")
    return out


# ----------------------------------------------------------------------
# Repair
# ----------------------------------------------------------------------
def create_weekly_all_domains(db, interval_hours: int = DEFAULT_INTERVAL_HOURS,
                              list_name: str = AUTO_LIST_NAME,
                              schedule_name: str = AUTO_SCHEDULE_NAME,
                              dry_run: bool = False) -> dict:
    """
    Ensure a single auto-managed domain list holding every known domain, and a
    single schedule driving it.

    Idempotent: re-running updates the list contents and the schedule interval
    in place rather than creating duplicates. Safe to run from cron.

    Returns a summary describing what was (or would be) changed.
    """
    domains = db.get_all_known_domains()
    result = {"dry_run": dry_run, "domains": len(domains),
              "list_id": None, "list_action": "unchanged",
              "schedule_id": None, "schedule_action": "unchanged",
              "added": [], "removed": [], "notes": []}

    if not domains:
        result["notes"].append(
            "No domains known to the database — nothing to schedule")
        return result

    existing = next((l for l in db.get_domain_lists()
                     if l["name"] == list_name), None)
    if existing:
        current = set(existing["domains"])
        wanted = set(domains)
        result["list_id"] = existing["id"]
        result["added"] = sorted(wanted - current)
        result["removed"] = sorted(current - wanted)
        if result["added"] or result["removed"]:
            result["list_action"] = "updated"
            if not dry_run:
                db.update_domain_list(existing["id"], domains=domains)
    else:
        result["list_action"] = "created"
        result["added"] = list(domains)
        if not dry_run:
            result["list_id"] = db.save_domain_list(
                list_name, domains, query="auto:all_known_domains")

    list_id = result["list_id"]

    with db._connect() as conn:
        row = conn.execute(
            "SELECT * FROM scheduled_scans WHERE name=?",
            (schedule_name,)).fetchone()

        if row is None:
            result["schedule_action"] = "created"
            if not dry_run:
                next_run = (_now() + timedelta(hours=interval_hours)).isoformat()
                cur = conn.execute(
                    "INSERT INTO scheduled_scans "
                    "(name, domain_list_id, interval_hours, enabled, "
                    " next_run_at) VALUES (?,?,?,1,?)",
                    (schedule_name, list_id, interval_hours, next_run))
                result["schedule_id"] = cur.lastrowid
        else:
            result["schedule_id"] = row["id"]
            changes = []
            if list_id is not None and row["domain_list_id"] != list_id:
                changes.append("domain_list_id")
            if row["interval_hours"] != interval_hours:
                changes.append("interval_hours")
            if not row["enabled"]:
                changes.append("enabled")
            if changes:
                result["schedule_action"] = "updated"
                result["notes"].append("changed: " + ", ".join(changes))
                if not dry_run:
                    conn.execute(
                        "UPDATE scheduled_scans SET domain_list_id=?, "
                        "interval_hours=?, enabled=1 WHERE id=?",
                        (list_id if list_id is not None
                         else row["domain_list_id"],
                         interval_hours, row["id"]))

    if not dry_run and (result["schedule_action"] != "unchanged"
                        or result["list_action"] != "unchanged"):
        result["notes"].append(
            "A running scheduler daemon picks up database changes on its next "
            "reload tick (see scheduling.reload_interval_minutes); restart the "
            "service to apply immediately")
    return result
