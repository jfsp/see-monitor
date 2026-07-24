#!/usr/bin/env python3
"""
SEE-Monitor: Schedule audit (standalone)

Reports which periodic scan schedules exist, which domains they cover, and
which domains known to the database are in no enabled schedule — i.e. which
domains are never rescanned.

    python3 scripts/schedule_audit.py --db /var/lib/see-monitor/see_monitor.db
    python3 scripts/schedule_audit.py --create-weekly --dry-run
    python3 scripts/schedule_audit.py --create-weekly

--create-weekly maintains ONE auto-managed domain list holding every known
domain, driven by ONE weekly schedule. It is idempotent, so it is safe to run
from cron to keep coverage complete as new domains appear.

Exit codes:
    0  every known domain is covered by an enabled schedule
    1  coverage gaps or schedule problems were found
    2  the database could not be opened

Note: this writes to `domain_lists` and `scheduled_scans` only when
--create-weekly is given; the audit itself is read-only. A running scheduler
daemon picks the change up on its next reload tick.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scheduler.schedule_audit import (audit_schedules,               # noqa: E402
                                      create_weekly_all_domains,
                                      DEFAULT_INTERVAL_HOURS)


def _load_db_path(args) -> str:
    if args.db:
        return args.db
    if os.path.exists(args.config):
        try:
            import yaml
            with open(args.config, encoding="utf-8") as fh:
                cfg = yaml.safe_load(fh) or {}
            return cfg.get("db_path", "data/see_monitor.db")
        except Exception:
            pass
    return os.environ.get("SEE_DB_PATH", "data/see_monitor.db")


def _print_report(report, action):
    print(f"SEE-Monitor schedule audit — {report['generated_at']}")
    print("")
    print("Schedules")
    if not report["schedules"]:
        print("  (none configured — nothing is rescanned automatically)")
    for sc in report["schedules"]:
        state = "enabled" if sc["enabled"] else "DISABLED"
        print(f"  [{sc['id']}] {sc['name']}  ({state}, every "
              f"{sc['interval_hours']}h)")
        print(f"      list: {sc['list_name'] or '<missing>'} "
              f"({sc['domain_count']} domain(s))")
        print(f"      last: {sc['last_run_at'] or 'never'}   "
              f"next: {sc['next_run_at'] or 'unknown'}")
        for problem in sc["problems"]:
            print(f"      ! {problem}")

    cov = report["coverage"]
    pct = "n/a" if cov is None else f"{cov * 100:.0f}%"
    print("")
    print("Coverage")
    print(f"  {len(report['covered'])} of {report['known_domains']} known "
          f"domain(s) covered ({pct})")
    if report["uncovered"]:
        shown = ", ".join(report["uncovered"][:15])
        more = ("" if len(report["uncovered"]) <= 15
                else f" (+{len(report['uncovered']) - 15} more)")
        print(f"  never rescanned: {shown}{more}")
    if report["duplicated"]:
        print(f"  in multiple schedules: {len(report['duplicated'])} domain(s)")

    if report["problems"]:
        print("")
        print("Problems")
        for problem in report["problems"]:
            print(f"  ! {problem}")
    if report["recommendations"]:
        print("")
        print("Recommendations")
        for rec in report["recommendations"]:
            print(f"  -> {rec}")

    if action:
        print("")
        print("Would apply" if action["dry_run"] else "Applied")
        print(f"  list      {action['list_action']} "
              f"({action['domains']} domain(s))")
        print(f"  schedule  {action['schedule_action']}")
        if action["added"]:
            print(f"  added     {len(action['added'])}")
        if action["removed"]:
            print(f"  removed   {len(action['removed'])}")
        for note in action["notes"]:
            print(f"  note      {note}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Audit and repair SEE-Monitor scan schedules.")
    ap.add_argument("--db", help="Path to see_monitor.db")
    ap.add_argument("--config", default="config/config.yaml")
    ap.add_argument("--json", action="store_true", help="Machine-readable")
    ap.add_argument("--create-weekly", action="store_true",
                    help="Create/refresh the auto-managed weekly schedule "
                         "covering every known domain")
    ap.add_argument("--interval-hours", type=int,
                    default=DEFAULT_INTERVAL_HOURS,
                    help=f"Interval for --create-weekly "
                         f"(default {DEFAULT_INTERVAL_HOURS} = weekly)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Report what --create-weekly would change, then exit")
    args = ap.parse_args()

    db_path = _load_db_path(args)
    if not os.path.exists(db_path):
        print(f"database not found: {db_path}", file=sys.stderr)
        return 2
    try:
        from data.database import Database
        db = Database(db_path)
    except Exception as exc:
        print(f"cannot open database: {exc}", file=sys.stderr)
        return 2

    action = None
    if args.create_weekly:
        action = create_weekly_all_domains(
            db, args.interval_hours, dry_run=args.dry_run)

    report = audit_schedules(db)
    if args.json:
        payload = {"audit": report}
        if action:
            payload["action"] = action
        print(json.dumps(payload, indent=2))
    else:
        _print_report(report, action)

    return 1 if (report["uncovered"] or report["problems"]) else 0


if __name__ == "__main__":
    sys.exit(main())
