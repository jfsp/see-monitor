#!/usr/bin/env python3
"""
SEE-Monitor: Prune no-mail / empty domains

Removes domains that were added to a scan by mistake — domains that have no MX
record and therefore no email-security posture to measure. Left in place they
show up as "no email (N/A)" on dashboards, which is correct but clutters the
view; this tool deletes them completely.

Two ways to choose what to remove:

  * DEFAULT (inspect the database) — every domain whose most recent assessment
    is flagged no_mail *and* carries no positive signal at all (every control
    score is 0 or n/a). A deliberately parked domain that publishes, say,
    `v=spf1 -all` is NOT selected, because it is doing something.

  * --list FILE — remove exactly the domains in the file (one per line, `#`
    comments allowed), regardless of what the database thinks. Use this to
    clean up a known bad batch.

  * --all-no-mail — relax the DEFAULT so that ANY no_mail domain is removed,
    even one with a positive anti-spoofing record. Use with care.

"Completely" means: raw scans, assessments, DKIM selectors, organisation
assignments and roadmaps for the domain are deleted, and the domain is stripped
from every saved domain list. Organisations, communities and schedules
themselves are kept — only the domain's membership is removed.

    # See what would be removed (always start here)
    python3 scripts/prune_no_mail.py --dry-run

    # Remove empty no-mail domains found in the DB
    python3 scripts/prune_no_mail.py

    # Remove a specific bad batch
    python3 scripts/prune_no_mail.py --list bad_domains.txt

This tool WRITES to the database. It refuses to proceed without either
--dry-run or --yes, so an accidental invocation cannot delete anything.

Exit codes:
    0  completed (including a dry run, and the case of nothing to do)
    2  fatal: database or list could not be read

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _load_config(config_path: str) -> dict:
    if not os.path.exists(config_path):
        return {}
    try:
        import yaml
        with open(config_path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


def _read_list(path: str) -> list[str]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line.split(",")[0].strip().lower().rstrip("."))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Remove no-mail / empty domains from the database.")
    ap.add_argument("--db", help="Override db_path from the config file.")
    ap.add_argument("--config", default="config/config.yaml")
    ap.add_argument("--list", dest="list_file",
                    help="Remove exactly the domains in this file "
                         "(one per line), regardless of DB state.")
    ap.add_argument("--all-no-mail", action="store_true",
                    help="When inspecting the DB, remove every no_mail domain, "
                         "not only the ones with zero positive signal.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show what would be removed; change nothing.")
    ap.add_argument("--yes", action="store_true",
                    help="Actually delete (required unless --dry-run).")
    args = ap.parse_args()

    cfg = _load_config(args.config)
    db_path = args.db or cfg.get("db_path", "data/see_monitor.db")
    if not os.path.exists(db_path):
        print(f"database not found: {db_path}", file=sys.stderr)
        return 2
    try:
        from data.database import Database
        db = Database(db_path)
    except Exception as exc:
        print(f"cannot open database {db_path}: {exc}", file=sys.stderr)
        return 2

    # ---- Decide the target set ---------------------------------------
    if args.list_file:
        if not os.path.exists(args.list_file):
            print(f"list not found: {args.list_file}", file=sys.stderr)
            return 2
        listed = _read_list(args.list_file)
        known = set(db.get_all_known_domains())
        targets = sorted(set(listed))
        source = f"list {args.list_file}"
        # Warn about entries that are not in the DB (nothing to delete) or that
        # do receive mail (the operator may be removing something real).
        not_in_db = [d for d in targets if d not in known]
        flagged = {e["domain"] for e in db.find_no_mail_domains(empty_only=False)}
        has_mail = [d for d in targets if d in known and d not in flagged]
    else:
        rows = db.find_no_mail_domains(empty_only=not args.all_no_mail)
        targets = [r["domain"] for r in rows]
        source = ("all no-mail domains in the DB" if args.all_no_mail
                  else "empty no-mail domains in the DB")
        not_in_db = []
        has_mail = []

    print(f"SEE-Monitor prune — source: {source}")
    print(f"Database: {db_path}")
    print("")

    if not targets:
        print("Nothing to remove.")
        return 0

    print(f"{len(targets)} domain(s) selected:")
    for d in targets:
        print(f"  - {d}")
    if not_in_db:
        print("")
        print(f"note: {len(not_in_db)} listed domain(s) are not in the "
              "database (nothing to delete for them): "
              + ", ".join(not_in_db[:10]))
    if has_mail:
        print("")
        print(f"WARNING: {len(has_mail)} listed domain(s) DO have mail and are "
              "not flagged no_mail — removing them anyway because they were "
              "given explicitly: " + ", ".join(has_mail[:10]))

    if args.dry_run:
        print("")
        print("Dry run — nothing was changed.")
        return 0

    if not args.yes:
        print("")
        print("Refusing to delete without --yes. Re-run with --dry-run to "
              "preview, or --yes to proceed.", file=sys.stderr)
        return 0

    counts = db.purge_domains(targets)
    print("")
    print("Removed:")
    print(f"  assessments          {counts['assessments']}")
    print(f"  raw_scans            {counts['raw_scans']}")
    print(f"  dkim_selectors       {counts['dkim_selectors']}")
    print(f"  organisation links   {counts['domain_organisations']}")
    print(f"  roadmaps             {counts['roadmaps']}")
    print(f"  domain lists updated {counts['lists_updated']}")
    print("")
    print(f"{counts['domains']} domain(s) purged from the database.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
