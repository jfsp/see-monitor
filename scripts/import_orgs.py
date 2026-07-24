#!/usr/bin/env python3
"""
SEE-Monitor: Bulk organisation import

Takes a CSV of `domain,organisation,country` and, in one pass:

  1. registers each organisation (creating it if it does not exist) and
     assigns its domains,
  2. optionally adds every organisation in the file to a named community,
  3. scans every domain and writes a dated log of the results,
  4. optionally refreshes the weekly all-domains schedule so the new domains
     are actually rescanned from now on.

    python3 scripts/import_orgs.py banks.csv --community "EU Central Banks"
    python3 scripts/import_orgs.py banks.csv --dry-run
    python3 scripts/import_orgs.py banks.csv --no-scan --schedule

INPUT FORMAT
------------
One row per domain. Blank lines and `#` comments are ignored, a header row
starting with `domain` is skipped, and quoted fields are handled, so
organisation names containing commas are safe:

    oenb.at,Oesterreichische Nationalbank,Austria
    fma.gv.at,Finanzmarktaufsicht,Austria
    "example.be","Bank, National",Belgium

A fourth column is accepted and used as the organisation's sector. Several
rows may share an organisation name; their domains are merged into one
organisation, which is the normal case for a regulator with several domains.

ORDER OF OPERATIONS
-------------------
Registration happens BEFORE scanning, deliberately. Scanning a large list takes
minutes to hours, and a crash or Ctrl-C partway through would otherwise lose
the entire import. Registration is fast and idempotent, so doing it first means
an interrupted run can simply be repeated. Use --scan-only to rescan an
already-imported file.

IDEMPOTENCY
-----------
Safe to re-run. Organisations are matched by name (case-insensitive), domain
assignments and community membership use INSERT OR IGNORE, and existing domain
assignments are never removed. Re-running after adding rows imports only the
new material.

Exit codes:
    0  everything succeeded
    1  completed with errors (bad rows, or one or more scans failed)
    2  fatal: input or database could not be read

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import csv
import io
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+"
                       r"[a-z]{2,63}$")

DEFAULT_LOG_DIR = "logs"


# ----------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------
def parse_rows(text: str) -> tuple:
    """
    Parse CSV text into (rows, errors).

    row = {"domain", "organisation", "country", "sector", "line"}
    errors are human-readable strings naming the offending line.
    """
    rows, errors = [], []
    first_data_row = True
    reader = csv.reader(io.StringIO(text))
    for lineno, fields in enumerate(reader, start=1):
        if not fields:
            continue
        raw = [f.strip() for f in fields]
        if not any(raw) or raw[0].startswith("#"):
            continue
        # A header may not be on line 1: comment lines are common above it.
        if first_data_row and raw[0].lower() in ("domain", "domains", "fqdn"):
            first_data_row = False
            continue
        first_data_row = False
        if len(raw) < 2:
            errors.append(f"line {lineno}: expected at least "
                          f"'domain,organisation' — got {raw!r}")
            continue

        domain = raw[0].lower().rstrip(".").lstrip("*.")
        org = raw[1]
        country = raw[2] if len(raw) > 2 else ""
        sector = raw[3] if len(raw) > 3 else ""

        if not DOMAIN_RE.match(domain):
            errors.append(f"line {lineno}: '{raw[0]}' is not a valid domain")
            continue
        if not org:
            errors.append(f"line {lineno}: organisation name is empty")
            continue
        rows.append({"domain": domain, "organisation": org,
                     "country": country, "sector": sector, "line": lineno})
    return rows, errors


def group_by_org(rows: list) -> dict:
    """Merge rows into {organisation_name: {domains, country, sector}}."""
    groups: dict = {}
    for row in rows:
        key = row["organisation"].strip()
        entry = groups.setdefault(key, {"name": key, "domains": [],
                                        "country": "", "sector": "",
                                        "conflicts": []})
        if row["domain"] not in entry["domains"]:
            entry["domains"].append(row["domain"])
        for field in ("country", "sector"):
            value = row[field]
            if not value:
                continue
            if not entry[field]:
                entry[field] = value
            elif entry[field].lower() != value.lower():
                entry["conflicts"].append(
                    f"line {row['line']}: {field} '{value}' conflicts with "
                    f"'{entry[field]}' — keeping the first")
    return groups


# ----------------------------------------------------------------------
# Geography
# ----------------------------------------------------------------------
def _country_name_index() -> dict:
    """Build {lowercase country name: (code, country, region)} from tld_geo."""
    index = {}
    try:
        from data.geo_inference import _load_table
        for entry in _load_table().values():
            name = (entry.get("country") or "").strip().lower()
            if name and name not in index:
                index[name] = (entry.get("country_code", ""),
                               entry.get("country", ""),
                               entry.get("region", ""))
    except Exception:
        pass
    return index


def resolve_geo(domains: list, country_name: str, name_index: dict) -> tuple:
    """
    Return (country_code, country, region).

    The ccTLD is the strongest signal, so it decides the code and region. The
    operator-supplied country name wins as the display label, because the CSV
    reflects an intent the TLD cannot express (a .eu or .com domain belonging
    to a national body, for example).
    """
    code = country = region = ""
    try:
        from data.geo_inference import infer_from_domains
        result = infer_from_domains(domains)
        if result.inferred:
            code, country, region = (result.country_code, result.country,
                                     result.region)
    except Exception:
        pass
    if country_name:
        hit = name_index.get(country_name.strip().lower())
        if hit:
            if not code:
                code = hit[0]
            if not region:
                region = hit[2]
        country = country_name.strip()
    return code, country, region


# ----------------------------------------------------------------------
# Planning and application
# ----------------------------------------------------------------------
def plan_import(db, groups: dict, community: str = "") -> dict:
    """Work out what would change, without changing anything."""
    existing = {o["name"].strip().lower(): o for o in db.get_organisations()}
    name_index = _country_name_index()

    plan = {"organisations": [], "community": None,
            "domains_total": 0, "new_domains": 0}

    for name, entry in groups.items():
        current = existing.get(name.lower())
        code, country, region = resolve_geo(entry["domains"],
                                            entry["country"], name_index)
        assigned = (set(db.get_org_domains(current["id"]))
                    if current else set())
        to_add = [d for d in entry["domains"] if d not in assigned]
        plan["organisations"].append({
            "name": name, "org_id": current["id"] if current else None,
            "action": "reuse" if current else "create",
            "country_code": code, "country": country, "region": region,
            "sector": entry["sector"],
            "domains": entry["domains"], "new_domains": to_add,
            "conflicts": entry["conflicts"],
        })
        plan["domains_total"] += len(entry["domains"])
        plan["new_domains"] += len(to_add)

    if community:
        found = next((c for c in db.get_communities()
                      if c["name"].strip().lower() == community.strip().lower()),
                     None)
        plan["community"] = {"name": community,
                             "id": found["id"] if found else None,
                             "action": "reuse" if found else "create",
                             "org_count": len(plan["organisations"])}
    return plan


def apply_import(db, plan: dict, dry_run: bool = False,
                 created_by: int = None) -> dict:
    """Create/update organisations, domain assignments and community."""
    summary = {"created": 0, "reused": 0, "domains_assigned": 0,
               "community_action": None, "org_ids": []}

    for org in plan["organisations"]:
        org_id = org["org_id"]
        if org["action"] == "create":
            summary["created"] += 1
            if not dry_run:
                org_id = db.create_organisation(
                    name=org["name"], sector=org["sector"],
                    region=org["region"], country_code=org["country_code"],
                    country=org["country"], created_by=created_by)
        else:
            summary["reused"] += 1
            # Backfill geography on an organisation imported without it.
            if not dry_run and org_id is not None:
                current = db.get_organisation(org_id) or {}
                fields = {}
                for key in ("country_code", "country", "region", "sector"):
                    if org[key] and not (current.get(key) or "").strip():
                        fields[key] = org[key]
                if fields:
                    db.update_organisation(org_id, **fields)

        org["org_id"] = org_id
        if org_id is not None:
            summary["org_ids"].append(org_id)
        # replace=False: never remove domains this file does not mention.
        if not dry_run and org_id is not None and org["new_domains"]:
            db.set_org_domains(org_id, org["new_domains"], replace=False)
        summary["domains_assigned"] += len(org["new_domains"])

    community = plan.get("community")
    if community:
        cid = community["id"]
        if cid is None:
            summary["community_action"] = "created"
            if not dry_run:
                cid = db.create_community(
                    community["name"],
                    description="Imported by scripts/import_orgs.py",
                    created_by=created_by)
        else:
            summary["community_action"] = "reused"
        community["id"] = cid
        if not dry_run and cid is not None and summary["org_ids"]:
            db.set_community_orgs(cid, summary["org_ids"], replace=False)
    return summary


# ----------------------------------------------------------------------
# Scanning
# ----------------------------------------------------------------------
def scan_domains(cfg, db, domains: list, log, profiles=None) -> dict:
    """Scan each domain, persist results, and write one log line per domain."""
    from scanner.orchestrator import ScanOrchestrator
    from scanner.assessor import assess_all_profiles, available_guidelines

    gids = profiles or available_guidelines()
    orch = ScanOrchestrator(cfg, db=db)
    run_id = db.create_run(domains, trigger="import")
    stats = {"run_id": run_id, "ok": 0, "failed": 0, "failures": []}

    log(f"[scan] run {run_id}: {len(domains)} domain(s) x "
        f"{len(gids)} profile(s)")
    for domain in domains:
        try:
            scan = orch.scan_domain(domain)
            db.save_scan_result(run_id, scan)
            assessments = assess_all_profiles(scan, cfg, gids)
            for a in assessments.values():
                db.save_assessment(run_id, a)
            primary = next(iter(assessments.values()))
            scores = "  ".join(
                f"{gid}={a['score']}/{a['rating']}"
                for gid, a in assessments.items())
            log(f"[scan] {domain:<28} evidence={primary['confidence']:<6} "
                f"{scores}")
            stats["ok"] += 1
        except Exception as exc:
            log(f"[scan] {domain:<28} FAILED: {exc}")
            stats["failed"] += 1
            stats["failures"].append(domain)
        finally:
            db.bump_run_progress(run_id)
    db.finish_run(run_id,
                  "completed" if not stats["failed"] else "completed_with_errors")
    return stats


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def _open_log(log_dir: str, log_file: str):
    """Open the dated log file and return (write_fn, path, close_fn)."""
    if log_file:
        path = log_file
    else:
        os.makedirs(log_dir, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = os.path.join(log_dir, f"see-monitor-import-{stamp}.log")
    handle = open(path, "a", encoding="utf-8")

    def write(line: str = ""):
        print(line)
        handle.write(line + "\n")
        handle.flush()

    return write, path, handle.close


def _load_config(config_path: str) -> dict:
    if not os.path.exists(config_path):
        return {}
    try:
        import yaml
        with open(config_path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Bulk-import organisations and domains from CSV, scan "
                    "them, and optionally group them into a community.")
    ap.add_argument("csv_file", help="CSV: domain,organisation,country[,sector]")
    ap.add_argument("--community", default="",
                    help="Add every imported organisation to this community "
                         "(created if it does not exist).")
    ap.add_argument("--config", default="config/config.yaml")
    ap.add_argument("--db", help="Override db_path from the config file.")
    ap.add_argument("--log-dir", default=DEFAULT_LOG_DIR,
                    help=f"Directory for the dated log (default {DEFAULT_LOG_DIR}/).")
    ap.add_argument("--log-file", default="",
                    help="Explicit log path, overriding --log-dir.")
    ap.add_argument("--profile", action="append", default=None,
                    help="Limit scoring to specific profile(s); repeatable.")
    ap.add_argument("--no-scan", action="store_true",
                    help="Import and assign only; do not scan.")
    ap.add_argument("--scan-only", action="store_true",
                    help="Scan the domains in the file without touching "
                         "organisations or communities.")
    ap.add_argument("--schedule", action="store_true",
                    help="Refresh the auto-managed weekly schedule afterwards "
                         "so the new domains are rescanned periodically.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Report what would change; write nothing, scan nothing.")
    args = ap.parse_args()

    try:
        with open(args.csv_file, encoding="utf-8-sig") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"cannot read {args.csv_file}: {exc}", file=sys.stderr)
        return 2

    rows, errors = parse_rows(text)
    if not rows:
        print("no usable rows found in the input file", file=sys.stderr)
        for err in errors:
            print(f"  ! {err}", file=sys.stderr)
        return 2

    cfg = _load_config(args.config)
    db_path = args.db or cfg.get("db_path", "data/see_monitor.db")
    try:
        from data.database import Database
        db = Database(db_path)
    except Exception as exc:
        print(f"cannot open database {db_path}: {exc}", file=sys.stderr)
        return 2

    write, log_path, close = _open_log(args.log_dir, args.log_file)
    started = datetime.now(timezone.utc)
    groups = group_by_org(rows)
    domains = sorted({r["domain"] for r in rows})
    exit_code = 0

    try:
        write("=" * 72)
        write(f"SEE-Monitor bulk import — {started.isoformat()}")
        write(f"Source:    {os.path.abspath(args.csv_file)}")
        write(f"Database:  {db_path}")
        write(f"Parsed:    {len(rows)} row(s), {len(groups)} organisation(s), "
              f"{len(domains)} domain(s)")
        if args.community:
            write(f"Community: {args.community}")
        if args.dry_run:
            write("Mode:      DRY RUN — nothing will be written")
        write("=" * 72)

        for err in errors:
            write(f"  ! skipped {err}")
            exit_code = 1

        if not args.scan_only:
            plan = plan_import(db, groups, args.community)
            for org in plan["organisations"]:
                geo = " / ".join(x for x in (org["country_code"],
                                             org["region"]) if x)
                write(f"[org] {org['action']:<6} {org['name']}"
                      + (f"  ({geo})" if geo else ""))
                for conflict in org["conflicts"]:
                    write(f"        ! {conflict}")
                    exit_code = 1
                for domain in org["domains"]:
                    mark = "+" if domain in org["new_domains"] else "="
                    write(f"        {mark} {domain}")

            summary = apply_import(db, plan, dry_run=args.dry_run)
            write("")
            write(f"[import] organisations: {summary['created']} created, "
                  f"{summary['reused']} reused")
            write(f"[import] domain assignments added: "
                  f"{summary['domains_assigned']}")
            if plan.get("community"):
                attached = (plan["community"]["org_count"] if args.dry_run
                            else len(summary["org_ids"]))
                verb = "would attach" if args.dry_run else "attached"
                write(f"[import] community '{plan['community']['name']}' "
                      f"{summary['community_action']} — {attached} "
                      f"organisation(s) {verb}")
            write("")

        if args.no_scan or args.dry_run:
            write("[scan] skipped")
        else:
            stats = scan_domains(cfg, db, domains, write, args.profile)
            write("")
            write(f"[scan] {stats['ok']} ok, {stats['failed']} failed")
            if stats["failures"]:
                write("[scan] failed: " + ", ".join(stats["failures"]))
                exit_code = 1

        if args.schedule and not args.dry_run:
            from scheduler.schedule_audit import create_weekly_all_domains
            action = create_weekly_all_domains(db)
            write(f"[schedule] list {action['list_action']}, "
                  f"schedule {action['schedule_action']} "
                  f"({action['domains']} domain(s))")
            for note in action["notes"]:
                write(f"[schedule] {note}")

        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        write("")
        write(f"Finished in {elapsed:.1f}s — log: {log_path}")
        write("=" * 72)
    finally:
        close()

    print(f"\nLog written to {log_path}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
