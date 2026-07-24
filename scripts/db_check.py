#!/usr/bin/env python3
"""
SEE-Monitor: Database consistency checker

Read-only integrity/consistency audit of the SEE-Monitor SQLite database. It
never writes to the database (opens the file in read-only mode) and is safe to
run against a live deployment.

What it checks
--------------
  structural     PRAGMA integrity_check + PRAGMA foreign_key_check
  schema         schema_version present and matches the code's SCHEMA_VERSION
  orphans        soft references that have no declared FK
                 (roadmaps/assessments -> scan_runs; user_* / created_by ->
                 users; audit_log -> users)
  json           checks_json / controls_json / findings_json / domains_json /
                 roadmap_json parse as valid JSON
  values         assessments.score in [0,100]; no_mail in {0,1};
                 confidence in {high,medium,low} (schema v3);
                 guideline is installed; rating is valid for that guideline
  operational    (info) runs stuck in 'running'; assessments with no raw scan
  data           relational hygiene: scanned domains not linked to any org;
                 organisations with no domains; empty communities; analyst users
                 with no org; community_manager users with no community; users
                 with no access grants at all; no active admin; unknown roles;
                 empty/missing domain lists on schedules; stale roadmaps

Exit codes: 0 = no errors, 1 = at least one ERROR (or any issue with --strict),
2 = the check could not run (missing DB, etc.).

Standard library only. Run:
    python scripts/db_check.py --config config/config.yaml
    python scripts/db_check.py --db data/see_monitor.db --json

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Optional imports — the script degrades gracefully if the app package or the
# guideline profiles are not importable (e.g. run standalone against a copy).
try:
    from data.database import SCHEMA_VERSION as _EXPECTED_SCHEMA
except Exception:
    _EXPECTED_SCHEMA = None
try:
    from scanner.assessor import available_guidelines, load_guideline
except Exception:
    available_guidelines = None
    load_guideline = None
try:
    from auth.models import (ALL_ROLES, ROLE_ADMIN, ROLE_ANALYST,
                             ROLE_COMMUNITY_MANAGER)
except Exception:
    ROLE_ADMIN, ROLE_ANALYST, ROLE_COMMUNITY_MANAGER = (
        "admin", "analyst", "community_manager")
    ALL_ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_COMMUNITY_MANAGER)

_MAX_EXAMPLES = 10


class Issue:
    __slots__ = ("level", "check", "detail", "count", "examples")

    def __init__(self, level, check, detail, count=1, examples=None):
        self.level = level                       # error | warn | info
        self.check = check
        self.detail = detail
        self.count = count
        self.examples = examples or []

    def as_dict(self):
        return {"level": self.level, "check": self.check, "detail": self.detail,
                "count": self.count, "examples": self.examples[:_MAX_EXAMPLES]}


def _table_exists(conn, name):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,)).fetchone() is not None


def _cols(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


# ----------------------------------------------------------------------
# Individual checks. Each appends Issue objects to `out`; each is wrapped so a
# failure in one never aborts the audit.
# ----------------------------------------------------------------------
def _check_structural(conn, out):
    rows = conn.execute("PRAGMA integrity_check").fetchall()
    if not (len(rows) == 1 and rows[0][0] == "ok"):
        out.append(Issue("error", "integrity_check",
                         "SQLite reported structural corruption",
                         count=len(rows), examples=[r[0] for r in rows]))
    fk = conn.execute("PRAGMA foreign_key_check").fetchall()
    if fk:
        ex = [f"{r[0]} rowid={r[1]} -> {r[2]}" for r in fk]
        out.append(Issue("error", "foreign_key_check",
                         "Declared foreign-key violations (orphaned child rows)",
                         count=len(fk), examples=ex))


def _check_schema_version(conn, out):
    if not _table_exists(conn, "schema_version"):
        out.append(Issue("error", "schema_version",
                         "schema_version table is missing"))
        return
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    have = row[0] if row else None
    if have is None:
        out.append(Issue("error", "schema_version",
                         "schema_version table has no rows"))
    elif _EXPECTED_SCHEMA is None:
        out.append(Issue("info", "schema_version",
                         f"DB schema_version={have} (code version unknown here)"))
    elif have < _EXPECTED_SCHEMA:
        out.append(Issue("warn", "schema_version",
                         f"DB schema_version={have} < code {_EXPECTED_SCHEMA} "
                         "— migration expected on next startup"))
    elif have > _EXPECTED_SCHEMA:
        out.append(Issue("warn", "schema_version",
                         f"DB schema_version={have} > code {_EXPECTED_SCHEMA} "
                         "— database is newer than this code"))


def _orphans(conn, child, child_col, parent, parent_col, out,
             level="error", allow_null=True):
    """Report child rows whose *child_col* has no match in parent.parent_col."""
    if not (_table_exists(conn, child) and _table_exists(conn, parent)):
        return
    if child_col not in _cols(conn, child) or parent_col not in _cols(conn, parent):
        return
    null_clause = f" AND c.{child_col} IS NOT NULL" if allow_null else ""
    sql = (f"SELECT c.rowid, c.{child_col} FROM {child} c "
           f"LEFT JOIN {parent} p ON c.{child_col} = p.{parent_col} "
           f"WHERE p.{parent_col} IS NULL{null_clause}")
    rows = conn.execute(sql).fetchall()
    if rows:
        ex = [f"rowid={r[0]} {child_col}={r[1]!r}" for r in rows]
        out.append(Issue(level, "orphan",
                         f"{child}.{child_col} has no matching "
                         f"{parent}.{parent_col}",
                         count=len(rows), examples=ex))


def _check_orphans(conn, out):
    # Soft references (no declared FK in the schema).
    _orphans(conn, "roadmaps", "run_id", "scan_runs", "id", out,
             level="warn")
    # Cross-module references to the auth-owned users table.
    _orphans(conn, "user_organisations", "user_id", "users", "id", out,
             allow_null=False)
    _orphans(conn, "user_communities", "user_id", "users", "id", out,
             allow_null=False)
    _orphans(conn, "user_domain_lists", "user_id", "users", "id", out,
             allow_null=False)
    _orphans(conn, "organisations", "created_by", "users", "id", out,
             level="warn")
    _orphans(conn, "communities", "created_by", "users", "id", out,
             level="warn")
    _orphans(conn, "audit_log", "user_id", "users", "id", out, level="warn")


def _check_json(conn, out):
    targets = [
        ("raw_scans", "checks_json"), ("assessments", "controls_json"),
        ("assessments", "findings_json"),
        ("assessments", "subscores_json"),
        ("assessments", "confidence_notes_json"),
        ("domain_lists", "domains_json"),
        ("roadmaps", "roadmap_json"),
    ]
    for table, col in targets:
        if not _table_exists(conn, table) or col not in _cols(conn, table):
            continue
        bad = []
        for rowid, val in conn.execute(f"SELECT rowid, {col} FROM {table}"):
            try:
                json.loads(val)
            except (TypeError, ValueError):
                bad.append(f"rowid={rowid}")
        if bad:
            out.append(Issue("error", "json",
                             f"{table}.{col} contains unparseable JSON",
                             count=len(bad), examples=bad))


def _check_assessment_values(conn, out):
    if not _table_exists(conn, "assessments"):
        return
    cols = _cols(conn, "assessments")
    bad_score, bad_nomail = [], []
    for rowid, score, no_mail in conn.execute(
            "SELECT rowid, score, no_mail FROM assessments"):
        if score is None or not (0 <= score <= 100):
            bad_score.append(f"rowid={rowid} score={score}")
        if no_mail not in (0, 1):
            bad_nomail.append(f"rowid={rowid} no_mail={no_mail}")
    if bad_score:
        out.append(Issue("error", "values",
                         "assessments.score outside 0..100",
                         count=len(bad_score), examples=bad_score))
    if bad_nomail:
        out.append(Issue("error", "values",
                         "assessments.no_mail not boolean (0/1)",
                         count=len(bad_nomail), examples=bad_nomail))
    if "guideline" not in cols:
        return

    installed = set(available_guidelines()) if available_guidelines else None
    # unknown guideline profiles
    guidelines = [r[0] for r in conn.execute(
        "SELECT DISTINCT guideline FROM assessments")]
    if installed is not None:
        unknown = [g for g in guidelines if g not in installed]
        if unknown:
            out.append(Issue("warn", "values",
                             "assessments reference guideline profiles not "
                             "installed under guidelines/",
                             count=len(unknown), examples=unknown))
    # rating valid for each guideline's bands
    if load_guideline is not None:
        band_cache = {}
        bad_rating = []
        for rowid, guideline, rating in conn.execute(
                "SELECT rowid, guideline, rating FROM assessments"):
            if guideline not in band_cache:
                try:
                    g = load_guideline(None, guideline)
                    band_cache[guideline] = {
                        b["rating"] for b in g.get("rating_bands", [])}
                except Exception:
                    band_cache[guideline] = None       # unknown -> skip
            valid = band_cache[guideline]
            if valid and rating not in valid:
                bad_rating.append(f"rowid={rowid} {guideline}:{rating}")
        if bad_rating:
            out.append(Issue("warn", "values",
                             "assessment rating not defined by its guideline's "
                             "rating_bands",
                             count=len(bad_rating), examples=bad_rating))


def _check_confidence(conn, out):
    """v3: assessments.confidence must be one of the three evidence levels."""
    if not _table_exists(conn, "assessments"):
        return
    if "confidence" not in _cols(conn, "assessments"):
        return
    allowed = {"high", "medium", "low"}
    bad = []
    for rowid, value in conn.execute(
            "SELECT rowid, confidence FROM assessments"):
        if value not in allowed:
            bad.append(f"rowid={rowid} confidence={value!r}")
    if bad:
        out.append(Issue("error", "values",
                         "assessments.confidence outside {high,medium,low}",
                         count=len(bad), examples=bad))


def _check_operational(conn, out):
    if _table_exists(conn, "scan_runs"):
        stuck = conn.execute(
            "SELECT id FROM scan_runs WHERE status='running' "
            "AND finished_at IS NULL").fetchall()
        if stuck:
            out.append(Issue("info", "operational",
                             "scan_runs still marked 'running' (unfinished)",
                             count=len(stuck),
                             examples=[r[0] for r in stuck]))
    # assessments whose domain was never captured in raw_scans
    if _table_exists(conn, "assessments") and _table_exists(conn, "raw_scans"):
        rows = conn.execute(
            "SELECT DISTINCT a.domain FROM assessments a "
            "LEFT JOIN raw_scans r ON a.domain = r.domain "
            "WHERE r.domain IS NULL").fetchall()
        if rows:
            out.append(Issue("info", "operational",
                             "assessments exist with no raw_scans row for the "
                             "domain (provenance gap)",
                             count=len(rows),
                             examples=[r[0] for r in rows]))


def _check_data_relations(conn, out):
    """Semantic/relational data-hygiene checks (not corruption)."""
    have = lambda t: _table_exists(conn, t)

    # --- Domains vs organisations ------------------------------------
    if have("domain_organisations"):
        scanned = set()
        for t in ("assessments", "raw_scans"):
            if have(t):
                scanned |= {r[0] for r in conn.execute(
                    f"SELECT DISTINCT domain FROM {t}")}
        orged = {r[0] for r in conn.execute(
            "SELECT DISTINCT domain FROM domain_organisations")}
        missing = sorted(scanned - orged)
        if missing:
            out.append(Issue("warn", "data.domain_no_org",
                             "scanned domains not linked to any organisation "
                             "(excluded from org/community rollups)",
                             count=len(missing), examples=missing))
        dup = conn.execute(
            "SELECT domain, COUNT(*) FROM domain_organisations "
            "GROUP BY domain HAVING COUNT(*) > 1").fetchall()
        if dup:
            out.append(Issue("info", "data.domain_multi_org",
                             "domains associated with more than one organisation",
                             count=len(dup),
                             examples=[f"{r[0]} (x{r[1]})" for r in dup]))

    if have("organisations") and have("domain_organisations"):
        rows = conn.execute(
            "SELECT o.id, o.name FROM organisations o "
            "LEFT JOIN domain_organisations d ON o.id = d.org_id "
            "WHERE d.org_id IS NULL").fetchall()
        if rows:
            out.append(Issue("info", "data.org_no_domains",
                             "organisations with no domains",
                             count=len(rows),
                             examples=[f"id={r[0]} {r[1]!r}" for r in rows]))

    # --- Communities --------------------------------------------------
    if have("communities"):
        if have("community_organisations"):
            rows = conn.execute(
                "SELECT c.id, c.name FROM communities c "
                "LEFT JOIN community_organisations co ON c.id = co.community_id "
                "WHERE co.community_id IS NULL").fetchall()
        else:
            rows = conn.execute("SELECT id, name FROM communities").fetchall()
        if rows:
            out.append(Issue("warn", "data.empty_community",
                             "communities with no member organisations",
                             count=len(rows),
                             examples=[f"id={r[0]} {r[1]!r}" for r in rows]))

    # --- Users / RBAC -------------------------------------------------
    if have("users"):
        cols = _cols(conn, "users")
        has_role = "role" in cols
        if has_role:
            active = " AND is_active = 1" if "is_active" in cols else ""
            n_admin = conn.execute(
                f"SELECT COUNT(*) FROM users WHERE role = ?{active}",
                (ROLE_ADMIN,)).fetchone()[0]
            if n_admin == 0:
                out.append(Issue("warn", "data.no_active_admin",
                                 "no active admin user exists — the platform "
                                 "cannot be administered"))
            unknown = [r[0] for r in conn.execute(
                "SELECT DISTINCT role FROM users") if r[0] not in ALL_ROLES]
            if unknown:
                out.append(Issue("warn", "data.unknown_role",
                                 "users with a role outside the known set "
                                 f"{tuple(ALL_ROLES)}",
                                 count=len(unknown), examples=unknown))

        if has_role and have("user_organisations"):
            rows = conn.execute(
                "SELECT u.id, u.username FROM users u "
                "LEFT JOIN user_organisations uo ON u.id = uo.user_id "
                "WHERE u.role = ? AND uo.user_id IS NULL",
                (ROLE_ANALYST,)).fetchall()
            if rows:
                out.append(Issue("warn", "data.analyst_no_org",
                                 "analyst users not assigned to any organisation",
                                 count=len(rows),
                                 examples=[f"id={r[0]} {r[1]}" for r in rows]))

        if has_role and have("user_communities"):
            rows = conn.execute(
                "SELECT u.id, u.username FROM users u "
                "LEFT JOIN user_communities uc ON u.id = uc.user_id "
                "WHERE u.role = ? AND uc.user_id IS NULL",
                (ROLE_COMMUNITY_MANAGER,)).fetchall()
            if rows:
                out.append(Issue("warn", "data.community_manager_no_community",
                                 "community_manager users with no community "
                                 "assigned",
                                 count=len(rows),
                                 examples=[f"id={r[0]} {r[1]}" for r in rows]))

        grant_tables = [t for t in ("user_organisations", "user_communities",
                                    "user_domain_lists") if have(t)]
        if has_role and grant_tables:
            union = " UNION ".join(
                f"SELECT user_id FROM {t}" for t in grant_tables)
            rows = conn.execute(
                "SELECT u.id, u.username, u.role FROM users u "
                f"WHERE u.role <> ? AND u.id NOT IN ({union})",
                (ROLE_ADMIN,)).fetchall()
            if rows:
                out.append(Issue("warn", "data.user_no_access",
                                 "non-admin users with no org/community/"
                                 "domain-list grants (can see nothing)",
                                 count=len(rows),
                                 examples=[f"id={r[0]} {r[1]} ({r[2]})"
                                           for r in rows]))

    # --- Domain lists & schedules ------------------------------------
    if have("domain_lists"):
        empties = []
        for rid, name, dj in conn.execute(
                "SELECT id, name, domains_json FROM domain_lists"):
            try:
                arr = json.loads(dj)
            except (TypeError, ValueError):
                continue                       # bad JSON already reported
            if isinstance(arr, list) and not arr:
                empties.append(f"id={rid} {name!r}")
        if empties:
            out.append(Issue("info", "data.empty_domain_list",
                             "domain lists with zero domains",
                             count=len(empties), examples=empties))

    if have("scheduled_scans") and have("domain_lists"):
        rows = conn.execute(
            "SELECT s.id, s.name FROM scheduled_scans s "
            "LEFT JOIN domain_lists d ON s.domain_list_id = d.id "
            "WHERE s.domain_list_id IS NULL OR d.id IS NULL").fetchall()
        if rows:
            out.append(Issue("warn", "data.schedule_no_list",
                             "scheduled scans whose domain list is unset or "
                             "missing (they scan nothing)",
                             count=len(rows),
                             examples=[f"id={r[0]} {r[1]!r}" for r in rows]))

    # --- Stale roadmaps ----------------------------------------------
    if have("roadmaps") and have("assessments"):
        rows = conn.execute(
            "SELECT r.id, r.domain FROM roadmaps r "
            "LEFT JOIN assessments a ON r.domain = a.domain "
            "WHERE r.domain IS NOT NULL AND a.domain IS NULL").fetchall()
        if rows:
            out.append(Issue("info", "data.stale_roadmap",
                             "roadmaps whose domain has no assessment",
                             count=len(rows),
                             examples=[f"id={r[0]} {r[1]}" for r in rows]))


_CHECKS = [_check_structural, _check_schema_version, _check_orphans,
           _check_json, _check_assessment_values, _check_confidence,
           _check_operational, _check_data_relations]


def run_checks(db_path: str) -> list:
    """Run every check read-only; return a list of Issue objects."""
    if not os.path.exists(db_path):
        return [Issue("error", "open", f"database not found: {db_path}")]
    out: list = []
    uri = f"file:{os.path.abspath(db_path)}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        return [Issue("error", "open", f"cannot open database: {exc}")]
    try:
        for check in _CHECKS:
            try:
                check(conn, out)
            except sqlite3.Error as exc:
                out.append(Issue("error", check.__name__,
                                 f"check failed: {exc}"))
    finally:
        conn.close()
    return out


# ----------------------------------------------------------------------
def _load_db_path(args) -> str:
    if args.db:
        return args.db
    cfg = {}
    if args.config and os.path.exists(args.config):
        try:
            import yaml
            with open(args.config) as fh:
                cfg = yaml.safe_load(fh) or {}
        except Exception:
            cfg = {}
    return cfg.get("db_path", "data/see_monitor.db")


def main() -> int:
    ap = argparse.ArgumentParser(description="SEE-Monitor DB consistency check")
    ap.add_argument("--db", help="Path to the SQLite database file")
    ap.add_argument("--config", default="config/config.yaml",
                    help="Config file to read db_path from (if --db omitted)")
    ap.add_argument("--json", action="store_true", help="Machine-readable output")
    ap.add_argument("--strict", action="store_true",
                    help="Exit non-zero on warnings too, not just errors")
    args = ap.parse_args()

    db_path = _load_db_path(args)
    issues = run_checks(db_path)
    errors = sum(1 for i in issues if i.level == "error")
    warns = sum(1 for i in issues if i.level == "warn")
    infos = sum(1 for i in issues if i.level == "info")

    if args.json:
        print(json.dumps({
            "db": db_path, "errors": errors, "warnings": warns, "info": infos,
            "issues": [i.as_dict() for i in issues]}, indent=2))
    else:
        print(f"SEE-Monitor DB check — {db_path}")
        if not issues:
            print("  ✓ clean: no inconsistencies detected")
        for i in sorted(issues, key=lambda x: {"error": 0, "warn": 1,
                                               "info": 2}[x.level]):
            tag = {"error": "ERROR", "warn": "WARN ", "info": "INFO "}[i.level]
            print(f"  [{tag}] {i.check}: {i.detail} (x{i.count})")
            for ex in i.examples[:_MAX_EXAMPLES]:
                print(f"           - {ex}")
            if i.count > _MAX_EXAMPLES:
                print(f"           … and {i.count - _MAX_EXAMPLES} more")
        print(f"\nSummary: {errors} error(s), {warns} warning(s), {infos} info.")

    if errors or (args.strict and warns):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
