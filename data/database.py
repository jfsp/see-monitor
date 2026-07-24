#!/usr/bin/env python3
"""
SEE-Monitor: Database Layer (SQLite, WAL mode)
Fresh schema (v1) designed for email-security assessments. The API surface
mirrors PQC-Monitor's Database where the auth/admin layers depend on it
(domain lists, organisations, communities, user scoping), so those modules
work unchanged.

Schema notes (lessons carried over):
  - PRAGMA foreign_keys=ON on every connection.
  - assessments always persist every computed column (no silent omissions).
  - domain is always a normalised bare FQDN; MX hosts never leak into the
    domain column.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import logging
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "data/see_monitor.db"
SCHEMA_VERSION = 2
# Assessments are now stored per (domain, guideline); this is the guideline
# used when a caller does not specify one, preserving pre-v2 behaviour.
DEFAULT_GUIDELINE_ID = "nist_800_177r1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


import datetime as _dt


def _period_bucket(iso: str, period: str) -> tuple:
    """Return (key, label, start_iso) for an assessed_at timestamp.

    period: weekly (ISO week, default) | monthly | quarterly | yearly.
    """
    try:
        d = _dt.date.fromisoformat((iso or "")[:10])
    except ValueError:
        d = _dt.date(1970, 1, 1)
    if period == "yearly":
        return (f"{d.year}", str(d.year), f"{d.year}-01-01")
    if period == "quarterly":
        q = (d.month - 1) // 3 + 1
        return (f"{d.year}-Q{q}", f"{d.year} Q{q}",
                f"{d.year}-{3 * (q - 1) + 1:02d}-01")
    if period == "monthly":
        return (f"{d.year}-{d.month:02d}", d.strftime("%b %Y"),
                f"{d.year}-{d.month:02d}-01")
    # weekly (ISO-8601 week starting Monday)
    iso_y, iso_w, _ = d.isocalendar()
    monday = _dt.date.fromisocalendar(iso_y, iso_w, 1)
    return (f"{iso_y}-W{iso_w:02d}", f"{iso_y}-W{iso_w:02d}", monday.isoformat())


class Database:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        d = os.path.dirname(db_path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version     INTEGER NOT NULL,
                applied_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_runs (
                id            TEXT PRIMARY KEY,
                started_at    TEXT NOT NULL,
                finished_at   TEXT,
                status        TEXT NOT NULL DEFAULT 'running',
                trigger       TEXT DEFAULT 'manual',
                domains_total INTEGER DEFAULT 0,
                domains_done  INTEGER DEFAULT 0
            );

            -- One row per (run, domain): full JSON of every control check
            CREATE TABLE IF NOT EXISTS raw_scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id      TEXT REFERENCES scan_runs(id),
                domain      TEXT NOT NULL,
                scanned_at  TEXT NOT NULL,
                checks_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_raw_domain ON raw_scans(domain);

            CREATE TABLE IF NOT EXISTS assessments (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id         TEXT REFERENCES scan_runs(id),
                domain         TEXT NOT NULL,
                assessed_at    TEXT NOT NULL,
                guideline      TEXT NOT NULL,
                score          REAL NOT NULL,
                rating         TEXT NOT NULL,
                no_mail        INTEGER NOT NULL DEFAULT 0,
                controls_json  TEXT NOT NULL,   -- {control: score|null}
                findings_json  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assess_domain
                ON assessments(domain, assessed_at);
            -- v2: latest-per-(domain,guideline) lookups for multi-profile scoring
            CREATE INDEX IF NOT EXISTS idx_assess_domain_guideline
                ON assessments(guideline, domain, assessed_at);

            CREATE TABLE IF NOT EXISTS dkim_selectors (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                domain       TEXT NOT NULL,
                selector     TEXT NOT NULL,
                source       TEXT NOT NULL DEFAULT 'manual',
                added_at     TEXT NOT NULL,
                last_seen_at TEXT,
                UNIQUE(domain, selector)
            );

            CREATE TABLE IF NOT EXISTS domain_lists (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL,
                query        TEXT,
                created_at   TEXT NOT NULL,
                domains_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                name           TEXT NOT NULL,
                domain_list_id INTEGER REFERENCES domain_lists(id),
                interval_hours INTEGER NOT NULL DEFAULT 168,
                enabled        INTEGER NOT NULL DEFAULT 1,
                last_run_at    TEXT,
                next_run_at    TEXT
            );

            CREATE TABLE IF NOT EXISTS organisations (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL UNIQUE,
                sector       TEXT DEFAULT '',
                description  TEXT DEFAULT '',
                country_code TEXT DEFAULT '',
                country      TEXT DEFAULT '',
                region       TEXT DEFAULT '',
                created_by   INTEGER,
                created_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS domain_organisations (
                domain  TEXT NOT NULL,
                org_id  INTEGER NOT NULL REFERENCES organisations(id)
                        ON DELETE CASCADE,
                PRIMARY KEY (domain, org_id)
            );

            CREATE TABLE IF NOT EXISTS user_organisations (
                user_id    INTEGER NOT NULL,
                org_id     INTEGER NOT NULL REFERENCES organisations(id)
                           ON DELETE CASCADE,
                granted_at TEXT,
                granted_by INTEGER,
                PRIMARY KEY (user_id, org_id)
            );

            CREATE TABLE IF NOT EXISTS communities (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                created_by  INTEGER,
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS community_organisations (
                community_id INTEGER NOT NULL REFERENCES communities(id)
                             ON DELETE CASCADE,
                org_id       INTEGER NOT NULL REFERENCES organisations(id)
                             ON DELETE CASCADE,
                PRIMARY KEY (community_id, org_id)
            );

            CREATE TABLE IF NOT EXISTS user_communities (
                user_id      INTEGER NOT NULL,
                community_id INTEGER NOT NULL REFERENCES communities(id)
                             ON DELETE CASCADE,
                granted_at   TEXT,
                granted_by   INTEGER,
                PRIMARY KEY (user_id, community_id)
            );

            CREATE TABLE IF NOT EXISTS roadmaps (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id       TEXT,
                domain       TEXT,
                scope        TEXT NOT NULL DEFAULT 'domain',
                created_at   TEXT NOT NULL,
                roadmap_json TEXT NOT NULL
            );
            """)
            row = conn.execute(
                "SELECT MAX(version) FROM schema_version").fetchone()
            current = row[0]
            # Fresh DB, or an older DB that predates a version: record the
            # current schema version. The v1->v2 change is index-only (added
            # above with IF NOT EXISTS), so no data migration is required.
            if current is None or current < SCHEMA_VERSION:
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) "
                    "VALUES (?,?)", (SCHEMA_VERSION, _now()))

    # ------------------------------------------------------------------
    # Scan runs
    # ------------------------------------------------------------------
    def create_run(self, domains: list, trigger: str = "manual") -> str:
        run_id = uuid.uuid4().hex[:12]
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_runs (id, started_at, status, trigger, "
                "domains_total) VALUES (?,?,?,?,?)",
                (run_id, _now(), "running", trigger, len(domains)))
        return run_id

    def finish_run(self, run_id: str, status: str = "completed"):
        with self._connect() as conn:
            conn.execute(
                "UPDATE scan_runs SET finished_at=?, status=? WHERE id=?",
                (_now(), status, run_id))

    def bump_run_progress(self, run_id: str):
        with self._connect() as conn:
            conn.execute(
                "UPDATE scan_runs SET domains_done=domains_done+1 WHERE id=?",
                (run_id,))

    def list_runs(self, limit: int = 20) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Raw scans & assessments
    # ------------------------------------------------------------------
    def save_scan_result(self, run_id: str, scan: dict):
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO raw_scans (run_id, domain, scanned_at, "
                "checks_json) VALUES (?,?,?,?)",
                (run_id, scan["domain"], scan["scanned_at"],
                 json.dumps(scan["checks"])))

    def get_domain_scans(self, domain: str, limit: int = 10) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM raw_scans WHERE domain=? "
                "ORDER BY scanned_at DESC LIMIT ?", (domain, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["checks"] = json.loads(d.pop("checks_json"))
            out.append(d)
        return out

    def save_assessment(self, run_id: str, a: dict):
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO assessments (run_id, domain, assessed_at, "
                "guideline, score, rating, no_mail, controls_json, "
                "findings_json) VALUES (?,?,?,?,?,?,?,?,?)",
                (run_id, a["domain"], a["assessed_at"], a["guideline"],
                 a["score"], a["rating"], 1 if a.get("no_mail") else 0,
                 json.dumps(a["control_scores"]),
                 json.dumps(a["findings"])))

    def _parse_assessment_row(self, row) -> dict:
        d = dict(row)
        d["control_scores"] = json.loads(d.pop("controls_json"))
        d["findings"] = json.loads(d.pop("findings_json"))
        d["no_mail"] = bool(d["no_mail"])
        return d

    def get_guidelines_present(self) -> list[str]:
        """Distinct guideline ids that have stored assessments."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT guideline FROM assessments "
                "ORDER BY guideline").fetchall()
        return [r["guideline"] for r in rows]

    def get_latest_assessments(self, domains: Optional[list] = None,
                               guideline: Optional[str] = DEFAULT_GUIDELINE_ID
                               ) -> list:
        """Latest assessment per domain for one guideline profile.

        guideline=None returns the latest per (domain, guideline) across all
        profiles (used for exports); otherwise it is filtered to that profile.
        """
        if guideline is None:
            sql = ("SELECT a.* FROM assessments a JOIN ("
                   "  SELECT domain, guideline, MAX(assessed_at) AS ts "
                   "  FROM assessments GROUP BY domain, guideline) m "
                   "ON a.domain=m.domain AND a.guideline=m.guideline "
                   "AND a.assessed_at=m.ts")
            params: tuple = ()
        else:
            sql = ("SELECT a.* FROM assessments a JOIN ("
                   "  SELECT domain, MAX(assessed_at) AS ts FROM assessments "
                   "  WHERE guideline=? GROUP BY domain) m "
                   "ON a.domain=m.domain AND a.assessed_at=m.ts "
                   "WHERE a.guideline=?")
            params = (guideline, guideline)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = [self._parse_assessment_row(r) for r in rows]
        if domains is not None:
            allowed = {d.strip().lower() for d in domains}
            out = [a for a in out if a["domain"] in allowed]
        return out

    def get_domain_history(self, domain: str, limit: int = 50,
                           guideline: Optional[str] = DEFAULT_GUIDELINE_ID
                           ) -> list:
        sql = "SELECT * FROM assessments WHERE domain=?"
        params: list = [domain]
        if guideline is not None:
            sql += " AND guideline=?"
            params.append(guideline)
        sql += " ORDER BY assessed_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._parse_assessment_row(r) for r in rows]

    def get_summary_stats(self, domains: Optional[list] = None,
                          guideline: Optional[str] = DEFAULT_GUIDELINE_ID
                          ) -> dict:
        latest = self.get_latest_assessments(domains, guideline)
        ratings = {"not_implemented": 0, "medium": 0, "strong": 0,
                   "very_strong": 0}
        control_impl: dict = {}
        for a in latest:
            ratings[a["rating"]] = ratings.get(a["rating"], 0) + 1
            for control, score in a["control_scores"].items():
                if score is None:
                    continue
                c = control_impl.setdefault(
                    control, {"implemented": 0, "applicable": 0})
                c["applicable"] += 1
                if score > 0:
                    c["implemented"] += 1
        avg = round(sum(a["score"] for a in latest) / len(latest), 1) \
            if latest else 0.0
        return {"total_domains": len(latest), "ratings": ratings,
                "avg_score": avg, "controls": control_impl}

    def get_timeline(self, domains: Optional[list] = None,
                     guideline: Optional[str] = DEFAULT_GUIDELINE_ID,
                     period: str = "weekly") -> list[dict]:
        """Time-bucketed trend of assessments for a domain set + guideline.

        Each bucket aggregates *every* assessment in the period (mean score +
        rating counts across all scans), per the 'average across the period'
        semantics. Buckets are returned chronologically.
        """
        if period not in ("weekly", "monthly", "quarterly", "yearly"):
            period = "weekly"
        sql = "SELECT domain, assessed_at, score, rating FROM assessments"
        params: list = []
        if guideline is not None:
            sql += " WHERE guideline=?"
            params.append(guideline)
        sql += " ORDER BY assessed_at"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        allowed = {d.strip().lower() for d in domains} \
            if domains is not None else None
        buckets: dict = {}
        for r in rows:
            if allowed is not None and r["domain"] not in allowed:
                continue
            key, label, start = _period_bucket(r["assessed_at"], period)
            b = buckets.setdefault(key, {
                "period": key, "label": label, "start": start,
                "scores": [], "ratings": {}, "domains": set()})
            b["scores"].append(r["score"])
            b["domains"].add(r["domain"])
            b["ratings"][r["rating"]] = b["ratings"].get(r["rating"], 0) + 1

        out = []
        for key in sorted(buckets, key=lambda k: buckets[k]["start"]):
            b = buckets[key]
            out.append({
                "period": b["period"], "label": b["label"], "start": b["start"],
                "avg_score": round(sum(b["scores"]) / len(b["scores"]), 1)
                if b["scores"] else 0.0,
                "scans": len(b["scores"]), "domains": len(b["domains"]),
                "ratings": b["ratings"]})
        return out

    # ------------------------------------------------------------------
    # DKIM selectors
    # ------------------------------------------------------------------
    def get_dkim_selectors(self, domain: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT selector FROM dkim_selectors WHERE domain=? "
                "ORDER BY selector", (domain,)).fetchall()
        return [r["selector"] for r in rows]

    def record_dkim_selector(self, domain: str, selector: str,
                             source: str = "manual"):
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO dkim_selectors (domain, selector, source, "
                "added_at, last_seen_at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(domain, selector) DO UPDATE SET last_seen_at=?",
                (domain, selector.strip().lower(), source, _now(), _now(),
                 _now()))

    def delete_dkim_selector(self, domain: str, selector: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM dkim_selectors WHERE domain=? AND selector=?",
                (domain, selector.strip().lower()))
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Domain lists (auth store depends on this shape)
    # ------------------------------------------------------------------
    def save_domain_list(self, name: str, domains: list,
                         query: str = "") -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO domain_lists (name, query, created_at, "
                "domains_json) VALUES (?,?,?,?)",
                (name, query, _now(), json.dumps(domains)))
        return cur.lastrowid

    def get_domain_lists(self) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, name, query, created_at, domains_json "
                "FROM domain_lists ORDER BY created_at DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["domains"] = json.loads(d.pop("domains_json"))
            d["count"] = len(d["domains"])
            out.append(d)
        return out

    def get_domain_list_by_id(self, list_id: int) -> Optional[list]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT domains_json FROM domain_lists WHERE id=?",
                (list_id,)).fetchone()
        return json.loads(row["domains_json"]) if row else None

    def update_domain_list(self, list_id: int, name: str = None,
                           domains: list = None) -> bool:
        with self._connect() as conn:
            if name is not None:
                conn.execute("UPDATE domain_lists SET name=? WHERE id=?",
                             (name, list_id))
            if domains is not None:
                conn.execute(
                    "UPDATE domain_lists SET domains_json=? WHERE id=?",
                    (json.dumps(domains), list_id))
        return True

    def delete_domain_list(self, list_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM domain_lists WHERE id=?",
                               (list_id,))
        return cur.rowcount > 0

    def get_domain_list_full(self, list_id: int):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, name, query, created_at, domains_json "
                "FROM domain_lists WHERE id=?", (list_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["domains"] = json.loads(d.pop("domains_json"))
        d["count"] = len(d["domains"])
        return d

    def get_all_known_domains(self) -> list[str]:
        domains: set = set()
        with self._connect() as conn:
            for r in conn.execute("SELECT domains_json FROM domain_lists"):
                domains.update(json.loads(r["domains_json"]))
            for r in conn.execute("SELECT DISTINCT domain FROM assessments"):
                domains.add(r["domain"])
            for r in conn.execute(
                    "SELECT DISTINCT domain FROM domain_organisations"):
                domains.add(r["domain"])
        return sorted(domains)

    # ------------------------------------------------------------------
    # Organisations
    # ------------------------------------------------------------------
    def create_organisation(self, name: str, sector: str = "",
                            region: str = "", description: str = "",
                            country_code: str = "", country: str = "",
                            created_by: int = None, **_ignored) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO organisations (name, sector, description, "
                "country_code, country, region, created_by, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (name, sector, description, (country_code or "").upper(),
                 country, region, created_by, _now()))
        return cur.lastrowid

    def get_organisations(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT o.*, COUNT(do2.domain) AS domain_count "
                "FROM organisations o LEFT JOIN domain_organisations do2 "
                "ON do2.org_id=o.id GROUP BY o.id ORDER BY o.name").fetchall()
        return [dict(r) for r in rows]

    def get_organisation(self, org_id: int) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM organisations WHERE id=?",
                               (org_id,)).fetchone()
        return dict(row) if row else None

    def update_organisation(self, org_id: int, **fields) -> bool:
        allowed = {"name", "sector", "description", "country_code",
                   "country", "region"}
        sets, vals = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                vals.append(v.upper() if k == "country_code" and v else v)
        if not sets:
            return False
        vals.append(org_id)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE organisations SET {', '.join(sets)} WHERE id=?", vals)
        return cur.rowcount > 0

    def delete_organisation(self, org_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM organisations WHERE id=?",
                               (org_id,))
        return cur.rowcount > 0

    def set_org_domains(self, org_id: int, domains: list[str],
                        replace: bool = True, **_ignored):
        with self._connect() as conn:
            if replace:
                conn.execute(
                    "DELETE FROM domain_organisations WHERE org_id=?",
                    (org_id,))
            for d in domains:
                d = d.strip().lower().rstrip(".")
                if d:
                    conn.execute(
                        "INSERT OR IGNORE INTO domain_organisations "
                        "(domain, org_id) VALUES (?,?)", (d, org_id))

    def get_org_domains(self, org_id: int) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT domain FROM domain_organisations WHERE org_id=? "
                "ORDER BY domain", (org_id,)).fetchall()
        return [r["domain"] for r in rows]

    def get_domain_org(self, domain: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT o.* FROM organisations o "
                "JOIN domain_organisations do2 ON do2.org_id=o.id "
                "WHERE do2.domain=? LIMIT 1", (domain,)).fetchone()
        return dict(row) if row else None

    def set_user_orgs(self, user_id: int, org_ids: list[int],
                      replace: bool = True):
        with self._connect() as conn:
            if replace:
                conn.execute(
                    "DELETE FROM user_organisations WHERE user_id=?",
                    (user_id,))
            for oid in org_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO user_organisations "
                    "(user_id, org_id) VALUES (?,?)", (user_id, oid))

    def get_user_org_ids(self, user_id: int) -> list[int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT org_id FROM user_organisations WHERE user_id=?",
                (user_id,)).fetchall()
        return [r["org_id"] for r in rows]

    # ------------------------------------------------------------------
    # Communities
    # ------------------------------------------------------------------
    def create_community(self, name: str, description: str = "",
                         created_by: int = None, **_ignored) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO communities (name, description, created_by, "
                "created_at) VALUES (?,?,?,?)",
                (name, description, created_by, _now()))
        return cur.lastrowid

    def get_communities(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT c.*, COUNT(co.org_id) AS org_count "
                "FROM communities c LEFT JOIN community_organisations co "
                "ON co.community_id=c.id GROUP BY c.id ORDER BY c.name"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_community(self, community_id: int) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM communities WHERE id=?",
                               (community_id,)).fetchone()
        return dict(row) if row else None

    def update_community(self, community_id: int, **fields) -> bool:
        allowed = {"name", "description"}
        sets, vals = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                vals.append(v)
        if not sets:
            return False
        vals.append(community_id)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE communities SET {', '.join(sets)} WHERE id=?", vals)
        return cur.rowcount > 0

    def delete_community(self, community_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM communities WHERE id=?",
                               (community_id,))
        return cur.rowcount > 0

    def set_community_orgs(self, community_id: int, org_ids: list[int],
                           replace: bool = True, **_ignored):
        with self._connect() as conn:
            if replace:
                conn.execute(
                    "DELETE FROM community_organisations WHERE community_id=?",
                    (community_id,))
            for oid in org_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO community_organisations "
                    "(community_id, org_id) VALUES (?,?)",
                    (community_id, oid))

    def get_community_orgs(self, community_id: int) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT o.* FROM organisations o "
                "JOIN community_organisations co ON co.org_id=o.id "
                "WHERE co.community_id=? ORDER BY o.name",
                (community_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_community_domains(self, community_id: int) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT do2.domain FROM domain_organisations do2 "
                "JOIN community_organisations co ON co.org_id=do2.org_id "
                "WHERE co.community_id=? ORDER BY do2.domain",
                (community_id,)).fetchall()
        return [r["domain"] for r in rows]

    def get_user_communities(self, user_id: int) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT c.* FROM communities c "
                "JOIN user_communities uc ON uc.community_id=c.id "
                "WHERE uc.user_id=? ORDER BY c.name", (user_id,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Aggregates for group reports
    # ------------------------------------------------------------------
    def _org_latest_assessments(self, org_id: int,
                                guideline: str = DEFAULT_GUIDELINE_ID
                                ) -> list[dict]:
        domains = self.get_org_domains(org_id)
        return self.get_latest_assessments(domains, guideline) if domains else []

    def _build_group_aggregate(self, orgs: list[dict],
                               guideline: str = DEFAULT_GUIDELINE_ID) -> dict:
        out = {"guideline": guideline, "organisations": [], "totals": {
            "orgs": len(orgs), "domains": 0, "avg_score": 0.0, "ratings": {}}}
        scores = []
        for org in orgs:
            assessments = self._org_latest_assessments(org["id"], guideline)
            org_scores = [a["score"] for a in assessments]
            entry = {
                "id": org["id"], "name": org["name"],
                "country_code": org.get("country_code", ""),
                "country": org.get("country", ""),
                "region": org.get("region", ""),
                "domains": len(assessments),
                "avg_score": round(sum(org_scores) / len(org_scores), 1)
                if org_scores else None,
                "ratings": {},
            }
            for a in assessments:
                entry["ratings"][a["rating"]] = \
                    entry["ratings"].get(a["rating"], 0) + 1
                out["totals"]["ratings"][a["rating"]] = \
                    out["totals"]["ratings"].get(a["rating"], 0) + 1
            out["totals"]["domains"] += len(assessments)
            scores.extend(org_scores)
            out["organisations"].append(entry)
        if scores:
            out["totals"]["avg_score"] = round(sum(scores) / len(scores), 1)
        return out

    def get_community_aggregate(self, community_id: int,
                                guideline: str = DEFAULT_GUIDELINE_ID) -> dict:
        orgs = self.get_community_orgs(community_id)
        agg = self._build_group_aggregate(orgs, guideline)
        agg["community"] = self.get_community(community_id)
        return agg

    def get_countries(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT country_code, MAX(country) AS country, "
                "COUNT(*) AS org_count FROM organisations "
                "WHERE country_code != '' GROUP BY country_code "
                "ORDER BY country_code").fetchall()
        return [dict(r) for r in rows]

    def get_regions(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT region, COUNT(*) AS org_count FROM organisations "
                "WHERE region != '' GROUP BY region ORDER BY region"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_country_aggregate(self, country_code: str,
                              allowed_org_ids: Optional[set] = None,
                              guideline: str = DEFAULT_GUIDELINE_ID) -> dict:
        orgs = [o for o in self.get_organisations()
                if o.get("country_code", "").upper() == country_code.upper()]
        if allowed_org_ids is not None:
            orgs = [o for o in orgs if o["id"] in allowed_org_ids]
        agg = self._build_group_aggregate(orgs, guideline)
        agg["country_code"] = country_code.upper()
        return agg

    def get_region_aggregate(self, region: str,
                             allowed_org_ids: Optional[set] = None,
                             guideline: str = DEFAULT_GUIDELINE_ID) -> dict:
        orgs = [o for o in self.get_organisations()
                if o.get("region", "") == region]
        if allowed_org_ids is not None:
            orgs = [o for o in orgs if o["id"] in allowed_org_ids]
        agg = self._build_group_aggregate(orgs, guideline)
        agg["region"] = region
        return agg

    # ------------------------------------------------------------------
    # Roadmaps
    # ------------------------------------------------------------------
    def save_roadmap(self, roadmap: dict, domain: str = None,
                     scope: str = "domain", run_id: str = None) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO roadmaps (run_id, domain, scope, created_at, "
                "roadmap_json) VALUES (?,?,?,?,?)",
                (run_id, domain, scope, _now(), json.dumps(roadmap)))
        return cur.lastrowid

    def get_roadmaps(self, domain: str = None, limit: int = 20) -> list:
        with self._connect() as conn:
            if domain:
                rows = conn.execute(
                    "SELECT * FROM roadmaps WHERE domain=? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (domain, limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM roadmaps ORDER BY created_at DESC LIMIT ?",
                    (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["roadmap"] = json.loads(d.pop("roadmap_json"))
            out.append(d)
        return out
