# SEE-Monitor — Database Schema

SEE-Monitor uses a single **SQLite** database file (default
`data/see_monitor.db`, configurable via `db_path`). This document describes
every table, its columns, keys and relationships, and how to check the database
for consistency.

## Conventions

- **Engine:** SQLite. Every connection sets `PRAGMA journal_mode=WAL` and
  `PRAGMA foreign_keys=ON` (see `data/database.py::_connect`). WAL allows the
  scheduler to write while the dashboard reads.
- **Timestamps:** stored as ISO-8601 **text** in UTC (e.g.
  `2026-07-22T09:00:00+00:00`). There are no native DATE/DATETIME columns.
- **JSON columns:** several columns hold JSON-encoded text (suffix `_json`).
  They are parsed in the data-access layer, not by SQLite.
- **Booleans:** stored as INTEGER `0` / `1`.
- **Two schema owners, one file:**
  - `data/database.py` owns the scan/assessment/organisation/community tables.
  - `auth/store.py` owns the identity/RBAC tables (`users`,
    `user_domain_lists`, `audit_log`).
  Both modules open the **same** database file and create their tables with
  `CREATE TABLE IF NOT EXISTS`, so ordering is not significant.
- **Cross-module references are “soft”:** columns such as
  `user_organisations.user_id`, `organisations.created_by`,
  `communities.created_by` and `audit_log.user_id` point at `users(id)` but do
  **not** declare a SQL foreign key (the two modules are independent). These are
  validated by `scripts/db_check.py` instead of the engine.

## Schema version

`schema_version` is an append-only log; the **current** version is
`MAX(version)`. The code constant is `data/database.py::SCHEMA_VERSION`.

| Version | Change |
|---------|--------|
| 1 | Initial schema. |
| 2 | Multi-profile scoring. Added index `idx_assess_domain_guideline` on `assessments(guideline, domain, assessed_at)` for latest-per-(domain,guideline) lookups. **Index-only — no data migration.** |
| 3 | Sub-scores and evidence quality. Added `assessments.subscores_json`, `assessments.confidence`, `assessments.confidence_notes_json`. **Additive migration:** the three columns are appended with `ALTER TABLE … ADD COLUMN` when absent, each with a default, so existing rows remain valid and readable. No data is rewritten and no row is lost. |

On startup, if the stored version is missing or `< SCHEMA_VERSION`, a new
`schema_version` row is inserted (indexes are created idempotently with
`IF NOT EXISTS`).

Migrations are executed before the version row is written and are guarded by
`PRAGMA table_info`, so `Database()` is safe to call repeatedly and safe to
call against a database created by an older release. Downgrading is not
supported: an older binary reading a v3 database will simply ignore the extra
columns.

---

## Tables (data/database.py)

### `scan_runs`
One row per scan batch (CLI, scheduler, or web-triggered).

| Column | Type | Notes |
|--------|------|-------|
| `id` | TEXT **PK** | Run UUID. |
| `started_at` | TEXT NOT NULL | |
| `finished_at` | TEXT | NULL while running. |
| `status` | TEXT NOT NULL | `running` → `completed` (default `running`). |
| `trigger` | TEXT | `manual` / `cli` / `scheduled` / `reassess` … |
| `domains_total` | INTEGER | Progress denominator. |
| `domains_done` | INTEGER | Progress counter. |

### `raw_scans`
Full JSON of every control check, one row per (run, domain).

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER **PK** AUTOINCREMENT | |
| `run_id` | TEXT → `scan_runs(id)` | FK (no ON DELETE). |
| `domain` | TEXT NOT NULL | Indexed (`idx_raw_domain`). |
| `scanned_at` | TEXT NOT NULL | |
| `checks_json` | TEXT NOT NULL | `{control: {…check output…}}`. |

### `assessments`
One scored result per (run, domain, **guideline**). Multiple profiles produce
multiple rows for the same scan (see [Guideline profiles](#guideline-profiles)).

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER **PK** AUTOINCREMENT | |
| `run_id` | TEXT → `scan_runs(id)` | FK (no ON DELETE). |
| `domain` | TEXT NOT NULL | |
| `assessed_at` | TEXT NOT NULL | Basis for timeline bucketing. |
| `guideline` | TEXT NOT NULL | Profile id, e.g. `nist_800_177r1`, `bsi_tr03182`. |
| `score` | REAL NOT NULL | 0–100. |
| `rating` | TEXT NOT NULL | Must be a rating in that guideline's `rating_bands`. |
| `no_mail` | INTEGER NOT NULL | `0`/`1`; transport controls are n/a when `1`. |
| `controls_json` | TEXT NOT NULL | `{control: score|null}`. |
| `findings_json` | TEXT NOT NULL | `[{control, severity, message}]`. |
| `subscores_json` | TEXT NOT NULL DEFAULT `'{}'` | v3. `{impersonation, transport, resilience}` → 0–100 or `null`. Profile-independent. |
| `confidence` | TEXT NOT NULL DEFAULT `'high'` | v3. Evidence quality: `high` / `medium` / `low`. Validated by `db_check.py`. |
| `confidence_notes_json` | TEXT NOT NULL DEFAULT `'[]'` | v3. `["DKIM not confirmed…", …]` — why the confidence is not `high`. |

Indexes: `idx_assess_domain(domain, assessed_at)`,
`idx_assess_domain_guideline(guideline, domain, assessed_at)`.

> **`scheduled_scans.next_run_at` (0.6.1).** Written at creation and refreshed
> after every run from the live APScheduler job (falling back to
> `now + interval_hours` when the scheduler is not running). Before 0.6.1 it was
> written once and never updated, so the stored value drifted. APScheduler
> remains the authority for when a job actually fires; this column is a
> reporting convenience. `scripts/schedule_audit.py` derives "overdue" from
> `last_run_at + interval_hours`, not from this column.

### `dkim_selectors`
Known DKIM selectors per domain (wordlist is not stored; discovered/registered
selectors are).

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER **PK** | |
| `domain` | TEXT NOT NULL | `UNIQUE(domain, selector)`. |
| `selector` | TEXT NOT NULL | |
| `source` | TEXT | `manual` / passive source name. |
| `added_at` | TEXT NOT NULL | |
| `last_seen_at` | TEXT | |

### `domain_lists`
Named saved sets of domains (targets for scheduled scans).

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER **PK** | |
| `name` | TEXT NOT NULL | |
| `query` | TEXT | Optional source query. |
| `created_at` | TEXT NOT NULL | |
| `domains_json` | TEXT NOT NULL | JSON array of domains. |

### `scheduled_scans`
Recurring scan schedules.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER **PK** | |
| `name` | TEXT NOT NULL | |
| `domain_list_id` | INTEGER → `domain_lists(id)` | FK. |
| `interval_hours` | INTEGER NOT NULL | Default 168 (weekly). |
| `enabled` | INTEGER NOT NULL | Default 1. |
| `last_run_at` / `next_run_at` | TEXT | |

### `organisations`
Grouping of domains under an owning organisation, with geography.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER **PK** | |
| `name` | TEXT NOT NULL **UNIQUE** | |
| `sector` / `description` | TEXT | |
| `country_code` / `country` / `region` | TEXT | Used by country/region aggregates. |
| `created_by` | INTEGER | Soft → `users(id)`. |
| `created_at` | TEXT NOT NULL | |

### `domain_organisations`
Membership: which domains belong to which organisation.

| Column | Type | Notes |
|--------|------|-------|
| `domain` | TEXT NOT NULL | Composite **PK** `(domain, org_id)`. |
| `org_id` | INTEGER → `organisations(id)` **ON DELETE CASCADE** | |

### `user_organisations`
RBAC grant: which analyst may see which organisation.

| Column | Type | Notes |
|--------|------|-------|
| `user_id` | INTEGER | Composite **PK** `(user_id, org_id)`; soft → `users(id)`. |
| `org_id` | INTEGER → `organisations(id)` **ON DELETE CASCADE** | |
| `granted_at` / `granted_by` | TEXT / INTEGER | |

### `communities`
Named collections of organisations (e.g. a sector or federation).

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER **PK** | |
| `name` | TEXT NOT NULL **UNIQUE** | |
| `description` | TEXT | |
| `created_by` | INTEGER | Soft → `users(id)`. |
| `created_at` | TEXT NOT NULL | |

### `community_organisations`
Membership: organisations in a community.

| Column | Type | Notes |
|--------|------|-------|
| `community_id` | INTEGER → `communities(id)` **ON DELETE CASCADE** | Composite **PK**. |
| `org_id` | INTEGER → `organisations(id)` **ON DELETE CASCADE** | |

### `user_communities`
RBAC grant: which user may see which community.

| Column | Type | Notes |
|--------|------|-------|
| `user_id` | INTEGER | Composite **PK** `(user_id, community_id)`; soft → `users(id)`. |
| `community_id` | INTEGER → `communities(id)` **ON DELETE CASCADE** | |
| `granted_at` / `granted_by` | TEXT / INTEGER | |

### `roadmaps`
Cached generated improvement roadmaps (domain or group scope).

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER **PK** | |
| `run_id` | TEXT | Soft → `scan_runs(id)` (nullable, no FK). |
| `domain` | TEXT | NULL for group roadmaps. |
| `scope` | TEXT NOT NULL | `domain` / `org` / `community` / … |
| `created_at` | TEXT NOT NULL | |
| `roadmap_json` | TEXT NOT NULL | Serialized roadmap. |

---

## Tables (auth/store.py)

### `users`
| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER **PK** | |
| `username` | TEXT **UNIQUE** NOT NULL COLLATE NOCASE | |
| `email` | TEXT **UNIQUE** NOT NULL COLLATE NOCASE | |
| `password_hash` | TEXT NOT NULL | |
| `role` | TEXT NOT NULL | `admin` / `analyst` (default `analyst`). |
| `full_name` | TEXT | |
| `is_active` | INTEGER NOT NULL | Default 1. |
| `created_at` | TEXT NOT NULL | |
| `last_login` | TEXT | |
| `failed_logins` | INTEGER | Lockout counter. |
| `locked_until` | TEXT | |

### `user_domain_lists`
RBAC grant of a saved domain list to a user (declares real FKs, unlike the
other `user_*` tables).

| Column | Type | Notes |
|--------|------|-------|
| `user_id` | INTEGER → `users(id)` **ON DELETE CASCADE** | Composite **PK**. |
| `domain_list_id` | INTEGER → `domain_lists(id)` **ON DELETE CASCADE** | |
| `granted_at` | TEXT NOT NULL | |
| `granted_by` | INTEGER → `users(id)` | |

### `audit_log`
Append-only security/audit trail.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER **PK** | |
| `user_id` | INTEGER | Soft → `users(id)` (nullable). |
| `username` | TEXT NOT NULL | Denormalised for retention after user deletion. |
| `action` | TEXT NOT NULL | |
| `resource` / `ip_address` / `user_agent` / `detail` | TEXT | |
| `timestamp` | TEXT NOT NULL | |

---

## Relationships (overview)

```
users ──< user_organisations >── organisations ──< domain_organisations (domain)
  │                                   │
  ├──< user_communities >── communities ──< community_organisations >──┘
  └──< user_domain_lists >── domain_lists ──< scheduled_scans

scan_runs ──< raw_scans        (run_id, FK)
scan_runs ──< assessments      (run_id, FK; also keyed by domain + guideline)
scan_runs ──· roadmaps         (run_id, soft)

organisations.created_by, communities.created_by,
user_*.user_id, audit_log.user_id ──· users.id   (soft, validated by db_check)
```

`>──` = declared SQL foreign key · `·──` = soft reference (checked by tooling).

## JSON column contents

| Column | Shape |
|--------|-------|
| `raw_scans.checks_json` | `{ "spf": {...}, "dkim": {...}, … , "client_tls": {...}, "dns_hygiene": {...}, "reputation": {...}, "subdomains": {...} }` — raw scanner output per control. **Never contains raw certificate bytes:** the STARTTLS probe's `_chain_der` and `starttls._chains` are consumed in-memory by the certificate and DANE analysis and stripped by the orchestrator before persistence. |
| `assessments.controls_json` | `{ "spf": 100, "dane": null, … }` — per-control score or `null` (n/a). |
| `assessments.findings_json` | `[ { "control", "severity", "message" }, … ]`. |
| `assessments.subscores_json` | `{ "impersonation": 82.5, "transport": 40.0, "resilience": null }` — orthogonal views over the same control scores. `null` when no contributing control was applicable. |
| `assessments.confidence_notes_json` | `[ "DKIM not confirmed: no selector found and none registered", … ]`. |
| `domain_lists.domains_json` | `[ "example.com", … ]`. |
| `roadmaps.roadmap_json` | Roadmap structure from `roadmap/generator.py`. |

## Guideline profiles

`assessments.guideline` is a profile id that must correspond to a
`guidelines/<id>.json` file (`nist_800_177r1`, `bsi_tr03182`, `acn_email`,
`ccn_cert_bp02`). A single scan yields one `assessments` row per installed
profile. `assessments.rating` must be one of the `rating_bands` ratings defined
in that guideline; `scripts/db_check.py` flags rows that reference an
uninstalled profile or an out-of-band rating.

## Consistency checking

Run the read-only auditor (never writes; safe on a live DB):

```bash
python scripts/db_check.py --config config/config.yaml       # or --db <path>
python scripts/db_check.py --db data/see_monitor.db --json    # machine output
python scripts/db_check.py --db data/see_monitor.db --strict  # warnings fail too
```

It runs `PRAGMA integrity_check` and `PRAGMA foreign_key_check`, verifies the
schema version, detects orphaned rows for both declared and soft references,
validates every `_json` column, and checks assessment value domains (score
range, boolean `no_mail`, installed guideline, in-band rating). Exit codes:
`0` = no errors, `1` = at least one error (or any issue with `--strict`),
`2` = the audit could not run.
