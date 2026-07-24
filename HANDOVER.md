# SEE-Monitor — Handover

**Version:** 0.5.1 · **Status:** functional, all tests passing (23) · **Standards:** NIST SP 800-177r1 (default) + BSI TR-03182, ACN, CCN-CERT BP/02 profiles

> Final handover for this session. Recent additions are summarised in
> `CHANGELOG.md` (0.3.0 profiles → 0.4.0 status dashboards + trends → 0.5.0 PDF
> export → 0.5.1 DB consistency checker + schema doc).

This document lets a new session (or engineer) resume work without re-deriving
context. It records what exists, the invariants that must hold, deployment
specifics, known caveats, and the outstanding TODOs.

---

## 1. What this is

A multi-user platform that scans DNS domains, identifies which email-security
controls are implemented, scores each domain against NIST SP 800-177r1, and
produces prioritised improvement roadmaps for domains, organisations, and
communities. Derived from the **pqc-monitor** codebase (multi-user model, RBAC,
dashboards, roadmap engine, country tagging) but with an email-security scope
and a fresh database. It is a new tool, not a fork in place.

Controls scored: **SPF, DKIM, DMARC, STARTTLS, CLIENT-TLS, DNSSEC, DANE,
MTA-STS, TLS-RPT, BIMI**. NIST ratings: `not_implemented → medium → strong →
very_strong`. National profiles rate `not_implemented → partial → compliant`,
where `compliant` requires all of the profile's `required_signals` (independent
of the numeric score).

**Multi-profile:** every scan is assessed against all installed
`guidelines/*.json` profiles and one assessment row is stored per profile. The
DB query layer and web API are guideline-aware (`?guideline=<id>`); the CLI
shows all profiles (`--profile` to limit).

---

## 2. Where things live

- **Working source (ephemeral):** `/home/claude/see/see-monitor` — resets
  between sessions. Do not rely on it persisting.
- **Deliverable (persistent):** `see-monitor-0.5.1.zip` in the outputs area.
  **Start a new session by extracting this zip.**
- **Lineage reference:** the original pqc-monitor tree was at
  `/home/claude/pqc/pqc-monitor-1.9.1` (also ephemeral).

Run tests: `python3 -m pytest tests/test_smoke.py -q` (23 passing).
DB audit:  `python3 scripts/db_check.py --db data/see_monitor.db` (read-only).
Compile check: `python3 -m py_compile $(find . -name "*.py" -not -path "*__pycache__*")`.

---

## 3. Architecture

```
see_monitor.py          CLI: scan / serve / init-db / scheduler-daemon
app_factory.py          Flask factory (RBAC, security headers, blueprints)
app_routes.py           /app/* dashboard REST API (role-scoped, guideline-aware);
                        +/api/timeline, +/api/guidelines(bands), +/api/report/{pdf,trend.pdf}
dashboard/app.py        DASHBOARD_HTML SPA: profile selector, status dashboards
                        (segmented bars), Trends (inline SVG timeline chart)
scanner/
  dns_client.py         resolver wrapper; timeout-tolerant query(); ad_flag() DNSSEC
  mx_resolver.py        strict MX normalisation (bare FQDN; null-MX aware)
  spf_check.py          record, all-qualifier, lookup counting (RFC 7208 limit)
  dkim_check.py         registered + passive + wordlist selectors; key sizing
  dmarc_check.py        policy/pct/sp/rua/alignment
  policy_checks.py      mta_sts, tlsrpt, dnssec (+_dmarc AD), dane, bimi
  client_tls_check.py   CCN submission/retrieval TLS via RFC 6186 SRV
  starttls_probe.py     active SMTP EHLO→STARTTLS→handshake probe
  shodan_client.py      passive STARTTLS evidence (1st)
  censys_client.py      passive STARTTLS evidence (alt)
  smtp_tls_check.py     per-MX STARTTLS: shodan→censys→active fallback
  dnsdumpster_client.py passive DKIM selector discovery (X-API-Key)
  securitytrails_client.py passive DNS intel: MX/TXT + selector discovery (APIKEY)
  orchestrator.py       runs all checks per domain; builds scan["services"]
  assessor.py           per-control scores + weighted rating; multi-profile
                        (guideline_id), required_signals gating, assess_all_profiles
data/
  database.py           SQLite schema v2 + full data-access API; get_timeline()
docs/DATABASE.md        authoritative schema reference (KEEP CURRENT on changes)
  geo_inference.py, tld_geo.csv   country tagging (reused)
roadmap/generator.py    per-domain + group roadmaps
reports/
  report_generator.py   CSV/JSON export
  pdf_report.py         reportlab scope + trend PDF reports (profile-aware)
guidelines/*.json       scoring profiles: nist_800_177r1 (default) +
                        bsi_tr03182, acn_email, ccn_cert_bp02
auth/ admin/ scheduler/ reused from pqc-monitor, rewired to the new DB API
```

Ops: `install.sh`, `scripts/{deploy,sync-tree,wait-for-db,fix-permissions}.sh`,
`scripts/reassess_all.py`, `scripts/db_check.py` (read-only consistency audit),
`systemd/{web,scheduler,target,nginx,env}`,
`.gitattributes`, `config/config.yaml.example`, `tests/test_smoke.py`.

---

## 4. Invariants — do not break these

1. **Passive sources never feed scoring.** Shodan, Censys, DNSDumpster and
   SecurityTrails produce *candidates and intel only*. Every DKIM selector and
   MX is re-confirmed against authoritative DNS before it can affect a score.
2. **No-mail domains.** If a domain has no MX or a null MX (RFC 7505), transport
   controls (starttls, dane, mta_sts, tlsrpt) are scored `None` (n/a) — never as
   failures. `assessment.no_mail` is set.
3. **MX normalisation is strict.** MX values become bare validated FQDNs;
   priority is stripped; MX hostnames must never leak into the `domain` column.
4. **DB writes are complete.** `assessments` persists every computed column;
   `PRAGMA foreign_keys=ON` + WAL on every connection.
5. **RBAC scoping.** admin = everything; community_manager = their communities'
   orgs; analyst = assigned domains. In `app_routes.py`, `_allowed_domains`
   returns `None` for admins (no filter) else a set.
6. **Instance state is never overwritten.** `install.sh` / `fix-permissions.sh`
   never clobber the env secrets, `config.yaml`, the DB, or the venv, and never
   re-mode `*.db*`.
7. **Scoring is adjustable & multi-profile.** Weights, rating bands and the
   very_strong/required_signals gating live in `guidelines/*.json`. `config.yaml`
   `scoring:` overrides apply to the **default** guideline only (per-profile
   JSON weights are never clobbered). After changing them, run
   `scripts/reassess_all.py` (re-scores every profile without re-querying DNS).
8. **Passive sources still never feed scoring** (unchanged). CLIENT-TLS and the
   `_dmarc` AD check are active/authoritative like the rest.
9. **Profile conflicts are intentional.** ACN requires DMARC `ruf`; BSI forbids
   it (GDPR). Never "reconcile" them into one rule — they are per-profile.
10. **`scripts/db_check.py` is read-only** (opens the DB `mode=ro`); it must
   never mutate data. When the schema changes, update BOTH `SCHEMA_VERSION`
   (+ migration) AND `docs/DATABASE.md`, and extend `db_check.py` if new
   references/invariants are introduced.

---

## 5. Configuration & external services

`config.yaml` keys: `db_path`, `secret_key`, `https_enabled`,
`scanning.{timeout,active_smtp,dkim_wordlist,nameservers}`,
`shodan.api_key`, `censys.{api_id,api_secret}`,
`dnsdumpster.api_key`, `securitytrails.api_key`, `scoring.{weights,rating_bands,
very_strong_requirements}`.

**Important gap:** the orchestrator reads passive-source API keys from
`config.yaml` (`cfg.get("shodan")…`), **not** from the systemd env vars
(`SHODAN_API_KEY`, `SECURITYTRAILS_API_KEY`, …). Those env lines are currently
placeholders. Either wire env→config in `load_config()` / `create_app`, or keep
keys in `config.yaml` and document that. Decide this early next session.

CLI output levels: default = summary block + "Sources" line; `-v` = debug
detail + per-service diagnostics (works before *or* after the subcommand);
`--quiet` = one line/domain; `--json` = machine-readable.

---

## 6. Deployment specifics

- Runs under Gunicorn behind nginx (TLS termination). systemd: `see-monitor-web`,
  `see-monitor-scheduler`, grouped by `see-monitor.target`.
- **Scheduler ExecStartPre** runs `wait-for-db.sh` via `/bin/bash` so it does not
  need the execute bit (fixed a `203/EXEC` failure).
- **Windows→Git→Linux workflow:** Git from Windows drops the Unix execute bit
  and can introduce CRLF. Mitigations shipped: `.gitattributes` (LF), and
  `scripts/fix-permissions.sh` (idempotent, non-destructive) called automatically
  by `install.sh` and `deploy.sh`. One-time in the repo:
  `git update-index --chmod=+x install.sh scripts/*.sh scripts/reassess_all.py see_monitor.py`.
- **install.sh** is a first-run installer: instance state written only if absent;
  code replaced only with `--upgrade` (backed up); units backed up before
  replacement; `--dry-run` supported.

### Co-hosting with PQC-Monitor (same host)
- **Port:** default `SEE_BIND=127.0.0.1:5000` collides with PQC. Set a different
  port (e.g. 5001) via `install.sh --bind` and update nginx `proxy_pass`.
- **Secret:** use a distinct `SEE_SECRET_KEY` (never reuse PQC's).
- **Cookie (OUTSTANDING):** both apps use Flask's default `session` cookie name.
  Cookies are host-scoped, not port-scoped, so on a shared hostname you get
  session thrashing. **TODO:** set `SESSION_COOKIE_NAME="see_session"` in
  `app_factory.py`.

---

## 7. Known caveats

- **Sandbox DNS only:** large apex TXT responses time out to external resolvers
  in the build sandbox, so test scans here can show SPF=0. On a real server it
  resolves correctly (e.g. `bde.es` scored 38, not 8).
- **API schemas unverified:** the DNSDumpster and SecurityTrails response shapes
  were not confirmed against the live 2026 APIs. Parsers are defensive (`.get()`
  chains + recursive/`_extract_selectors`); auth is `X-API-Key` (DNSDumpster) and
  `APIKEY` (SecurityTrails). 401/429 surface in `-v`. **Verify before relying on
  them** — a quick web search of each API's current docs is the first step.
- **Lineage comments:** `auth/`, `admin/`, `data/geo_inference.py` retain some
  "PQC-Monitor" attribution comments (intentional).

---

## 8. Outstanding TODOs (rough priority)

1. `SESSION_COOKIE_NAME` in `app_factory.py` (clean PQC co-hosting).
2. Decide/​implement env→config wiring for passive-source API keys (§5 gap).
3. Verify DNSDumpster + SecurityTrails (+ Censys) live API request/response
   schemas; adjust clients if needed.
4. ~~Group PDF report export~~ **DONE** (0.5.0, `reports/pdf_report.py` +
   `/app/api/report/{pdf,trend.pdf}`). Optional: an HTML export variant.
5. Admin UI screens for DKIM selector registration and scheduled scans (backend
   endpoints + scheduler already exist).
6. Optional dedicated passive-DNS provider (Farsight/SecurityTrails tier) purely
   for broader selector coverage at scale.
7. ~~`CHANGELOG.md`~~ **DONE** — created and maintained (0.1.0–0.5.1).
9. ~~DB schema doc + consistency checker~~ **DONE** (0.5.1, `docs/DATABASE.md`
   + `scripts/db_check.py`). Wire `db_check` into CI / a scheduler health check
   if desired.
8. **Future feature, documented not coded:** PGP/S-MIME end-to-end detection via
   WKD/keyservers (see README "Future features").

---

## 9. Version & changelog convention

- Version is single-sourced from the `VERSION` file (read by `version.py`).
  Now at **0.5.1**. Trajectory: 0.2.0 (passive sources, CLI) → 0.3.0 (national
  profiles) → 0.4.0 (status dashboards + trends) → 0.5.0 (PDF export) →
  0.5.1 (DB consistency checker + schema doc). Full detail in `CHANGELOG.md`.
- **Convention going forward:** every change ships with a Conventional-Commits
  changelog. The 0.1.0→0.2.0 commits are listed in the session notes; seed
  `CHANGELOG.md` from them when created. Commit trailer used:
  `Assisted-by: Claude (Anthropic)` (drop if undesired).

---

## 10. First steps in the next session

1. Extract `see-monitor-0.5.1.zip`; run `pytest tests/test_smoke.py -q`
   (expect 23 passing) and `python3 scripts/db_check.py --db <db>` to confirm a
   clean base.
2. Pick from §8. Cheapest high-value items remain `SESSION_COOKIE_NAME` (§6)
   and the passive-key env/config gap (§5).
3. Before wiring real DNSDumpster/SecurityTrails keys, verify their current API
   docs (§7).
4. Keep the §4 invariants intact (now 10 items); update `docs/DATABASE.md` and
   `CHANGELOG.md` with every change; commit with `Assisted-by: Claude (Anthropic)`.
