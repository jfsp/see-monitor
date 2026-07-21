# SEE-Monitor — Handover

**Version:** 0.2.0 · **Status:** functional, all tests passing · **Standard:** NIST SP 800-177r1

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

Controls scored: **SPF, DKIM, DMARC, STARTTLS, DNSSEC, DANE, MTA-STS, TLS-RPT,
BIMI**. Ratings: `not_implemented → medium → strong → very_strong` (the last
requires all core controls enforcing).

---

## 2. Where things live

- **Working source (ephemeral):** `/home/claude/see-monitor` — resets between
  sessions. Do not rely on it persisting.
- **Deliverable (persistent):** `see-monitor-0.2.0.zip` in the outputs area.
  **Start a new session by extracting this zip.**
- **Lineage reference:** the original pqc-monitor tree was at
  `/home/claude/pqc/pqc-monitor-1.9.1` (also ephemeral).

Run tests: `python3 -m pytest tests/test_smoke.py -q` (11 passing).
Compile check: `python3 -m py_compile $(find . -name "*.py" -not -path "*__pycache__*")`.

---

## 3. Architecture

```
see_monitor.py          CLI: scan / serve / init-db / scheduler-daemon
app_factory.py          Flask factory (RBAC, security headers, blueprints)
app_routes.py           /app/* dashboard REST API (role-scoped)
dashboard/app.py        DASHBOARD_HTML single-page UI (rendered via Jinja)
scanner/
  dns_client.py         resolver wrapper; timeout-tolerant query(); ad_flag() DNSSEC
  mx_resolver.py        strict MX normalisation (bare FQDN; null-MX aware)
  spf_check.py          record, all-qualifier, lookup counting (RFC 7208 limit)
  dkim_check.py         registered + passive + wordlist selectors; key sizing
  dmarc_check.py        policy/pct/sp/rua/alignment
  policy_checks.py      mta_sts, tlsrpt, dnssec, dane, bimi
  starttls_probe.py     active SMTP EHLO→STARTTLS→handshake probe
  shodan_client.py      passive STARTTLS evidence (1st)
  censys_client.py      passive STARTTLS evidence (alt)
  smtp_tls_check.py     per-MX STARTTLS: shodan→censys→active fallback
  dnsdumpster_client.py passive DKIM selector discovery (X-API-Key)
  securitytrails_client.py passive DNS intel: MX/TXT + selector discovery (APIKEY)
  orchestrator.py       runs all checks per domain; builds scan["services"]
  assessor.py           per-control scores + weighted rating (adjustable)
data/
  database.py           SQLite schema v1 + full data-access API
  geo_inference.py, tld_geo.csv   country tagging (reused)
roadmap/generator.py    per-domain + group roadmaps
reports/report_generator.py  CSV/JSON export
guidelines/nist_800_177r1.json  weights, rating bands, very_strong requirements
auth/ admin/ scheduler/ reused from pqc-monitor, rewired to the new DB API
```

Ops: `install.sh`, `scripts/{deploy,sync-tree,wait-for-db,fix-permissions}.sh`,
`scripts/reassess_all.py`, `systemd/{web,scheduler,target,nginx,env}`,
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
7. **Scoring is adjustable.** Weights, rating bands and the very_strong
   enforcement requirements live in `guidelines/nist_800_177r1.json` and can be
   overridden under `scoring:` in `config.yaml`. After changing them, run
   `scripts/reassess_all.py` (re-scores stored scans without re-querying DNS).

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
4. Group **PDF/HTML** report export (CSV/JSON already exist in
   `reports/report_generator.py`).
5. Admin UI screens for DKIM selector registration and scheduled scans (backend
   endpoints + scheduler already exist).
6. Optional dedicated passive-DNS provider (Farsight/SecurityTrails tier) purely
   for broader selector coverage at scale.
7. `CHANGELOG.md` (Keep a Changelog) — not yet created; see §9 for the 0.2.0
   entries to seed it.
8. **Future feature, documented not coded:** PGP/S-MIME end-to-end detection via
   WKD/keyservers (see README "Future features").

---

## 9. Version & changelog convention

- Version is single-sourced from the `VERSION` file (read by `version.py`).
  This session bumped it to **0.2.0** (three `feat:` additions since 0.1.0:
  DNSDumpster, SecurityTrails, richer CLI).
- **Convention going forward:** every change ships with a Conventional-Commits
  changelog. The 0.1.0→0.2.0 commits are listed in the session notes; seed
  `CHANGELOG.md` from them when created. Commit trailer used:
  `Assisted-by: Claude (Anthropic)` (drop if undesired).

---

## 10. First steps in the next session

1. Extract `see-monitor-0.2.0.zip`; run the test suite to confirm a clean base.
2. Pick from §8. The two cheapest high-value items are `SESSION_COOKIE_NAME`
   (§6) and resolving the passive-key env/config gap (§5).
3. Before wiring real DNSDumpster/SecurityTrails keys, verify their current API
   docs (§7).
4. Keep the §4 invariants intact; provide a commit changelog with the change.
