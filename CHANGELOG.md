# Changelog

All notable changes to SEE-Monitor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
Semantic Versioning. Commit trailer used: `Assisted-by: Claude (Anthropic)`.

## [0.8.2] — 2026-08-06

### Fixed
- **ssl-tools `/refresh` now works (CSRF POST).** The refresh route is a Rails
  POST guarded by CSRF — a plain GET 404s (which is why stale reports were never
  refreshed). The client now fetches the page for its `csrf-token` meta + session
  cookie and POSTs `/mailservers/<domain>/refresh` with `X-CSRF-Token`, then
  polls for the fresh report. `refresh_wait` default raised to 25s (cap 60s) so
  the ~14s upstream re-test can complete.
- **Egress-25 messaging is now outcome-aware.** Instead of always advising to
  "enable a remote-active source", the STARTTLS issue and the CLI banner now
  report what actually happened: if the port-25 block was harmless (all inbound
  verdicts resolved from other sources) it says so and names them; only when
  inbound host(s) remain `unknown` does it advise enabling/fixing a source. The
  once-per-process WARNING lists all remote sources, not just MXToolbox.

### Changed
- **Startup "External sources" line lists enabled remote sources** (MXToolbox,
  ssl-tools, internet.nl) alongside SecurityTrails/DNSDumpster/Shodan/Censys.
- `scan --json` adds `egress25_unresolved_domains`.

## [0.8.1] — 2026-08-06

### Changed
- **Closed submission/implicit ports (587/465) scored n/a, not unknown.** A TCP
  RST (connection refused / errno 111) means the host is reachable but offers no
  service on that port — not a security failure — so it is now excluded from the
  STARTTLS tally (`na_count`, `by_port[*].na`) instead of counting as `unknown`
  and dragging the score/confidence. A *timeout* (filtered/egress-blocked) still
  stays `unknown`. Inbound port 25 is unaffected. `scan -v` shows these as `n/a`.

### Fixed
- **ssl-tools JSON parser corrected to the real schema** (verified live). The
  `?format=json` payload is far thinner than the HTML report: it carries no
  `starttls` flag or TLS version, only `hosts[]` (with a `certificate`
  fingerprint) and cert `chains`. STARTTLS support is now derived from
  certificate presence (a presented cert proves a successful STARTTLS
  handshake); absence stays `unknown`, never a false `no_tls`. Previously the
  parser looked for a non-existent `starttls` field, always returned `unknown`,
  and ssl-tools never contributed a verdict.
- **ssl-tools report timestamp parsing.** `"YYYY-MM-DD HH:MM:SS UTC"` was not
  recognised (age came back `None`), so the freshness check never fired and the
  client always served the stale cached report. Timestamps now parse and the
  `freshness_days` refresh triggers as intended; `state` (`done`) is also
  factored into freshness, and the post-refresh poll waits for a fresh report.
- **Egress-25 guidance now lists all remote-active sources** (ssl-tools and
  internet.nl free, MXToolbox paid) in the STARTTLS issue text and the CLI
  end-of-run banner, instead of naming MXToolbox only.

### Notes
- `scripts/check_apis.py ssltools --domain <d> -v` now prints the derived
  STARTTLS per host (e.g. `smtp.bde.es=ok`) alongside the raw keys.
- The check runs with `--domain <d>`; a bare positional (e.g. `ssltools bde.es`)
  is parsed as a service name, not a domain.

## [0.8.0] — 2026-08-06

### Added
- **Two egress-independent remote-active STARTTLS sources.** When this host
  cannot open port 25 outbound (permanent on GCP, common on AWS/Azure), the
  local probe alone cannot confirm STARTTLS. Two sources that test from their
  own networks now fill that gap and feed the reconciler:
  - **ssl-tools.net** (`scanner/ssltools_client.py`) — free, no account,
    **per-MX**, synchronous. Reads `/mailservers/<domain>?format=json`, and
    because ssl-tools caches reports (a domain's report can be years old),
    auto-triggers `/refresh` when the report is older than
    `ssltools.freshness_days` (default 7) and re-polls. Stale data that cannot
    be refreshed is flagged and **not used for scoring**. Disabled by default.
  - **internet.nl** (`scanner/internetnl_client.py`) — free, government-backed
    (Dutch Internet Standards Platform), **domain-level**, batch API v2. Because
    the API is asynchronous (submit → poll → results, minutes per batch), it is
    consumed as a **scheduled batch that caches per-domain verdicts**
    (`scheduler/internetnl_batch.py`, weekly), which the scanner reads at scan
    time within `internetnl.cache_ttl_days` (default 7). Requires an approved
    account (non-profit / NIS2 high-criticality organisations qualify).
    Trigger a refresh manually with `see_monitor.py internetnl-refresh`.
- **N-source reconciliation.** The STARTTLS reconciler was generalised from a
  fixed local/passive/MXToolbox set to any number of remote-active sources.
  Precedence unchanged in spirit: a positive STARTTLS from **any active source**
  (local probe, MXToolbox, ssl-tools, internet.nl) wins; the local probe still
  takes priority among active sources; passive (Shodan/Censys) fills gaps;
  conflicts are flagged.
- **`internetnl_results` cache table (schema v5)** with `upsert`/`get`
  accessors; a weekly scheduler job; and the `internetnl-refresh` CLI command.
- **Connectivity checks** for both sources in `scripts/check_apis.py`
  (`ssltools`, `internetnl`). The `ssltools` check dumps the parsed JSON shape
  and raw keys so the (undocumented) field mapping can be confirmed live.

### Changed
- **`scan -v` Sources panel** now reports ssl-tools and internet.nl usage
  alongside Shodan/Censys/MXToolbox/active-SMTP.

### Notes / caveats
- **ssl-tools JSON schema is unverified upstream** (their robots policy blocks
  automated fetching from the build sandbox; robots.txt targets crawlers per
  RFC 9309, not single documented API lookups). The parser is tolerant of
  several key-name shapes and fails safe to `unknown`. Confirm the mapping with
  `scripts/check_apis.py ssltools -v <domain>` and tighten if needed.
- **internet.nl results envelope** (the exact `results.tests` shape) was not
  verifiable without an account; the mapper is defensive. Confirm once the
  account is approved.
- BinaryEdge was **shut down (Mar 2025)** and Onyphe requires a **corporate
  account**, so neither is a viable Tier-2 passive source. MXToolbox's free
  tier has **0 network lookups/day**, so its SMTP test needs a paid plan.

### Migration
- Schema auto-migrates to v5 (additive table, no data change). Both new sources
  are off until configured. After enabling, run `scripts/reassess_all.py` /
  `scan --rescan-all` as usual to reflect new evidence.

## [0.7.0] — 2026-08-06

### Added
- **Active SMTP transport TLS, reconciled across sources.** STARTTLS is no
  longer decided by Shodan/Censys with the live probe as a rarely-reached
  fallback. The `starttls` control now consults every configured source and
  reconciles them (`scanning.smtp_tls_strategy`, default `reconcile`): a
  positive STARTTLS observation from **any active source** wins; a reachable
  local probe seeing STARTTLS absent/refused yields `no_tls`; passive banner
  data fills gaps at lower confidence; otherwise `unknown` (never a failure).
  When sources conflict the active result is used and an informational issue
  records the disagreement (stale-passive-intel signal). Other strategies:
  `active_first`, `passive_first` (legacy), `active_only`, `passive_only`.
- **587/465 folded into the STARTTLS score, probed on the MX hosts.** SMTP
  submission STARTTLS (587) and implicit TLS (465) are now probed on each MX
  host and blended into the STARTTLS control's score (`by_port` breakdown
  retained). SRV-only discovery found these almost nowhere; probing the MX
  hosts is what makes the fold meaningful. `all_starttls` (the "all MX offer
  STARTTLS" requirement) is still computed on port 25 only, so the requirement
  stays aligned with NIST SP 800-177r1 §5.1 while the numeric score widens.
- **MXToolbox as a remote, egress-independent active source.**
  `scanner/mxtoolbox_client.py`. MXToolbox runs its SMTP diagnostic from its
  own network, so it confirms a target's port-25 TLS even when this host cannot
  open port 25 outbound. Key-gated (`mxtoolbox.api_key`); `mode: fallback`
  (default — query only MX hosts the local probe could not determine),
  `always`, or `off`. The SMTP lookup is a paid *network* lookup, so `fallback`
  conserves quota. `scripts/check_apis.py` gains an `mxtoolbox` check (uses the
  quota-free `/Usage` endpoint; warns when network quota is 0).
- **Tier-1 intent reconciliation.** After DANE and MTA-STS are evaluated, the
  scan cross-checks them against the STARTTLS verdict: if DANE TLSA is usable or
  MTA-STS is `mode=enforce` but STARTTLS is not confirmed on an inbound host,
  an `intent_mismatch` finding is raised — declared policy and observed
  transport disagree. No new connections are made.
- **Egress-25 detection and alerting.** If active probing is enabled but every
  local port-25 connection fails at the transport layer, the scan sets
  `egress25_blocked`, logs a single **WARNING** per process (visible in normal
  logs without `-v`), and the CLI prints a prominent end-of-run banner naming
  the affected domains (also surfaced in `--json` as
  `egress25_blocked_domains`). This is the exact cause of "active SMTP N/N MX →
  unknown" on port-25-filtered hosts (e.g. GCP, where the block is permanent
  and enforced above the VPC firewall).
- **Configurable HELO/EHLO name** (`scanning.helo_name`, default `escbmail.eu`),
  threaded into the active probe on ports 25 and 587 (previously hardcoded to
  `see-monitor.invalid` and, in fact, dropped before reaching the probe).
- **Active-probe logging.** The probe now logs connect / EHLO / STARTTLS /
  handshake / transport-failure at INFO, so `scan -v` shows the live probe
  (previously only Shodan/Censys diagnostics were visible under `-v`).

### Changed
- **`client_tls` is now IMAP/POP retrieval only.** SMTP submission (587/465)
  moved into the STARTTLS transport control (above). `client_tls` keeps its
  IMAPS/POP3S scope and its CCN-CERT BP/02 weight; guideline weights are
  otherwise unchanged.
- **`scan -v` STARTTLS detail** shows the true status (`ok`/`no`/`unknown`),
  the determining source, a `(disagree)` marker, and, for unknowns, the
  underlying error — instead of printing `no` for anything not confirmed `ok`.
  The Sources panel reports MXToolbox usage and an egress-25 warning.

### Migration
- No schema change. Run `scripts/reassess_all.py` after deploying so folded
  587/465 evidence and reconciled verdicts are reflected; run
  `see_monitor.py scan --rescan-all` to gather the new 587/465 data (reassess
  alone cannot, as older scans lack it). MXToolbox is optional and off until an
  API key is set.

## [0.6.11] — 2026-07-28

### Added
- **`check_apis.py --verbose` (`-v`).** Prints each HTTP request, its status and
  timing, per-service elapsed time, and the total run time to stderr, so a slow
  run is easy to diagnose. Secrets (Authorization headers, `key`/`token`-type
  query params) are redacted in the output. Elapsed time per service is also
  included in `--json` output.

### Changed
- **`check_apis.py` crt.sh check fails fast.** crt.sh is frequently slow or
  unavailable and its `%.<domain>` JSON response can be huge, which made it
  dominate the run (a single 15 s read timeout). Its wait is now capped at 8 s,
  it retries only on fast 5xx responses (a read timeout or 4xx no longer
  triggers pointless retries), and it parses the subdomain count from the
  response it already fetched instead of issuing a second heavy query. The
  failure note now makes clear crt.sh flakiness is expected and does not affect
  scoring or the keyed sources.

## [0.6.10] — 2026-07-28

### Changed (action required for Censys users)
- **Censys migrated to the Platform API.** The scanner client
  (`scanner/censys_client.py`) and the connectivity checker now use the Censys
  **Platform** API (`https://api.platform.censys.io/v3`) with a Personal Access
  Token (Bearer), instead of the deprecated Legacy Search API
  (`search.censys.io`, API id/secret, HTTP Basic auth — sunset by Censys in
  September 2026). Host lookups use `GET /v3/global/asset/host/{ip}` and parse
  the `result.resource.services[]` shape; STARTTLS is inferred from each SMTP
  service's `tls` object (port 465 left as implicit TLS, matching the Shodan
  client). **Update `config.yaml`:** replace the `censys.api_id` /
  `censys.api_secret` fields with:
  ```yaml
  censys:
    personal_access_token: "<your PAT>"
    organization_id: ""      # optional; set if your token is org-scoped
  ```
  A PAT is created at https://accounts.censys.io/settings/personal-access-tokens .
  `organization_id` is optional (free-tier host lookups work without it).

### Fixed
- **`check_apis.py` Censys check now works and is quota-free.** It validates the
  PAT against `GET /v3/accounts/users/credits` (the Platform Free-user
  credit-balance endpoint, which does not consume credits) and reports the
  balance. On `401` it flags an invalid/inactive token; on `404` it suggests
  setting `organization_id`. This replaces the previous check, which queried a
  non-existent legacy endpoint and returned a confusing 404/403.
- **`check_apis.py` crt.sh check retries transient 5xx.** crt.sh frequently
  returns 502/503/504; the check now retries up to three times before reporting
  a failure (with a note that it usually recovers), so a transient blip no
  longer reads as an outage.

## [0.6.9] — 2026-07-28

### Fixed
- **`check_apis.py` — Censys check hit the wrong endpoint.** It queried
  `/api/v2/account`, which does not exist (the v2 base serves only
  hosts/certificates), producing a confusing `404`. Account/quota lives on the
  Legacy-Search v1 path; the check now uses `/api/v1/account` (HTTP Basic auth,
  matching the scanner client). On `401/403`/`404` it now explains the likely
  cause: Censys is deprecating Legacy Search (`search.censys.io`, API id/secret)
  in September 2026 in favour of the Censys Platform (`platform.censys.io`),
  which authenticates with a Personal Access Token + organisation id. This makes
  an invalid/migrated Censys credential visible instead of silently yielding no
  passive data during scans.
- **`check_apis.py` — DNSDumpster domain-rejection was misreported as an API
  failure.** DNSDumpster refuses some domains (notably reserved ones like
  `example.com`) with `400 {"error":"Invalid domain"}`. Because a bad key
  returns `401`, a `400` domain rejection actually proves the key
  authenticated. The check now treats that case as **OK (key valid)** with a
  note, rather than a failure, and the default `--domain` changed from
  `example.com` to `google.com` so a normal run performs a real lookup.

## [0.6.8] — 2026-07-28

### Added
- **`scripts/check_apis.py` — passive-API connectivity checker.** Verifies that
  the passive-intelligence services configured in `config.yaml` are reachable
  and that their credentials work, using the keys already in the file. One
  bundled script covers all of them; run with no arguments to test everything or
  name services to narrow it (`check_apis.py shodan censys`). `--config`,
  `--domain`, `--timeout` and `--json` are supported. Checks are **quota-free**
  where the provider offers a health/account endpoint — Shodan `/api-info`,
  Censys `/account`, SecurityTrails `/ping` (+ `/account/usage` for quota);
  DNSDumpster has no such endpoint, so it does one real lookup (labelled as
  consuming a request), and crt.sh is keyless/quota-free. The script reuses the
  real `scanner/*_client.py` classes and their exported base URLs rather than
  duplicating any auth logic, and reuses `see_monitor.load_config()` for config
  discovery. Exit codes: `0` all configured services passed, `1` at least one
  failed, `2` bad invocation. An unconfigured service is reported and skipped
  without failing the run.

## [0.6.7] — 2026-07-27

Deploy-tooling refactor (no behaviour change from 0.6.6).

### Changed
- **Shared restart library.** The race-free service-restart logic added in
  0.6.6 was duplicated in `sync-tree.sh` and `deploy.sh`. It now lives in a
  single sourced library, `scripts/lib/systemd-restart.sh`, exposing `svc_up`
  (treats active/activating/reloading as "up") and `restart_units UNIT...`
  (snapshots state before restarting, restarts in the given order, polls each
  unit to settle, returns non-zero if any fails). Both scripts source it and
  pass their ordered unit list; the library is `set -euo pipefail`-safe and
  falls back to plain loggers if the caller has not defined `ok/warn/err`, so it
  can be exercised standalone. `RESTART_CTX` and `RESTART_SETTLE_TIMEOUT` are
  overridable. `.gitattributes` already enforces LF on `*.sh`; the file is
  sourced (no execute bit required, though `fix-permissions.sh` will set one).

## [0.6.6] — 2026-07-27

Deploy-tooling fix.

### Fixed
- **`sync-tree.sh`/`deploy.sh` falsely reported the scheduler as stopped.**
  With `--restart`, the scripts restart `see-monitor-web` first, then checked
  `systemctl is-active` on `see-monitor-scheduler` to decide whether to restart
  it. But the scheduler unit declares `Requires=see-monitor-web.service`, so
  restarting web makes systemd stop-and-restart the scheduler as well. The live
  check raced against that propagation and caught the scheduler mid-transition,
  printing `⚠ see-monitor-scheduler is not running — skipping restart.` for a
  service that was in fact running (and moments later back to `active`).

  Both scripts now (1) **snapshot** each unit's state *before* any restart, so
  the decision reflects operator intent rather than a state the script's own web
  restart just perturbed; (2) treat `active`/`activating`/`reloading` as "up";
  and (3) after issuing a restart, **poll for the unit to settle** (up to ~15s)
  before reporting success or failure. A service that was deliberately stopped
  before the sync is still skipped, now with an accurate message.




Bug-fix and hardening release: corrects the Overview control-implementation
denominators, locks scanning to admins, makes the admin tables sortable, fixes
organisations whose name contains an apostrophe, and adds file-based in-app
help.

### Fixed
- **Control implementation rate denominators.** `get_summary_stats` only counted
  a mail domain toward a control's `applicable` total when that control had a
  numeric score, so any control that came back `None` (unknown or not published)
  silently shrank its own denominator. DKIM read `17/17` (100%) instead of
  `17/32`, STARTTLS `24/24` instead of `24/32`, and BIMI `0/0` instead of
  `0/32`. A mail domain is now applicable for every control it carries; an
  unconfirmed or absent control counts as *not implemented* rather than dropping
  out. The rate now reads "of all my mail domains, how many have this control
  working". Fix is in the shared summary function, so the Overview, per-org and
  group-report views all correct together.
- **Why a control is unscored is now visible.** Because unconfirmed controls now
  count against the rate, the domain view explains each `—`: an inline reason
  ("STARTTLS could not be probed", "no DKIM selector discovered", "optional — no
  BIMI record", "n/a — no mail") plus a new **Evidence & confidence** panel that
  surfaces the already-stored confidence notes. Display-only; no schema change.
- **Organisations with an apostrophe in the name.** Actions on orgs such as
  *Banca d'Italia* (Domains, Delete — and the equivalent user/list/community
  buttons) silently did nothing. The names were HTML-escaped into inline
  `onclick` handlers, but the browser decodes `&#39;` back to `'` before the JS
  parser runs, so `openOrgDomains(5,'Banca d'Italia')` was a syntax error.
  A new `jss()` helper embeds values as JSON-encoded literals, which survive
  HTML decoding and also handle embedded double quotes. Backend SQL was already
  parameterised and unaffected.

### Changed
- **Scanning is admin-only.** `POST /app/api/scan` and `GET /app/api/runs` now
  require the admin role (previously any authenticated user scoped to their
  domains). Each scan spawns a live probing thread (DNS/SMTP/TLS) and writes
  results, so it is both a server-load and a data-integrity surface. The *Scans*
  nav tab and the domain *Re-scan* button are hidden for non-admins, and the
  runs view refuses to render for them. Analysts and community managers continue
  to **view** results and, for their own assigned domains, to register/remove
  DKIM selectors.
- **Sortable admin tables.** Users (username, name, email, role, status, last
  login), Organisations (id, name, sector, region, country, domains) and
  Communities (id, name, description, orgs) now sort on any column header, with
  a direction indicator. Client-side only.

### Added
- **In-app help.** A new `(?)` popover appears per control on the Overview
  implementation-rate list and on a domain's controls/findings, plus general
  topics for the rate itself and for unscored controls. Content is served from
  `help/help_content.json` (new `GET /app/api/help`) and is edited in that file
  alongside the code — deliberately **not** stored in the database, so no
  user-writable path can inject the HTML it renders. Seeded with a short
  description and authoritative links (NIST SP 800-177r1, BSI TR-03182,
  CCN-CERT BP/02, relevant RFCs) for every control.

### Security / least-privilege audit
- Reviewed every non-admin state-changing or resource-consuming endpoint. The
  scan trigger was the significant server-load vector (unbounded thread spawn +
  outbound probing) and is now admin-only. DKIM selector add/delete remain
  available to analysts, deliberately scoped to their assigned domains. PDF and
  roadmap generation remain available (bounded compute).

### Tests
- 24 → **97 passing** (5 new): control-rate denominator counts unconfirmed
  controls as applicable; `/app/api/scan` and `/app/api/runs` return 403 for
  analysts and 200 for admins; the help endpoint and shipped JSON expose all
  nine control topics; and a regression guard asserts inline handlers embed
  names via `jss()`.




Bug-fix release. Running `scripts/reassess_all.py` duplicated every domain in
the dashboards, once per run.

### Fixed
- **Duplicate assessments after re-assessment.** `reassess_all.py` re-scores a
  stored scan and reuses that scan's timestamp — which is correct, because the
  assessment describes the same measurement and inventing a new timestamp would
  plant a fake point on every trend chart. But nothing enforced uniqueness, so
  each run INSERTed a second row identical in `(domain, guideline,
  assessed_at)`, and `get_latest_assessments` joins on `MAX(assessed_at)`, where
  a tie returns *every* tied row. One reassess showed each domain twice, two
  showed it three times, and the counts, averages and rating distributions were
  inflated to match.

  Three layers of fix:
  1. `save_assessment` is now an **UPSERT** on `(domain, guideline,
     assessed_at)`, so re-scoring updates the row in place. `reassess_all.py`
     is idempotent — run it as often as you like.
  2. **Schema v4** adds a UNIQUE index on those three columns, so duplicates
     cannot be created by any code path, including direct SQL.
  3. `get_latest_assessments` breaks ties on `MAX(id)`, so even a database that
     has not been migrated (opened read-only, or restored from an old backup)
     renders one row per domain.
- **`db_check.py` now detects duplicates**, reporting the affected
  domain/guideline/timestamp groups as an error, how many redundant rows would
  be removed, and — separately — a warning when the v4 UNIQUE index is absent
  so duplicates could reappear.
- `db_check.py` crashed with `TypeError` when inspecting PRAGMA output: it
  connects without a row factory, so PRAGMA rows are plain tuples and cannot be
  indexed by column name.

### Database
- **Schema v4.** On first open, duplicate assessment rows are removed keeping
  the highest `id` (the most recently written row, i.e. the one scored by the
  newest code), the number removed is logged at WARNING, and a UNIQUE index is
  created. Rows with genuinely different timestamps are untouched, so per-domain
  history and trend charts are preserved. No data is rewritten and no scan is
  lost. Downgrading is not supported.

### Changed
- `reassess_all.py` reports the resulting row count and any domains skipped for
  having no stored raw scan, so an unexpected total is visible immediately.

### Migration
Deploy and open the database once — the CLI, the web app or
`scripts/db_check.py` all trigger it:

```bash
python3 scripts/db_check.py --db /var/lib/see-monitor/see_monitor.db
```

Expect a `Schema v4: removed N duplicate assessment row(s)` warning in the log
on the first run, then a clean report. No re-scan and no re-assessment is
needed to clear the duplicates.

## [0.6.3] — 2026-07-24

Domains with no MX record receive no mail, so grading their email security as
"weak" was misleading — there is nothing to grade. This release treats them as
N/A, skips them on scan by default, and adds a tool to clean up the ones
already stored.

### Added
- **`no_mail` rating.** A domain with no MX (or an RFC 7505 null MX) is now
  rated `no_mail` — rendered "No email (N/A)" — instead of falling into the
  weak/not-implemented band. The numeric score and per-control detail are kept
  (an absent SPF/DMARC record is still a real anti-spoofing fact), but the
  headline rating and the profile compliance verdict are set to N/A so nothing
  downstream miscounts a mistakenly-added domain. Shown distinctly in the CLI,
  the web dashboard (grey badge, its own legend entry) and PDF reports.
- **`scan --force`.** By default the scanner now MX-pre-checks each target and
  skips domains that receive no mail, so an accidental entry never lands in the
  database as an empty assessment. `--force` scans them anyway. The skip list
  is reported (and included in `--json` output). `scripts/import_orgs.py` gains
  the same `--force` flag and skips no-MX domains from scanning by default.
- **`scripts/prune_no_mail.py`** — removes no-mail/empty domains completely:
  their raw scans, assessments, DKIM selectors, organisation assignments and
  roadmaps are deleted, and they are stripped from every saved domain list.
  Organisations, communities and schedules themselves are kept.
  - DEFAULT: inspects the database and selects domains whose latest assessment
    is `no_mail` *and* have no positive EMAIL signal (every email control 0 or
    n/a). A parked domain publishing `v=spf1 -all` is kept — it is doing
    something. Infrastructure controls (dns_hygiene, reputation, subdomains)
    are ignored for this test, since a no-mail domain can still have healthy
    nameservers and that is no reason to keep it.
  - `--list FILE` removes exactly the domains listed, regardless of DB state,
    warning about any that are unknown or that actually have mail.
  - `--all-no-mail` relaxes DEFAULT to every no_mail domain.
  - Refuses to delete without `--dry-run` or `--yes`, so an accidental run
    cannot destroy anything.
- New DB helpers: `find_no_mail_domains(empty_only=True)` and
  `purge_domains(domains)` (per-table deletion counts + list updates).
- Scoring aggregates exclude no-mail domains from averages. `get_summary_stats`
  and the group/community/country aggregates count them in a separate `no_mail`
  bucket and report `mail_domains` / `no_mail_domains`, so a handful of parked
  domains cannot drag a community's average down.
- `ScanOrchestrator.has_mail(domain)` — cheap MX-only pre-check sharing the
  orchestrator's DNS client (cached for the full scan that may follow).
- 12 new tests (84 total): the no_mail rating and compliance override, average
  exclusion, empty-vs-parked discrimination, complete purge with other domains
  left intact, scan-time skip and `--force`, and the prune CLI in DB, list,
  dry-run and refuse-without-confirmation modes.

### Changed
- `assessments` averages and rating distributions now recognise the `no_mail`
  state throughout the CLI, dashboard, PDF and DB aggregates.

### Migration
No schema change. Existing stored assessments already carry `no_mail`, so they
render correctly as soon as the code is deployed; re-scanning is not required.
To retro-actively rate stored no-mail domains as N/A rather than weak, run
`scripts/reassess_all.py`. To remove them, run `scripts/prune_no_mail.py
--dry-run` and then, if the selection looks right, without `--dry-run`.

## [0.6.2] — 2026-07-24

### Added
- **Bulk organisation import** — `scripts/import_orgs.py`. Takes a CSV of
  `domain,organisation,country[,sector]` and in one pass registers the
  organisations, assigns their domains, optionally attaches them all to a named
  community, scans every domain, and writes a dated log.

  ```bash
  python3 scripts/import_orgs.py banks.csv --community "EU Central Banks"
  python3 scripts/import_orgs.py banks.csv --dry-run
  python3 scripts/import_orgs.py banks.csv --no-scan --schedule
  ```

  - **Parsing** uses the `csv` module, so organisation names containing commas
    work when quoted. Blank lines, `#` comments and a `domain,...` header are
    ignored — the header is detected on the first data row, not line 1, because
    comment blocks above it are common. Invalid rows are reported individually
    and skipped rather than aborting the run.
  - **Multiple domains per organisation** are merged into one organisation.
    Conflicting countries for the same organisation are reported, first value
    wins.
  - **Geography** is resolved per organisation: the ccTLD decides
    `country_code` and `region` via `data/tld_geo.csv`, while the CSV's country
    name is kept as the display label. A gTLD-only organisation still resolves
    its code by matching the supplied country name against the same table.
    Existing organisations imported without geography are backfilled.
  - **Idempotent.** Organisations match by name (case-insensitive), domain
    assignments and community membership use `INSERT OR IGNORE`, and
    `set_org_domains(..., replace=False)` means a domain already assigned is
    never removed by an import file that omits it. Re-running imports only new
    material; the log marks each domain `+` (added) or `=` (already present).
  - **Dated log** at `logs/see-monitor-import-YYYY-MM-DD.log` (append mode with
    a session header; `--log-dir` / `--log-file` to override). Contains the
    per-organisation plan, per-domain scan results with score, rating and
    evidence confidence for every profile, and a timing summary.
  - **`--schedule`** refreshes the auto-managed weekly schedule afterwards, so
    imported domains are actually rescanned rather than assessed once.
  - `--dry-run`, `--no-scan`, `--scan-only`, `--profile`, `--db`, `--config`.
  - Exit codes: 0 clean, 1 completed with errors (bad rows or failed scans),
    2 fatal (input or database unreadable).
- 11 new tests (74 total): parsing edge cases, quoted names, domain merging,
  country conflicts, ccTLD and country-name geography resolution, community
  creation, idempotent re-runs, the no-unassign guarantee, dry-run writing
  nothing, geography backfill, and an end-to-end run asserting the dated log.

### Note on ordering
Registration runs **before** scanning. Scanning a large list takes minutes to
hours, and an interruption partway through would otherwise lose the entire
import; registration is fast and idempotent, so an interrupted run can simply
be repeated. Use `--scan-only` to rescan a file that is already imported.

## [0.6.1] — 2026-07-24

Operational release. 0.6.0 added the checks; this makes sure they actually
reach every domain. Two of the fixes below are long-standing bugs found while
answering "does the scheduler rescan everything automatically?" — the answer
was no, and it was not scoring all profiles either.

### Added
- **`schedules` command and `scripts/schedule_audit.py`** — audits periodic
  scans against the domains the database actually knows about. Reports each
  schedule (interval, bound list, last/next run), coverage as a percentage,
  the domains in no enabled schedule and therefore never rescanned, domains
  duplicated across schedules, schedules bound to a missing or empty list,
  disabled schedules, and overdue schedules (a good proxy for "the daemon is
  not running"). Exit code 1 on any gap, so it works as a cron health check.
- **`--create-weekly`** — maintains one auto-managed domain list containing
  every known domain, driven by one weekly schedule. Idempotent: re-running
  updates the list contents and interval in place rather than creating
  duplicates, so it is safe to run from cron to keep coverage complete as new
  domains appear. `--dry-run` and `--interval-hours` supported.
- **`scan --rescan-all`** — rescans every domain known to the database (domain
  lists, past assessments, organisation assignments). This is the supported way
  to pick up new checks after an upgrade.
- **`ScanScheduler.reload()`** — re-reads `scheduled_scans` and reconciles
  registered jobs, so a schedule created by the audit tool is picked up without
  restarting the service. The daemon calls it on a configurable tick
  (`scheduling.reload_interval_minutes`, default 60). Unchanged jobs are left
  alone: re-registering uses `replace_existing=True`, which recomputes
  `next_run_time` from now, so blindly re-registering a 168h job every hour
  would reset its clock and it would never fire.
- **Post-run database health gate** — `scheduling.post_run_db_check` (default
  true) runs the read-only consistency audit after each scheduled scan. Error
  level findings are logged and mark the run `completed_with_errors`. It can
  never raise: a broken health check must not lose results already written.
- 12 new tests (63 total) covering coverage reporting, orphan/disabled/overdue
  detection, duplicate coverage, idempotent `--create-weekly`, multi-profile
  scheduled runs, run-time bookkeeping, the health gate, and the
  `--rescan-all` guard rails.

### Fixed
- **Scheduled scans now assess against every installed profile.** `_run_scheduled_scan`
  called `assess_domain(scan, self.config)`, so only the default profile
  (`nist_800_177r1`) was persisted. The CLI has used `assess_all_profiles`
  since 0.3.0, so BSI, ACN and CCN-CERT dashboards went progressively stale
  even while scheduling worked perfectly. Configurable via
  `scheduling.profiles` (empty = all installed).
- **`next_run_at` is now maintained.** It was written once at schedule creation
  and never updated, so the stored value drifted from reality as soon as the
  first run happened. It is now taken from the live APScheduler job after each
  run, falling back to `now + interval` when the scheduler is not running.
- A schedule whose domain list is empty now records its run timestamps instead
  of returning early and appearing to have never run.

### Configuration
New `scheduling` block: `profiles`, `post_run_db_check`,
`reload_interval_minutes`. All optional with safe defaults.

### Upgrade note
`scan --rescan-all` is still required once after upgrading from 0.5.x — the
scheduler will pick the new checks up on its own cycle, but that is up to a
week away, and `reassess_all.py` cannot help because the stored 0.5.x scans
contain none of the new data.

## [0.6.0] — 2026-07-24

Assessment-depth release. The scanner previously answered "is the record
published and what does it say"; it now also answers "does the record actually
work, and is the infrastructure behind it sound". Several changes are
**correctness fixes that alter existing scores** — see *Changed* and *Migration*.

### Added
- **DNS hygiene control** (`scanner/dns_hygiene.py`) — dangling MX, MX pointing
  at a CNAME (RFC 2181 §10.3, also breaks DANE), forward-confirmed reverse DNS,
  IPv6 readiness, CAA (RFC 8659), dangling `mta-sts`/`autodiscover`/
  `autoconfig`/`_dmarc` CNAMEs as subdomain-takeover exposure, nameserver count
  and provider diversity, MX provider concentration.
- **Reputation control** (`scanner/dnsbl_check.py`) — MX addresses and the
  domain against Spamhaus zen/DBL, SpamCop and PSBL. Enabled by default. A
  `127.255.255.x` refusal is reported as `blocked` and is never scored as clean
  or as listed; `confidence` drops accordingly. DQS zones configurable.
- **Subdomain coverage control** (`scanner/subdomain_check.py`,
  `scanner/crtsh_client.py`) — candidates from Certificate Transparency
  (crt.sh, no API key) and SecurityTrails, each DNS-confirmed before use.
  Detects subdomain DMARC records weaker than the apex `sp=`, live subdomains
  with no enforcing policy, and mail-receiving subdomains without SPF.
- **Certificate analysis** (`scanner/cert_check.py`) — SAN/wildcard hostname
  matching (RFC 6125), validity window and expiry warning, self-signed
  detection, signature algorithm, key strength, chain completeness, and offline
  PKIX path validation. Also TLSA parsing and digest matching.
- **DANE live verification** — TLSA usage/selector/matching-type validation per
  RFC 7672 (PKIX-TA/PKIX-EE rejected as unusable for SMTP), digest-length
  sanity, and matching against the certificate the server actually presents. A
  stale TLSA that no longer matches is now a finding; DANE-TA(2) against a
  leaf-only chain reports *unknown* rather than a false mismatch.
- **DMARC organizational-domain tree walk** — bounded DMARCbis walk, with
  `policy_domain` / `inherited` / `effective_policy`. `psd=y` records are
  correctly not inherited.
- **DMARCbis tags** — `np=` (non-existent subdomain policy) and `psd=`.
- **Verified DMARC reporting loop** — the RFC 7489 §7.1 external-destination
  authorisation record is now queried, not merely warned about, and `rua`
  destinations are checked for resolvability.
- **SMTP AUTH before STARTTLS** and **banner/version disclosure**, both derived
  from the probe's existing single connection.
- **SPF depth** — RFC 7208 §4.6.4 void-lookup limit, dangling include/redirect
  targets, size of the authorised address space, shared/multi-tenant ESP
  includes, macro use, `exp=`.
- **MTA-STS depth** — `id=` presence, HTTP 200 with no redirect, content-type,
  `version: STSv1`, `max_age` upper bound, and policy-host certificate failure
  as a distinct hard finding.
- **DNSSEC quality** — deprecated signing algorithms (RFC 8624), SHA-1-only DS
  digest, non-zero NSEC3 iterations (RFC 9276).
- **Passive client-endpoint discovery** — conventional names (`mail.`, `smtp.`,
  `imap.`, `pop.`, `webmail.`, `owa.`) plus Autodiscover/Autoconfig, reported
  as attack surface without connecting to them.
- **Sub-scores** — `impersonation`, `transport`, `resilience`: orthogonal,
  profile-independent views over the same control set.
- **Evidence quality** — every assessment carries `confidence`
  (`high`/`medium`/`low`) and `confidence_notes`.
- **Roadmap coverage** for the new controls, including takeover remediation,
  blocklist delisting, subdomain enforcement, certificate repair and TLSA
  re-publication.
- 27 new tests (51 total), covering the tree walk, `psd=` non-inheritance,
  void lookups, DKIM unknown-vs-absent, STARTTLS three-state scoring,
  certificate and TLSA matching (against a generated throwaway certificate),
  DNSBL refusal handling, subdomain override detection, sub-scores, and the
  v2→v3 database migration.

### Changed
- **STARTTLS is three-state** — `ok` / `no_tls` / `unknown`. Previously an
  unreachable host or disabled active probing produced a verdict identical to a
  server that genuinely refuses TLS. Coverage is computed over known hosts only,
  and a control with no determinable host scores `null`, not `0`.
- **DKIM absence is no longer assumed** — selectors are not enumerable from
  DNS, so a wordlist miss with no registered selector yields `status=unknown`
  and a `null` score. A registered selector that fails to resolve is still a
  high-confidence `absent` scoring `0`.
- **BIMI absence is n/a**, not a failure; a BIMI record without DMARC
  enforcement is scored `30` and flagged as an unmet prerequisite.
- **STARTTLS score is capped** by certificate hostname mismatch or invalidity
  (≤55), by cleartext AUTH (≤70) and by deprecated TLS (≤60), because each of
  these means MTA-STS `enforce` or DANE would fail in practice.
- **Findings from `dns_hygiene`, `reputation` and `subdomains` are always
  surfaced**, whatever the active profile weights — a blocklisted mail server
  matters to a BSI reader as much as to a NIST one.
- Guideline profiles gained weights for the three new controls. Their
  `required_signals` / `very_strong_requirements` are **unchanged**: those
  mirror the published national documents, and adding SEE-Monitor's own
  controls to them would misrepresent the standard (HANDOVER invariant 9).
- CLI shows evidence confidence, sub-scores and the new controls; the control
  glyph line now wraps to any number of controls.

### Fixed
- The external-report-destination hint named the wrong DNS record; the
  authorisation record lives at `<sender-domain>._report._dmarc.<destination>`.
- SPF lookup traversal no longer under-counts: `exists:` and explicit-domain
  `a:`/`mx:` targets are resolved, and unresolvable targets are counted as void
  lookups.

### Database
- **Schema v3.** `assessments` gains `subscores_json`, `confidence` and
  `confidence_notes_json`. Migration is additive (`ALTER TABLE … ADD COLUMN`
  with defaults, guarded by `PRAGMA table_info`); existing rows are preserved
  and remain readable, and no data is rewritten. `scripts/db_check.py` validates
  the new JSON columns and the `confidence` value domain. `docs/DATABASE.md`
  updated.
- Raw certificate bytes are never persisted: the probe's `_chain_der` and
  `starttls._chains` are consumed in memory and stripped by the orchestrator.

### Migration
1. Deploy, then run `python3 scripts/db_check.py --db <db>` to confirm the
   migration applied cleanly.
2. Run `python3 scripts/reassess_all.py` to re-score stored scans under the new
   weights and n/a semantics. Scores will move: domains previously penalised
   for an undiscoverable DKIM selector or an unreachable MX will rise, and
   domains with dangling DNS, invalid MX certificates or blocklist listings
   will fall.
3. Review `dnsbl.enabled` and `scanning.max_subdomains` before a
   community-scale scan — those two settings dominate query volume.

### Deferred (documented in README "Future features")
Inbound DMARC/TLS-RPT report ingestion (would make the tool a participant in
the assessed domain's mail flow rather than an external observer), and all
checks needing authorised active testing: TLS/cipher enumeration, open-relay
testing, `VRFY`/`EXPN`, recipient/catch-all probing, client-port TLS
verification on conventional names, and MTA version→CVE mapping.

## [0.5.1] — 2026-07-21

### Added
- **DB schema documentation** — `docs/DATABASE.md`: every table (both the
  `data/database.py` and `auth/store.py` owners), columns, keys, declared vs
  soft foreign keys, JSON column shapes, relationships, schema-version history,
  and how to run the consistency checker.
- **Database consistency checker** — `scripts/db_check.py` (stdlib only,
  read-only `mode=ro`): `PRAGMA integrity_check` + `foreign_key_check`, schema
  version, orphan detection for declared and soft references, `_json` column
  validation, and assessment value-domain checks (score range, boolean
  `no_mail`, installed guideline, in-band rating). Text/`--json` output,
  `--strict`; exit 0/1/2. Test-locked (`test_db_check_soundness`).

### Notes
- No application/schema change; version bump reflects tooling + docs. 23 tests.

## [0.5.0] — 2026-07-21

### Added
- **PDF export (reportlab).** Two profile-aware, server-rendered reports served
  with session auth: `GET /app/api/report/pdf` (scope report: header + status
  distribution + KPIs + per-domain table + embedded trend chart) and
  `GET /app/api/report/trend.pdf` (trend chart + per-period table). Both honour
  the selected `guideline`, the same scope resolver as the timeline
  (domain/org/community/country/region/all), and `period=`. "PDF report" and
  "Trend PDF" buttons appear on Overview, group reports, org, domain and Trends
  views. reportlab is the only new dependency (pure-Python); routes return a
  clean 501 if it is absent.
- **Organisation status dashboard.** The org detail page now matches the other
  status dashboards: segmented status bar + per-status KPIs + status-coloured
  domain table, with Trends and PDF export buttons.
- Charts (status bar + stacked-status/score trend) are drawn as reportlab
  vector graphics in `reports/pdf_report.py`.
- Tests: PDF builders + PDF endpoints (reportlab-guarded via importorskip); 22 total.

## [0.4.0] — 2026-07-21

### Added
- **Profile-aware status dashboards.** A **Standard** selector (NIST / BSI /
  ACN / CCN) in the nav drives every view; all GET API calls are auto-scoped
  with `?guideline=`. Overview and community/country/region reports are now
  status dashboards: a segmented status-distribution bar + per-status KPIs,
  with click-through from a status to the matching domains. Ratings, labels and
  colours come from each guideline's `rating_bands` (new `bands` field on
  `/app/api/guidelines`).
- **Trends view (timeline).** New `Trends` tab and `GET /app/api/timeline`
  (`period=weekly|monthly|quarterly|yearly`, default weekly; scope via
  `domain|org|community|country|region`, default all visible). Inline SVG chart
  plots stacked status distribution (bars) **and** average score (line) per
  period; per-period detail table below. Reachable from a domain's detail page
  and from every group report.
- **DB:** `get_timeline(domains, guideline, period)` with ISO-week / month /
  quarter / year bucketing; means and rating counts are aggregated across all
  scans in each period.
- Tests: timeline bucketing + timeline/guidelines API (20 passing).

## [0.3.0] — 2026-07-21

### Added
- **National conformance profiles.** Scoring is now multi-profile. New
  `guidelines/{bsi_tr03182,acn_email,ccn_cert_bp02}.json` profiles sit alongside
  the default `nist_800_177r1`, each with its own weights, rating bands and a
  `required_signals` list that gates the top ("compliant") rating independently
  of the numeric score.
- **Assessor:** `assess_domain(scan, config, guideline_id=...)`,
  `assess_all_profiles()`, `available_guidelines()`, and a named
  compliance-predicate registry (`_sig` / `_SIGNAL_LABELS`). Unmet required
  signals demote the rating and emit `profile` findings.
- **SPF signals** (BSI TR-03182-01 / ACN): `all`-is-last ordering, `ptr` usage,
  ip-vs-name mechanism ratio, and pure deny-all (`v=spf1 -all`) detection for
  parked-domain hardening.
- **DKIM signals** (BSI TR-03182-03/04/05): dual-algorithm presence
  (`has_rsa`/`has_ed25519`/`algorithms`), RSA >2048 flag, and SHA-1 (`h=`) flag.
- **DMARC signals** (BSI TR-03182-06 / ACN): strict alignment (`adkim=s;aspf=s`),
  `ruf` presence, and external `rua`/`ruf` report-domain detection.
- **DNSSEC:** AD-flag check on the `_dmarc` policy zone.
- **New control `client_tls`** (CCN-CERT BP/02): submission/retrieval TLS on
  587/465/993/995, discovered via RFC 6186 SRV records; n/a when not advertised.
  New scanner `scanner/client_tls_check.py`.
- **DB:** guideline-aware `get_latest_assessments`, `get_domain_history`,
  `get_summary_stats`, and group aggregates (community/country/region);
  `get_guidelines_present()`. Schema bumped to **v2** (index-only migration).
- **Web API:** every assessment endpoint accepts `?guideline=<id>`; new
  `/app/api/guidelines`. Scans persist one assessment per installed profile.
- **CLI:** `scan --profile <id>` (repeatable); per-profile score/compliance line.
- **Roadmap:** national-profile hardening activities (Ed25519, RSA cap, strict
  alignment, `ptr` removal, parked-domain hardening).
- Tests: 7 new smoke tests (SPF ordering/deny-all, DKIM dual-algorithm/bounds,
  DMARC strict/ruf/external, BSI/ACN/CCN gating, multi-profile DB round-trip).

### Notes
- **Intentional cross-standard conflict:** ACN requires DMARC `ruf`; BSI forbids
  it (GDPR). Handled per-profile — no single verdict.
- **Attestation-only** (not DNS/SMTP-observable, listed per profile): DKIM
  oversigning, `Authentication-Results` insertion, DMARC report
  sending/receiving/evaluation, and organisational controls.
- **Deferred (documented, not built):** DKIM key-rotation history (BSI
  TR-03182-03) — no schema column provisioned.

## [0.2.0] — prior session
- feat: DNSDumpster passive DKIM-selector discovery.
- feat: SecurityTrails passive DNS intel (MX/TXT + selectors).
- feat: richer CLI output (summary + sources; `-v` diagnostics; `--json`).

## [0.1.0] — initial build
- Initial SEE-Monitor: SPF/DKIM/DMARC/STARTTLS/DNSSEC/DANE/MTA-STS/TLS-RPT/BIMI
  scanning, NIST SP 800-177r1 scoring, roadmaps, multi-user RBAC, dashboards.
