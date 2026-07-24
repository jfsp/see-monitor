# Changelog

All notable changes to SEE-Monitor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
Semantic Versioning. Commit trailer used: `Assisted-by: Claude (Anthropic)`.

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
