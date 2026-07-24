# Changelog

All notable changes to SEE-Monitor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
Semantic Versioning. Commit trailer used: `Assisted-by: Claude (Anthropic)`.

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
