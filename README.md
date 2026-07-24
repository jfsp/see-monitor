# SEE-Monitor

**Secure Electronic Email Monitor** — a multi-user platform that scans DNS
domains, identifies which email-security controls are implemented, scores each
domain against NIST SP 800-177r1, and produces prioritised improvement
roadmaps for individual domains, organisations, and communities.

SEE-Monitor derives its multi-user architecture (users → organisations →
communities), RBAC, dashboards, and roadmap engine from the PQC-Monitor
codebase, but is a new tool with an email-security scope and a fresh database.

---

## Controls assessed

| Control  | Standard                        | What is checked |
|----------|---------------------------------|-----------------|
| SPF      | RFC 7208 / SP 800-177r1 §4.4    | Record presence, `all` qualifier + ordering, `ptr`, ip-vs-name, deny-all, lookup limit (≤10), **void-lookup limit (≤2, §4.6.4)**, **dangling include/redirect targets**, **size of the authorised address space**, **shared/multi-tenant ESP includes**, **macro use** |
| DKIM     | RFC 6376 / SP 800-177r1 §4.5    | Selectors (wordlist **+** passive **+** per-domain registered), key type/size, RSA≤2048, Ed25519 presence, SHA-1, testing flag, **evidence quality (`present` / `absent` / `unknown`)** |
| DMARC    | RFC 7489 + DMARCbis / §4.6      | Policy, `pct`, `sp`, strict alignment, `rua`/`ruf`, **organizational-domain tree walk**, **`np=` and `psd=`**, **verified external-destination authorisation (§7.1)**, **`rua` destination reachability** |
| STARTTLS | RFC 3207 / SP 800-177r1 §5.1    | Per-MX support (**three-state: ok / no_tls / unknown**), negotiated TLS version, **certificate validity, hostname match, expiry, chain completeness, key and signature strength**, **SMTP AUTH offered before STARTTLS**, **banner/version disclosure** |
| CLIENT-TLS | RFC 6186 / CCN-CERT BP/02      | Submission/retrieval TLS (587/465/993/995) discovered via SRV (n/a if not advertised); **conventional endpoint names and Autodiscover/Autoconfig reported passively as attack surface** |
| DNSSEC   | RFC 4033-4035 / §4.1-4.2        | DS + DNSKEY, AD-flag validation, `_dmarc` policy-zone AD, **signing algorithm quality (RFC 8624)**, **SHA-1-only DS digest**, **NSEC3 iterations (RFC 9276)** |
| DANE     | RFC 7672 / SP 800-177r1 §5.2    | TLSA per MX, usability (requires valid DNSSEC), **usage/selector/matching-type validation**, **live match against the presented certificate** |
| MTA-STS  | RFC 8461                        | TXT record + HTTPS policy, mode, MX coverage, **`id=` presence, HTTP 200/no-redirect, content-type, `version: STSv1`, `max_age` bounds, policy-host certificate validity** |
| TLS-RPT  | RFC 8460                        | Record presence, `rua` destination |
| BIMI     | industry practice               | Record presence, Verified Mark Certificate, **DMARC-enforcement prerequisite** (absence is n/a, not a failure) |
| DNS-HYG  | RFC 2181 §10.3, 8659, 9276      | **Dangling MX, MX-as-CNAME, forward-confirmed reverse DNS, IPv6 readiness, CAA, dangling `mta-sts`/`autodiscover`/`autoconfig`/`_dmarc` CNAMEs, nameserver count and provider diversity, MX provider concentration** |
| REPUTATION | public DNSBLs                 | **MX addresses and the domain against Spamhaus zen/DBL, SpamCop, PSBL. Query refusals (`127.255.255.x`) are reported as `blocked`, never as clean or listed** |
| SUBDOMAINS | RFC 7489 §6.6.3, DMARCbis     | **Live subdomains (from CT + passive DNS, DNS-confirmed) covered by an enforcing DMARC policy; subdomain records weaker than the apex `sp=`; mail-receiving subdomains without SPF** |

### Scanning strategy

STARTTLS evidence is gathered **passive-first**: Shodan is consulted first,
then Censys as an alternative (both via API). An active, non-intrusive SMTP
STARTTLS probe (EHLO → STARTTLS → handshake → QUIT) is used as a fallback only
when passive sources have no data and `scanning.active_smtp` is enabled.

DKIM selectors are discovered from **SecurityTrails** and **DNSDumpster** when
API keys are configured (see below), in addition to per-domain registered
selectors and the common-selector wordlist. Subdomain candidates come from
**Certificate Transparency** (crt.sh, no API key) and SecurityTrails. All other
checks are ordinary DNS/HTTPS lookups. Every passive result — MX cross-checks,
DKIM selectors and CT subdomain names alike — is re-confirmed against
authoritative DNS before it can affect scoring; passive sources never feed the
score directly.

**Connection budget.** Active probing is one TCP connection per MX host. The
banner, the EHLO capability list, the negotiated TLS parameters, the PKIX
verdict and the certificate used for DANE matching all come from that single
exchange. A second connection is opened only when PKIX validation fails, to
retrieve the certificate the aborted handshake did not deliver. No mail
transaction is ever started: no `MAIL FROM`, no `RCPT TO`, no `AUTH`, no
`VRFY`/`EXPN`.

### Evidence quality vs score

Absence of evidence is not evidence of absence, and the two are now kept
separate. Each assessment carries a `confidence` (`high` / `medium` / `low`)
with `confidence_notes` explaining any downgrade. Controls that could not be
determined are scored `null` (n/a) and excluded from the weighted average
rather than counted as zero. The three cases that matter in practice:

- **DKIM `unknown`** — no selector was found and none was registered. Selectors
  are not enumerable from DNS, so a wordlist miss proves nothing.
- **STARTTLS `unknown`** — the host was unreachable, or active probing is
  disabled and no passive source had data.
- **Reputation `blocked`** — a blocklist refused our query, so neither a clean
  nor a listed verdict can be asserted.

### Sub-scores

Alongside the profile score, every assessment reports three orthogonal,
**profile-independent** views (0–100, or `null` when nothing applicable was
measured):

| Sub-score | Answers | Built from |
|-----------|---------|------------|
| `impersonation` | How hard is it to send mail that appears to come from this domain? | SPF, DKIM, DMARC, subdomain coverage |
| `transport` | Is mail to and from this domain protected in transit? | STARTTLS, MTA-STS, DANE, TLS-RPT, CLIENT-TLS |
| `resilience` | Is the infrastructure the controls depend on sound? | DNSSEC, DNS hygiene, reputation |

Two domains can share a rating while differing sharply here: a "partial" domain
with `impersonation` 90 and `resilience` 30 needs completely different work
from its mirror image.

---

## Scoring

Each control is scored 0-100, then combined with adjustable weights into a
domain score and a rating:

| Rating            | Default band |
|-------------------|--------------|
| Not implemented / weak | 0-29   |
| Medium            | 30-59        |
| Strong            | 60-84        |
| Very strong       | 85-100 **and** all core controls enforcing |

*Very strong* additionally requires `-all` SPF, `p=reject` DMARC, strong DKIM
keys, STARTTLS on all MX, and channel enforcement via MTA-STS `enforce` **or**
full DANE. Weights, rating bands, and these requirements live in
`guidelines/nist_800_177r1.json` and can be overridden in `config.yaml` under
`scoring:`. Domains that do not receive mail (no MX or null MX per RFC 7505)
have their transport controls marked *n/a* rather than scored as failures.

After changing any scoring parameter, re-score stored scans without re-querying
DNS:

```bash
python scripts/reassess_all.py --config config/config.yaml
```

---

## Conformance profiles

Beyond the default NIST SP 800-177r1 scoring, SEE-Monitor ships selectable
national **conformance profiles**. Each is a `guidelines/<id>.json` file with
its own control weights, rating bands, and a list of `required_signals` that
gate the top rating (a domain can score highly yet still be *non-compliant* if
a mandated signal is missing):

| Profile id       | Standard                                             | Notable requirements |
|------------------|------------------------------------------------------|----------------------|
| `nist_800_177r1` | NIST SP 800-177r1 (default)                          | weighted `very_strong` |
| `bsi_tr03182`    | BSI TR-03182 (Germany)                               | dual RSA+Ed25519 DKIM, RSA ≤2048, no SHA-1, DMARC strict alignment, **no** `ruf` (GDPR), DNSSEC, parked-domain hardening |
| `acn_email`      | ACN Framework (Italy)                                | SPF `-all`, DMARC `p=reject`+`sp=reject`, strict alignment, `rua` **and** `ruf` |
| `ccn_cert_bp02`  | CCN-CERT BP/02 (Spain)                               | SPF/DKIM/DMARC + STARTTLS + client submission/retrieval TLS (587/465/993/995) |

A single scan is scored against every installed profile; the CLI shows all of
them (`--profile <id>` to limit), and every web endpoint accepts
`?guideline=<id>`.

**Conflicting requirements are intentional and profile-scoped.** For example,
ACN *requires* DMARC forensic reports (`ruf`) while BSI *forbids* them under the
GDPR — a domain cannot satisfy both, and each profile reports its own verdict.

Some requirements in these standards are **not DNS/SMTP-observable** and are
therefore attestation-only (listed under `attestation_only` in each profile
file) — e.g. DKIM oversigning, `Authentication-Results` insertion, DMARC report
sending/receiving/evaluation, and organisational controls (security concept,
GDPR processing). These are documented, not scored.

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp config/config.yaml.example config/config.yaml   # then edit
python see_monitor.py init-db                       # creates schema + admin

# scan from the CLI
python see_monitor.py scan example.com example.org   # per-domain summary
python see_monitor.py -v scan example.com            # debug: records, per-MX
                                                     #   STARTTLS, findings,
                                                     #   service diagnostics
python see_monitor.py scan --quiet --list domains.txt   # one line per domain
python see_monitor.py scan --json example.com        # machine-readable

# run the web app (dev server)
python see_monitor.py serve --host 127.0.0.1 --port 8080
```

Default admin credentials on first run are `admin` / `changeme123` —
**change these immediately**.

### Deploying updates (git pull) and file permissions

If you update the server by pulling from Git (especially when pushing from
Windows), two Unix-specific things do not survive by default and will break the
services:

- **Execute bits.** Git records only `100644` vs `100755`, and Windows has no
  Unix execute bit, so scripts arrive non-executable and `ExecStartPre`
  (`wait-for-db.sh`) fails with `203/EXEC`. Mark them executable in the index
  once, then commit — after that every pull restores `+x`:

  ```
  git update-index --chmod=+x install.sh scripts/*.sh scripts/reassess_all.py \
      see_monitor.py
  git commit -m "Mark scripts executable"
  ```

- **Line endings.** Shell scripts saved with CRLF fail with
  `bad interpreter: /bin/bash^M`. The shipped `.gitattributes` forces `LF` on
  checkout to prevent this.

As a **fallback that runs regardless of how the tree arrived**, normalise
permissions after every deployment:

```
sudo bash scripts/fix-permissions.sh            # exec bits, CRLF, ownership, modes
sudo bash scripts/fix-permissions.sh --dry-run  # preview only
```

`fix-permissions.sh` is idempotent and non-destructive: directories → `0750`,
files → `0640`, executables (`*.sh`, entry points) → `0750`, CRLF stripped from
shell scripts, tree re-owned `root:seemonitor` — while never touching the
database, the virtualenv binaries, `.git`, or file *content* (apart from CRLF
stripping). Both `install.sh` and `scripts/deploy.sh` call it automatically; the
standalone form is for the `git pull` workflow.

### Production

Run under Gunicorn behind nginx (TLS termination). Install the systemd units:

```bash
sudo cp systemd/see-monitor-*.service systemd/see-monitor.target /etc/systemd/system/
sudo install -m 640 -o root -g seemonitor systemd/see-monitor.env /etc/see-monitor/see-monitor.env
sudo systemctl daemon-reload
sudo systemctl enable --now see-monitor.target
```

`systemd/nginx-see-monitor.conf` is a sample reverse-proxy config. Set
`https_enabled: true` in `config.yaml` only when TLS is terminated in front.

---

## Architecture

```
see_monitor.py        CLI (scan / serve / init-db / scheduler-daemon)
app_factory.py        Flask app factory (RBAC, security headers)
app_routes.py         /app/* dashboard REST API (role-scoped)
dashboard/app.py      Single-page dashboard UI
scanner/              DNS client, per-control checks, orchestrator, scoring
data/database.py      SQLite schema v1 + data access
roadmap/generator.py  Per-domain and group improvement roadmaps
reports/              CSV / JSON exporters
auth/ admin/          Reused RBAC, login, and admin console
scheduler/            APScheduler periodic scans
guidelines/           scoring profiles: nist_800_177r1 (default) + bsi_tr03182, acn_email, ccn_cert_bp02
```

Roles: **admin** (everything), **community_manager** (their communities'
organisations), **analyst** (their assigned domains). Country/region tagging on
organisations is carried over from PQC-Monitor and drives the group reports.

---

## Registering DKIM selectors

DKIM selectors cannot be enumerated from DNS. SEE-Monitor discovers them from
three sources, highest-confidence first:

1. **Per-domain registered selectors** — added by analysts from a domain's
   detail page or the API.
2. **SecurityTrails (optional)** — if `securitytrails.api_key` is set,
   SEE-Monitor enumerates observed subdomains and extracts
   `<selector>._domainkey` names. As a name-indexed passive-DNS database it
   also catches rotated/historical and ESP-delegated selectors a wordlist
   would miss, and provides an MX / mail-subdomain cross-check.
3. **DNSDumpster (optional)** — if `dnsdumpster.api_key` is set, SEE-Monitor
   harvests `<selector>._domainkey.<domain>` names from its host inventory
   (reliably catches ESP CNAME-delegated selectors such as Microsoft 365's
   `selector1`/`selector2`).
4. **Common-selector wordlist** — built-in ESP defaults.

**Every candidate, whatever its source, is confirmed with an authoritative TXT
lookup before it can affect scoring** — DNSDumpster data is never trusted for
scoring directly. Register a domain's real selectors for the most reliable
result:

```
POST /app/api/domain/<domain>/selectors   {"selector": "s1"}
```

Confirmed selectors (including those surfaced by DNSDumpster) are persisted
automatically and reused on future scans.

---

## Future features (not yet implemented)

Everything below is **documented only**. Each entry states why it is not in
this release, because in every case the reason is a deliberate scope boundary
rather than an oversight.

### Inbound report ingestion (DMARC RUA / TLS-RPT)

DMARC aggregate reports and TLS-RPT reports are the only way to measure what
*actually happens* to a domain's mail — the real proportion passing DMARC, the
sending sources the operator has forgotten about, the forwarders that break
alignment, and the real count of failed TLS negotiations. It would also settle
the DKIM `unknown` case permanently, since every report names the selectors in
use.

**Deliberately out of scope for this release.** SEE-Monitor is an *external,
passive observer*: it assesses a domain using only publicly observable data and
requires no cooperation, credentials or configuration change from the domain
being assessed. Report ingestion inverts that model — the assessed domain would
have to point `rua=` at a mailbox this platform reads, which turns the tool from
a monitor into a participant in the domain's mail flow and makes
community-scale, unsolicited assessment impossible.

If it is added later, the parser (gzip/zip XML for RFC 7489, gzip JSON for
RFC 8460) is the easy part; the design questions are the transport (CLI import
of files, IMAP polling, or a web upload endpoint), per-organisation
authorisation of who may submit reports for which domain, and the retention
policy for what is personal data under GDPR in the `ruf` case.

### Authorised active testing

The following need traffic that goes beyond the current one-connection,
no-transaction probe. They are all high-value, and all require **explicit,
recorded authorisation from the domain owner** — which is why they are gated
behind a future second scan mode rather than shipped on by default.

| Check | Why it needs authorisation |
|-------|---------------------------|
| TLS version and cipher enumeration | Requires one handshake per protocol version and cipher group; dozens of connections per host, indistinguishable from a scanner at the receiving end |
| Open relay test | Requires a real `MAIL FROM` / `RCPT TO` transaction to a third-party address, aborted before `DATA`. Unauthorised, it looks exactly like relay abuse |
| `VRFY` / `EXPN` enabled | Extra SMTP verbs; commonly logged and alerted on as reconnaissance |
| Recipient / catch-all detection | Requires probing addresses that may not exist, which is address harvesting |
| Client-port TLS verification (587/465/993/995) on conventional names | Today only RFC 6186 SRV-advertised endpoints are probed, so the control is n/a for most domains. Probing `mail.`/`imap.`/`pop.` by convention means connecting to services the domain never advertised |
| STARTTLS-stripping resilience | Requires deliberately malformed sessions |

The DNS-observable half of this is already implemented: conventional endpoint
names and Autodiscover/Autoconfig records are discovered and reported as attack
surface, without connecting to them.

### MTA version → CVE mapping

The scanner already extracts the software name and version from the SMTP
banner and reports the disclosure. Mapping those versions to known
vulnerabilities (Exim, Exchange, Zimbra and friends) is not implemented because
it needs a maintained vulnerability database and a version-comparison layer
per vendor, and because banners are trivially forged — a wrong "vulnerable"
verdict on a patched host is worse than no verdict. It belongs behind a
vulnerability feed, not behind a regex.

### Infrastructure diversity by ASN and netblock

MX and nameserver diversity is currently inferred from the registrable domain
of the host names, which is a good proxy but misses the case where two
apparently independent providers share one ASN or one datacentre. Real
diversity measurement needs RDAP or BGP data, i.e. another external dependency
and another rate limit.

### Lookalike and homoglyph domain detection

Registered typosquats and IDN homoglyphs of a monitored domain are part of the
same threat picture as spoofing, but detecting them is a registration-data
problem (zone files, CT, RDAP) rather than an email-configuration one, and it
produces findings about domains the operator does not control.

### End-to-end email security detection (PGP / S-MIME)

A planned capability is to detect whether a domain's users publish end-to-end
message-encryption keys, complementing the transport-level controls above:

- **OpenPGP via keyservers / WKD** — query the Web Key Directory
  (`https://openpgpkey.<domain>/.well-known/openpgpkey/...`, RFC-style
  draft) and public keyservers (e.g. `keys.openpgp.org`) for keys associated
  with the domain, reporting coverage and key strength/expiry.
- **S/MIME** — optionally check for published S/MIME capabilities, including
  SMIMEA records (RFC 8162). Note that SMIMEA names are derived from a hash of
  the local part, so they are discoverable only for addresses already known
  (e.g. the RFC 2142 role mailboxes), never enumerable for a whole domain.

This would add an *end-to-end* scoring dimension separate from the transport
controls. It is **documented here only and intentionally not implemented** in
this release.

### DKIM key-rotation history (BSI TR-03182-03)

BSI TR-03182 requires DKIM key material to be renewed at least every six
months. This cannot be judged from a single DNS snapshot — it needs the key
material (the selector `p=` value) to be tracked over time so that a stale,
unrotated key can be flagged. The scanner already parses key material per
selector; a future feature would persist a per-selector key fingerprint with a
`first_seen` timestamp and raise a finding once a key exceeds the rotation
window. This is **documented here only and intentionally not implemented** in
this release (no schema column is provisioned for it yet).

---

## TODO / not completed in the initial build

- **Group PDF report export** — done (v0.5.0). `reports/pdf_report.py` +
  `GET /app/api/report/{pdf,trend.pdf}` render profile-aware scope and trend
  PDFs (reportlab). HTML export remains optional/not wired.
- **Admin UI for DKIM selectors and scheduled scans** — the backend endpoints
  and scheduler exist; management screens are minimal.
- **Censys parsing coverage** — `scanner/censys_client.py` maps the common
  Search API v2 shapes; verify against your Censys plan's response format.
- **Broader test coverage** — `tests/test_smoke.py` covers scoring, DB
  round-trips, and the app factory; live-DNS integration tests are not included.
- **Rate limiting / caching of passive lookups** for large domain sets.

---

## License

GPL-3.0-or-later. AI-assisted development: portions generated with Claude
(Anthropic).
