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
| SPF      | RFC 7208 / SP 800-177r1 §4.4    | Record presence, `all` qualifier + ordering, `ptr`, ip-vs-name, deny-all, lookup-limit (≤10) |
| DKIM     | RFC 6376 / SP 800-177r1 §4.5    | Selectors (wordlist **+** per-domain registered), key type/size, RSA≤2048, Ed25519 presence, SHA-1, testing flag |
| DMARC    | RFC 7489 / SP 800-177r1 §4.6    | Policy, `pct`, subdomain policy, strict alignment, `rua`/`ruf`, external-report domains |
| STARTTLS | RFC 3207 / SP 800-177r1 §5.1    | Per-MX support, negotiated TLS version |
| CLIENT-TLS | RFC 6186 / CCN-CERT BP/02      | Submission/retrieval TLS (587/465/993/995) discovered via SRV (n/a if not advertised) |
| DNSSEC   | RFC 4033-4035 / §4.1-4.2        | DS + DNSKEY, AD-flag validation, `_dmarc` policy-zone AD |
| DANE     | RFC 7672 / SP 800-177r1 §5.2    | TLSA per MX, usability (requires valid DNSSEC) |
| MTA-STS  | RFC 8461                        | TXT record + HTTPS policy, mode, MX coverage |
| TLS-RPT  | RFC 8460                        | Record presence, `rua` destination |
| BIMI     | industry practice               | Record presence, Verified Mark Certificate |

### Scanning strategy

STARTTLS evidence is gathered **passive-first**: Shodan is consulted first,
then Censys as an alternative (both via API). An active, non-intrusive SMTP
STARTTLS probe (EHLO → STARTTLS → handshake → QUIT) is used as a fallback only
when passive sources have no data and `scanning.active_smtp` is enabled.

DKIM selectors are discovered from **SecurityTrails** and **DNSDumpster** when
API keys are configured (see below), in addition to per-domain registered
selectors and the common-selector wordlist. All other checks are ordinary
DNS/HTTPS lookups. Every passive result — MX cross-checks and every DKIM
selector alike — is re-confirmed against authoritative DNS before it can affect
scoring; passive sources never feed the score directly.

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

### End-to-end email security detection (PGP / S-MIME)

A planned capability is to detect whether a domain's users publish end-to-end
message-encryption keys, complementing the transport-level controls above:

- **OpenPGP via keyservers / WKD** — query the Web Key Directory
  (`https://openpgpkey.<domain>/.well-known/openpgpkey/...`, RFC-style
  draft) and public keyservers (e.g. `keys.openpgp.org`) for keys associated
  with the domain, reporting coverage and key strength/expiry.
- **S/MIME** — optionally check for published S/MIME capabilities.

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

- **Group PDF/HTML report export** — the API and CSV/JSON exporters exist
  (`reports/report_generator.py`); a formatted PDF export is not yet wired up.
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
