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
| SPF      | RFC 7208 / SP 800-177r1 §4.4    | Record presence, `all` qualifier, lookup-limit (≤10) |
| DKIM     | RFC 6376 / SP 800-177r1 §4.5    | Selectors (wordlist **+** per-domain registered), key type/size, testing flag |
| DMARC    | RFC 7489 / SP 800-177r1 §4.6    | Policy, `pct`, subdomain policy, aggregate reporting |
| STARTTLS | RFC 3207 / SP 800-177r1 §5.1    | Per-MX support, negotiated TLS version |
| DNSSEC   | RFC 4033-4035 / §4.1-4.2        | DS + DNSKEY, AD-flag validation |
| DANE     | RFC 7672 / SP 800-177r1 §5.2    | TLSA per MX, usability (requires valid DNSSEC) |
| MTA-STS  | RFC 8461                        | TXT record + HTTPS policy, mode, MX coverage |
| TLS-RPT  | RFC 8460                        | Record presence, `rua` destination |
| BIMI     | industry practice               | Record presence, Verified Mark Certificate |

### Scanning strategy

STARTTLS evidence is gathered **passive-first**: Shodan is consulted first,
then Censys as an alternative (both via API). An active, non-intrusive SMTP
STARTTLS probe (EHLO → STARTTLS → handshake → QUIT) is used as a fallback only
when passive sources have no data and `scanning.active_smtp` is enabled. All
other checks are ordinary DNS/HTTPS lookups.

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

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp config/config.yaml.example config/config.yaml   # then edit
python see_monitor.py init-db                       # creates schema + admin

# scan from the CLI
python see_monitor.py scan example.com example.org
python see_monitor.py scan --list domains.txt --json

# run the web app (dev server)
python see_monitor.py serve --host 127.0.0.1 --port 8080
```

Default admin credentials on first run are `admin` / `changeme123` —
**change these immediately**.

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
guidelines/           NIST SP 800-177r1 scoring definition
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
2. **DNSDumpster (optional)** — if `dnsdumpster.api_key` is set, SEE-Monitor
   harvests `<selector>._domainkey.<domain>` names observed by DNSDumpster
   (this reliably catches ESP CNAME-delegated selectors such as Microsoft
   365's `selector1`/`selector2`).
3. **Common-selector wordlist** — built-in ESP defaults.

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
