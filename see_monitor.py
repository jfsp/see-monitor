#!/usr/bin/env python3
"""
SEE-Monitor: CLI entry point
Loads configuration, runs scans from the command line, and serves the web app.

Usage:
  ./see_monitor.py scan example.com example.org
  ./see_monitor.py scan --list mylist.txt
  ./see_monitor.py serve --host 0.0.0.0 --port 8080
  ./see_monitor.py init-db

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import logging
import os
import sys

import click

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CONFIG_PATHS = [
    os.environ.get("SEE_CONFIG", ""),
    "config/config.yaml",
    "/etc/see-monitor/config.yaml",
]


def load_config() -> dict:
    """Load YAML config from the first path that exists (or {})."""
    try:
        import yaml
    except ImportError:
        yaml = None
    for path in CONFIG_PATHS:
        if path and os.path.exists(path):
            if yaml is None:
                logging.warning("pyyaml not installed; ignoring %s", path)
                return {}
            with open(path, encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
    return {}


def _setup_logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@click.group()
@click.option("-v", "--verbose", is_flag=True,
              help="Debug-level output (per-control detail + service diagnostics).")
@click.pass_context
def cli(ctx, verbose):
    _setup_logging(verbose)
    ctx.obj = {"config": load_config(), "verbose": verbose}


@cli.command("init-db")
@click.pass_context
def init_db(ctx):
    """Create the database schema and default admin user."""
    from data.database import Database
    from auth.store import AuthStore
    cfg = ctx.obj["config"]
    db_path = cfg.get("db_path", "data/see_monitor.db")
    Database(db_path)
    AuthStore(db_path)   # seeds default admin on first run
    click.echo(f"Database initialised at {db_path}")


_CONTROLS = ["spf", "dkim", "dmarc", "starttls", "dnssec", "dane",
             "mta_sts", "tlsrpt", "bimi", "client_tls",
             "dns_hygiene", "reputation", "subdomains"]
_CTRL_LABEL = {"spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC",
               "starttls": "STARTTLS", "dnssec": "DNSSEC", "dane": "DANE",
               "mta_sts": "MTA-STS", "tlsrpt": "TLS-RPT", "bimi": "BIMI",
               "client_tls": "CLIENT-TLS", "dns_hygiene": "DNS-HYG",
               "reputation": "REPUTATION", "subdomains": "SUBDOMAINS"}
_CONFIDENCE_COLOR = {"high": "green", "medium": "yellow", "low": "red"}
_RATING_COLOR = {"not_implemented": "red", "medium": "yellow",
                 "strong": "cyan", "very_strong": "green",
                 "partial": "yellow", "compliant": "green"}


def _glyph(score):
    if score is None:
        return click.style("–", fg="bright_black")
    if score == 0:
        return click.style("✗", fg="red")
    if score < 100:
        return click.style("~", fg="yellow")
    return click.style("✓", fg="green")


def _render_scan(scan: dict, a: dict, verbose: bool,
                 profiles: dict | None = None) -> str:
    checks = scan.get("checks", {})
    svc = scan.get("services", {})
    cs = a.get("control_scores", {})
    L = []
    bar = "━" * 60
    L.append(click.style(f"━━ {a['domain']} ", bold=True)
             + click.style(bar[len(a['domain']) + 4:], fg="bright_black"))

    rating = a["rating"]
    conf = a.get("confidence", "high")
    L.append(f"  Score       {click.style(str(a['score']), bold=True)} / 100   "
             + click.style(f"({rating})", fg=_RATING_COLOR.get(rating))
             + "   evidence: "
             + click.style(conf, fg=_CONFIDENCE_COLOR.get(conf)))

    subs = a.get("subscores") or {}
    if any(v is not None for v in subs.values()):
        cells = []
        for name in ("impersonation", "transport", "resilience"):
            val = subs.get(name)
            cells.append(f"{name} " + ("n/a" if val is None
                                       else click.style(str(val), bold=True)))
        L.append("  Sub-scores  " + "   ".join(cells))

    # Per-profile scores (national conformance profiles)
    if profiles:
        cells = []
        for gid, pa in profiles.items():
            comp = pa.get("compliant")
            mark = ("" if comp is None
                    else click.style(" ✓ compliant", fg="green") if comp
                    else click.style(" ✗ non-compliant", fg="red"))
            cells.append(
                f"{gid} {click.style(str(pa['score']), bold=True)} "
                + click.style(f"({pa['rating']})",
                              fg=_RATING_COLOR.get(pa['rating'])) + mark)
        L.append("  Profiles    " + ("\n              ").join(cells))

    mx = checks.get("mx", {})
    hosts = [m["host"] for m in mx.get("mx_hosts", [])]
    if a.get("no_mail"):
        L.append("  Mail        " + click.style("no inbound mail "
                 "(no MX / null MX) — transport controls n/a", fg="bright_black"))
    else:
        shown = ", ".join(hosts[:4]) + (" …" if len(hosts) > 4 else "")
        L.append(f"  Mail        MX: {len(hosts)}"
                 + (f"  →  {shown}" if hosts else ""))

    # Control glyph line(s)
    cells = [f"{_glyph(cs.get(c))} {_CTRL_LABEL[c]}"
             f"{'' if cs.get(c) is None else ' ' + str(cs.get(c))}"
             for c in _CONTROLS]
    for start in range(0, len(cells), 4):
        prefix = "  Controls    " if start == 0 else "              "
        L.append(prefix + "   ".join(cells[start:start + 4]))

    findings = a.get("findings", [])
    if findings:
        sev = {"critical": 0, "warning": 0, "info": 0}
        for f in findings:
            sev[f.get("severity", "info")] = sev.get(f.get("severity"), 0) + 1
        L.append(f"  Findings    {len(findings)}  ("
                 + click.style(f"{sev['critical']} critical", fg='red') + " · "
                 + click.style(f"{sev['warning']} warning", fg='yellow') + " · "
                 + f"{sev['info']} info)")

    for note in (a.get("confidence_notes") or [])[:4]:
        L.append(click.style(f"  Evidence    {note}", fg="bright_black"))

    # External sources
    L.append("  Sources     " + _render_sources(svc, indent="              "))

    if not verbose:
        return "\n".join(L)

    # ---------------- Debug detail ----------------
    L.append(click.style("  · detail ·", fg="bright_black"))

    def rec(label, value):
        if value:
            L.append(f"    {label:<11} {value}")

    spf = checks.get("spf", {})
    rec("SPF", spf.get("record") or "(none)")
    if spf.get("lookup_count"):
        rec("", f"all={spf.get('all_qualifier')}  lookups={spf.get('lookup_count')}"
            + ("  OVER LIMIT" if spf.get("exceeds_lookup_limit") else ""))

    dkim = checks.get("dkim", {})
    if dkim.get("selectors"):
        for s in dkim["selectors"]:
            rec("DKIM", f"{s['selector']} ({s['source']})  "
                f"{s.get('key_type')}/{s.get('key_bits') or '?'}  "
                + click.style(s['status'],
                              fg=('green' if s['status'] == 'strong'
                                  else 'yellow' if s['status'] == 'weak'
                                  else 'red')))
    else:
        rec("DKIM", "no selectors confirmed")

    dmarc = checks.get("dmarc", {})
    rec("DMARC", dmarc.get("record") or "(none)")

    dnssec = checks.get("dnssec", {})
    rec("DNSSEC", f"signed={dnssec.get('signed')} "
        f"validated={dnssec.get('validated')}")

    dane = checks.get("dane", {})
    if dane.get("applicable"):
        rec("DANE", f"coverage={dane.get('coverage')} usable={dane.get('usable')}")

    sts = checks.get("mta_sts", {})
    if sts.get("present"):
        rec("MTA-STS", f"mode={sts.get('mode')} fetched={sts.get('policy_fetched')}")

    st = checks.get("starttls", {})
    for host, v in (st.get("hosts", {}) or {}).items():
        flag = click.style(" WEAK-TLS", fg="red") if v.get("weak_tls") else ""
        rec("STARTTLS", f"{host}: {'ok' if v.get('starttls_ok') else 'no'} "
            f"{v.get('tls_version') or ''} via {v.get('source')}{flag}")

    intel = (checks.get("intel", {}) or {}).get("securitytrails", {})
    if intel.get("mail_hosts"):
        rec("ST mail", ", ".join(intel["mail_hosts"][:8]))

    # per-service diagnostics with errors
    for name in ("shodan", "censys", "active_smtp", "dnsdumpster",
                 "securitytrails"):
        s = svc.get(name, {})
        if s.get("error"):
            rec(name, click.style(f"error: {s['error']}", fg="red"))

    for f in findings:
        col = {"critical": "red", "warning": "yellow"}.get(f["severity"])
        L.append(f"    {click.style('•', fg=col)} "
                 f"[{f['control']}] {f['message']}")

    return "\n".join(L)


def _render_sources(svc: dict, indent: str) -> str:
    parts = []
    st = svc.get("securitytrails", {})
    if st.get("available"):
        if st.get("error"):
            parts.append(click.style(f"SecurityTrails: {st['error']}", fg="red"))
        else:
            parts.append(f"SecurityTrails: MX×{st.get('mx', 0)}, "
                         f"{st.get('selectors', 0)} selectors, "
                         f"{st.get('subdomains', 0)} subdomains")
    dd = svc.get("dnsdumpster", {})
    if dd.get("available"):
        if dd.get("error"):
            parts.append(click.style(f"DNSDumpster: {dd['error']}", fg="red"))
        else:
            parts.append(f"DNSDumpster: {dd.get('selectors', 0)} selectors")
    for key, lbl in (("shodan", "Shodan"), ("censys", "Censys")):
        s = svc.get(key, {})
        if s.get("available"):
            parts.append(f"{lbl}: STARTTLS {s.get('mx_covered', 0)}/"
                         f"{s.get('mx_total', 0)} MX")
    act = svc.get("active_smtp", {})
    if act.get("used"):
        parts.append(f"active SMTP: {act.get('mx_covered', 0)}/"
                     f"{act.get('mx_total', 0)} MX")
    if not parts:
        return click.style("none configured (DNS + wordlist only)",
                           fg="bright_black")
    # first item inline, rest indented on new lines
    return ("\n" + indent).join(parts)


@cli.command()
@click.argument("domains", nargs=-1)
@click.option("--list", "list_file", type=click.Path(exists=True),
              help="File with one domain per line.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON only.")
@click.option("-q", "--quiet", is_flag=True,
              help="One terse line per domain (score + rating).")
@click.option("-v", "--verbose", "verbose_opt", is_flag=True,
              help="Debug detail: records, per-MX STARTTLS, findings, "
                   "service diagnostics.")
@click.option("--profile", "profiles_opt", multiple=True,
              help="Conformance profile(s) to score against (repeatable). "
                   "Default: all installed. e.g. --profile bsi_tr03182")
@click.option("--rescan-all", "rescan_all", is_flag=True,
              help="Rescan every domain already known to the database "
                   "(domain lists, past assessments, organisation "
                   "assignments). Use after upgrading to pick up new checks.")
@click.pass_context
def scan(ctx, domains, list_file, as_json, quiet, verbose_opt, profiles_opt,
         rescan_all):
    """Scan and assess one or more domains.

    Default output is a per-domain summary showing what was found and which
    external services (SecurityTrails, DNSDumpster, Shodan, Censys) were used.
    Add -v for full per-control detail and service diagnostics; --quiet for a
    single line per domain; --json for machine-readable output.
    """
    from data.database import Database, DEFAULT_GUIDELINE_ID
    from scanner.orchestrator import ScanOrchestrator
    from scanner.assessor import assess_all_profiles, available_guidelines

    cfg = ctx.obj["config"]
    # -v works whether given before the subcommand (group level) or after it.
    verbose = bool(ctx.obj.get("verbose", False) or verbose_opt)
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    targets = list(domains)
    if list_file:
        with open(list_file, encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh if ln.strip()
                        and not ln.startswith("#")]
    targets = [d.strip().lower().rstrip(".") for d in targets if d.strip()]

    db = Database(cfg.get("db_path", "data/see_monitor.db"))
    if rescan_all:
        known = db.get_all_known_domains()
        if not known:
            raise click.UsageError(
                "--rescan-all: the database contains no domains yet.")
        targets = sorted(set(targets) | set(known))
    if not targets:
        raise click.UsageError(
            "No domains supplied. Pass domains, --list FILE or --rescan-all.")

    orch = ScanOrchestrator(cfg, db=db)

    if not as_json and not quiet:
        active = [n for n, s in (
            ("SecurityTrails", orch.securitytrails), ("DNSDumpster", orch.dnsdumpster),
            ("Shodan", orch.shodan), ("Censys", orch.censys)) if s.available]
        click.echo("Scanning {} domain(s). External sources: {}".format(
            len(targets),
            ", ".join(active) if active else "none (authoritative DNS + wordlist)"))
        click.echo()

    gids = list(profiles_opt) or available_guidelines()
    if DEFAULT_GUIDELINE_ID in gids:
        primary_id = DEFAULT_GUIDELINE_ID
    else:
        primary_id = gids[0]

    run_id = db.create_run(targets, trigger="cli")
    results = []
    for d in targets:
        scan_res = orch.scan_domain(d)
        db.save_scan_result(run_id, scan_res)
        assessments = assess_all_profiles(scan_res, cfg, gids)
        for gid, a in assessments.items():
            db.save_assessment(run_id, a)
        db.bump_run_progress(run_id)
        primary = assessments.get(primary_id) or next(iter(assessments.values()))
        results.append({"domain": d, "primary": primary_id,
                        "assessments": assessments})
        if as_json:
            continue
        if quiet:
            profs = "  ".join(
                f"{gid}={pa['score']}/{pa['rating']}"
                for gid, pa in assessments.items())
            click.echo(f"{d:<32} {profs}")
        else:
            others = {g: pa for g, pa in assessments.items() if g != primary_id}
            click.echo(_render_scan(scan_res, primary, verbose,
                                    profiles=others or None))
            click.echo()
    db.finish_run(run_id)
    if as_json:
        click.echo(json.dumps(results, indent=2))


@cli.command("scheduler-daemon")
@click.pass_context
def scheduler_daemon(ctx):
    """Run the periodic-scan scheduler in the foreground (for systemd)."""
    import time
    from data.database import Database
    from scanner.orchestrator import ScanOrchestrator
    from scheduler.scan_scheduler import ScanScheduler
    cfg = ctx.obj["config"]
    db = Database(cfg.get("db_path", "data/see_monitor.db"))
    orch = ScanOrchestrator(cfg, db=db)
    sched = ScanScheduler(orch, db, config=cfg)
    sched.start()
    click.echo(f"Scheduler running (schedule reload every "
               f"{sched.reload_minutes} min). Ctrl-C to stop.")
    try:
        while True:
            time.sleep(max(60, sched.reload_minutes * 60))
            # Pick up schedules added or removed by another process (e.g.
            # scripts/schedule_audit.py) without needing a service restart.
            sched.reload()
    except KeyboardInterrupt:
        sched.stop()


@cli.command("schedules")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON only.")
@click.option("--create-weekly", is_flag=True,
              help="Create/refresh one auto-managed list of every known "
                   "domain, driven by a single weekly schedule (idempotent).")
@click.option("--interval-hours", default=None, type=int,
              help="Interval for --create-weekly (default 168 = weekly).")
@click.option("--dry-run", is_flag=True,
              help="With --create-weekly, report what would change and exit.")
@click.pass_context
def schedules(ctx, as_json, create_weekly, interval_hours, dry_run):
    """Audit periodic scan schedules against the domains in the database.

    Reports which schedules exist, which domains they cover, and which known
    domains are in no enabled schedule and are therefore never rescanned.
    With --create-weekly, closes that gap.
    """
    import json as _json
    from data.database import Database
    from scheduler.schedule_audit import (audit_schedules,
                                          create_weekly_all_domains,
                                          DEFAULT_INTERVAL_HOURS)
    cfg = ctx.obj["config"]
    db = Database(cfg.get("db_path", "data/see_monitor.db"))

    action = None
    if create_weekly:
        action = create_weekly_all_domains(
            db, interval_hours or DEFAULT_INTERVAL_HOURS, dry_run=dry_run)

    report = audit_schedules(db)
    if as_json:
        payload = {"audit": report}
        if action:
            payload["action"] = action
        click.echo(_json.dumps(payload, indent=2))
        return

    click.echo(click.style("Scheduled scans", bold=True))
    if not report["schedules"]:
        click.echo(click.style("  none configured", fg="red"))
    for sc in report["schedules"]:
        state = (click.style("enabled", fg="green") if sc["enabled"]
                 else click.style("disabled", fg="red"))
        click.echo(f"  [{sc['id']}] {sc['name']}  ({state}, "
                   f"every {sc['interval_hours']}h)")
        click.echo(f"      list: {sc['list_name'] or '<missing>'} "
                   f"({sc['domain_count']} domain(s))")
        click.echo(f"      last: {sc['last_run_at'] or 'never'}   "
                   f"next: {sc['next_run_at'] or 'unknown'}")
        for problem in sc["problems"]:
            click.echo(click.style(f"      ! {problem}", fg="yellow"))

    cov = report["coverage"]
    pct = "n/a" if cov is None else f"{cov * 100:.0f}%"
    colour = "green" if cov == 1 else ("yellow" if cov else "red")
    click.echo("")
    click.echo(click.style("Coverage", bold=True))
    click.echo(f"  {len(report['covered'])} of {report['known_domains']} "
               f"known domain(s) covered  ("
               + click.style(pct, fg=colour) + ")")
    if report["uncovered"]:
        shown = ", ".join(report["uncovered"][:10])
        more = ("" if len(report["uncovered"]) <= 10
                else f"  (+{len(report['uncovered']) - 10} more)")
        click.echo(click.style(f"  never rescanned: {shown}{more}", fg="red"))
    if report["duplicated"]:
        click.echo(click.style(
            f"  {len(report['duplicated'])} domain(s) in multiple schedules",
            fg="yellow"))

    if report["problems"]:
        click.echo("")
        click.echo(click.style("Problems", bold=True))
        for problem in report["problems"]:
            click.echo(click.style(f"  ! {problem}", fg="yellow"))
    if report["recommendations"] and not create_weekly:
        click.echo("")
        click.echo(click.style("Recommendations", bold=True))
        for rec in report["recommendations"]:
            click.echo(f"  → {rec}")

    if action:
        click.echo("")
        head = "Would apply" if action["dry_run"] else "Applied"
        click.echo(click.style(head, bold=True))
        click.echo(f"  list      {action['list_action']} "
                   f"({action['domains']} domain(s))")
        click.echo(f"  schedule  {action['schedule_action']}")
        if action["added"]:
            click.echo(f"  added     {len(action['added'])}: "
                       + ", ".join(action["added"][:8]))
        if action["removed"]:
            click.echo(f"  removed   {len(action['removed'])}: "
                       + ", ".join(action["removed"][:8]))
        for note in action["notes"]:
            click.echo(click.style(f"  note      {note}", fg="bright_black"))


@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8080, type=int)
@click.pass_context
def serve(ctx, host, port):
    """Run the web application (development server)."""
    from app_factory import create_app
    app = create_app(ctx.obj["config"])
    click.echo(f"SEE-Monitor serving on http://{host}:{port}")
    app.run(host=host, port=port)


if __name__ == "__main__":
    cli()
