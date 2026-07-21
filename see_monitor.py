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
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@click.group()
@click.option("-v", "--verbose", is_flag=True)
@click.pass_context
def cli(ctx, verbose):
    _setup_logging(verbose)
    ctx.obj = {"config": load_config()}


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


@cli.command()
@click.argument("domains", nargs=-1)
@click.option("--list", "list_file", type=click.Path(exists=True),
              help="File with one domain per line.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def scan(ctx, domains, list_file, as_json):
    """Scan and assess one or more domains."""
    from data.database import Database
    from scanner.orchestrator import ScanOrchestrator
    from scanner.assessor import assess_domain

    cfg = ctx.obj["config"]
    targets = list(domains)
    if list_file:
        with open(list_file, encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh if ln.strip()
                        and not ln.startswith("#")]
    targets = [d.strip().lower().rstrip(".") for d in targets if d.strip()]
    if not targets:
        raise click.UsageError("No domains supplied.")

    db = Database(cfg.get("db_path", "data/see_monitor.db"))
    orch = ScanOrchestrator(cfg, db=db)
    run_id = db.create_run(targets, trigger="cli")
    results = []
    for d in targets:
        scan_res = orch.scan_domain(d)
        db.save_scan_result(run_id, scan_res)
        a = assess_domain(scan_res, cfg)
        db.save_assessment(run_id, a)
        db.bump_run_progress(run_id)
        results.append(a)
        if not as_json:
            click.echo(f"{d:<40} {a['score']:>5}  {a['rating']}")
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
    click.echo("Scheduler running. Ctrl-C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        sched.stop()


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
