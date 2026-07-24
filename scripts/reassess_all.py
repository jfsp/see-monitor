#!/usr/bin/env python3
"""
SEE-Monitor: Re-assess all domains
Re-runs the scoring engine over the most recent raw scan of every domain,
without re-querying DNS. Use this after changing scoring weights or rating
bands in guidelines/nist_800_177r1.json or config.yaml.

Usage:  python scripts/reassess_all.py [--config config/config.yaml]

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data.database import Database                       # noqa: E402
from scanner.assessor import (assess_all_profiles,        # noqa: E402
                              available_guidelines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/config.yaml")
    ap.add_argument("--profile", action="append", default=None,
                    help="Limit to specific guideline profile(s); repeatable. "
                         "Default: all installed profiles.")
    args = ap.parse_args()

    cfg = {}
    if os.path.exists(args.config):
        import yaml
        with open(args.config, encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}

    gids = args.profile or available_guidelines()
    db = Database(cfg.get("db_path", "data/see_monitor.db"))
    domains = db.get_all_known_domains()
    run_id = db.create_run(domains, trigger="reassess")
    n = 0
    for domain in domains:
        scans = db.get_domain_scans(domain, limit=1)
        if not scans:
            continue
        scan = {"domain": domain,
                "scanned_at": scans[0]["scanned_at"],
                "checks": scans[0]["checks"]}
        for a in assess_all_profiles(scan, cfg, gids).values():
            db.save_assessment(run_id, a)
        db.bump_run_progress(run_id)
        n += 1
    db.finish_run(run_id)
    print(f"Re-assessed {n} domain(s) x {len(gids)} profile(s) into run {run_id}.")


if __name__ == "__main__":
    main()
