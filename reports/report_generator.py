#!/usr/bin/env python3
"""
SEE-Monitor: Report Generator
Exports the latest assessments as CSV or JSON for offline analysis.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import csv
import io
import json

CONTROLS = ["spf", "dkim", "dmarc", "starttls", "dnssec", "dane",
            "mta_sts", "tlsrpt", "bimi"]


def export_json(assessments: list[dict]) -> str:
    return json.dumps(assessments, indent=2)


def export_csv(assessments: list[dict]) -> str:
    buf = io.StringIO()
    fields = ["domain", "score", "rating", "no_mail", "assessed_at"] + CONTROLS
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for a in assessments:
        row = {
            "domain": a.get("domain"),
            "score": a.get("score"),
            "rating": a.get("rating"),
            "no_mail": a.get("no_mail"),
            "assessed_at": a.get("assessed_at"),
        }
        cs = a.get("control_scores", {})
        for c in CONTROLS:
            v = cs.get(c)
            row[c] = "" if v is None else v
        writer.writerow(row)
    return buf.getvalue()


def export_findings_csv(assessments: list[dict]) -> str:
    """One row per finding across all domains."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["domain", "control", "severity", "message"])
    for a in assessments:
        for f in a.get("findings", []):
            writer.writerow([a.get("domain"), f.get("control"),
                             f.get("severity"), f.get("message")])
    return buf.getvalue()
