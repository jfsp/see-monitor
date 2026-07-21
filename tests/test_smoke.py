#!/usr/bin/env python3
"""
SEE-Monitor: Smoke tests
Offline tests that exercise scoring, DB round-trips, the app factory and the
core API without touching the network. Run with:  python -m pytest -q

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data.database import Database          # noqa: E402
from scanner.assessor import assess_domain  # noqa: E402
from scanner.mx_resolver import normalise_mx_host  # noqa: E402


def _strong_scan(domain="example.com"):
    return {"domain": domain, "scanned_at": "2026-01-01T00:00:00Z", "checks": {
        "mx": {"has_mx": True, "null_mx": False,
               "mx_hosts": [{"host": "mx.example.com", "priority": 10}],
               "invalid_records": []},
        "spf": {"present": True, "valid": True, "all_qualifier": "-",
                "records": ["v=spf1 -all"], "issues": []},
        "dkim": {"present": True, "best_status": "strong", "any_testing": False,
                 "selectors": [{"selector": "s1", "status": "strong",
                                "key_type": "rsa", "key_bits": 2048,
                                "source": "registered", "revoked": False,
                                "testing": False}], "issues": []},
        "dmarc": {"present": True, "valid": True, "policy": "reject",
                  "pct": 100, "rua": ["mailto:r@example.com"],
                  "subdomain_policy": "reject", "issues": []},
        "dnssec": {"signed": True, "validated": True, "issues": []},
        "dane": {"applicable": True, "mx_with_tlsa": [{"mx": "mx.example.com"}],
                 "mx_without_tlsa": [], "coverage": 1.0, "usable": True,
                 "issues": []},
        "mta_sts": {"present": True, "policy_fetched": True, "mode": "enforce",
                    "mx_covered": True, "issues": []},
        "tlsrpt": {"present": True, "rua": ["mailto:t@example.com"],
                   "issues": []},
        "starttls": {"applicable": True, "supported_count": 1, "total": 1,
                     "coverage": 1.0, "all_starttls": True,
                     "any_weak_tls": False, "hosts": {}, "issues": []},
        "bimi": {"present": True, "vmc_url": "https://x/vmc.pem", "issues": []},
    }}


def test_mx_normalisation():
    assert normalise_mx_host("10 mx.example.com.") == "mx.example.com"
    assert normalise_mx_host(".") is None
    assert normalise_mx_host("not a host") is None


def test_very_strong():
    a = assess_domain(_strong_scan())
    assert a["score"] == 100.0
    assert a["rating"] == "very_strong"


def test_empty_domain_scores_zero():
    scan = {"domain": "void.example", "scanned_at": "2026-01-01T00:00:00Z",
            "checks": {"mx": {"has_mx": False, "null_mx": False,
                              "mx_hosts": [], "invalid_records": []}}}
    a = assess_domain(scan)
    assert a["rating"] == "not_implemented"
    # transport controls should be n/a for a domain with no MX
    assert a["control_scores"]["starttls"] is None


def test_null_mx_transport_na():
    scan = _strong_scan()
    scan["checks"]["mx"] = {"has_mx": False, "null_mx": True,
                            "mx_hosts": [], "invalid_records": []}
    a = assess_domain(scan)
    assert a["no_mail"] is True
    assert a["control_scores"]["dane"] is None


def test_weight_override_changes_score():
    scan = _strong_scan()
    scan["checks"]["dmarc"]["policy"] = "none"
    scan["checks"]["dmarc"]["rua"] = []
    base = assess_domain(scan)["score"]
    heavy = assess_domain(scan, {"scoring": {"weights": {"dmarc": 0.9}}})["score"]
    assert heavy < base  # heavier weight on a failing control lowers the score


def test_db_roundtrip():
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    scan = _strong_scan()
    a = assess_domain(scan)
    run_id = db.create_run(["example.com"])
    db.save_scan_result(run_id, scan)
    db.save_assessment(run_id, a)
    db.finish_run(run_id)
    latest = db.get_latest_assessments()
    assert len(latest) == 1
    assert latest[0]["domain"] == "example.com"
    assert latest[0]["control_scores"]["dmarc"] == 100
    stats = db.get_summary_stats()
    assert stats["total_domains"] == 1
    assert stats["ratings"]["very_strong"] == 1


def test_app_factory_and_login():
    os.environ["SEE_SECRET_KEY"] = "x" * 32
    path = tempfile.mktemp(suffix=".db")
    from app_factory import create_app
    app = create_app({"db_path": path, "scanning": {"active_smtp": False}})
    client = app.test_client()
    assert client.get("/api/version").status_code == 200
    r = client.post("/login", data={"username": "admin",
                                     "password": "changeme123"})
    assert r.status_code in (302, 303)
    assert client.get("/app/api/summary").status_code == 200


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
