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


def test_dnsdumpster_selector_extraction():
    from scanner.dnsdumpster_client import extract_selectors, DNSDumpsterClient
    payload = {
        "cname": [
            {"host": "selector1._domainkey.example.com",
             "target": "selector1-example-com._domainkey.example.onmicrosoft.com"},
        ],
        "txt": ['k3._domainkey.example.com "v=DKIM1; p=..."'],
        "foreign": [{"host": "sel._domainkey.sub.example.com"}],
    }
    sels = set(extract_selectors(payload, "example.com"))
    assert sels == {"selector1", "k3"}          # host + txt captured
    assert "selector1-example-com" not in sels  # CNAME target ignored
    assert "sel" not in sels                     # different zone ignored
    # No API key => discovery is a safe no-op
    assert DNSDumpsterClient(None).discover_selectors("example.com") == []


def test_dkim_confirms_passive_selector():
    """A DNSDumpster-discovered selector must still be TXT-confirmed."""
    from scanner import dkim_check

    class FakeDNS:
        def txt(self, name):
            if name == "odd-selector._domainkey.example.com":
                return ["v=DKIM1; k=rsa; p=" + "A" * 400]  # ~2048-bit-ish
            return []

    res = dkim_check.check_dkim("example.com", registered_selectors=[],
                                dns_client=FakeDNS(), use_wordlist=False,
                                passive_selectors=["odd-selector"])
    assert res["present"] is True
    assert res["selectors"][0]["selector"] == "odd-selector"
    assert res["selectors"][0]["source"] == "dnsdumpster"


def test_securitytrails_selector_extraction():
    from scanner.securitytrails_client import (
        _extract_selectors, SecurityTrailsClient)
    subs = ["www", "mail", "selector1._domainkey", "s2._domainkey",
            "autodiscover", "k3._domainkey.mkt"]
    sels = set(_extract_selectors(subs))
    assert sels == {"selector1", "s2", "k3"}
    # No key => safe no-op
    st = SecurityTrailsClient(None)
    assert st.available is False
    g = st.gather("example.com")
    assert g["available"] is False and g["selectors"] == []


def test_cli_scan_renderer():
    import see_monitor
    scan = {"domain": "example.com", "scanned_at": "2026-01-01T00:00:00Z",
            "checks": {"mx": {"has_mx": True, "null_mx": False,
                              "mx_hosts": [{"host": "mx.example.com",
                                            "priority": 10}]},
                       "dmarc": {"record": "v=DMARC1; p=reject"}},
            "services": {
                "securitytrails": {"available": True, "mx": 1, "selectors": 3,
                                   "subdomains": 40, "error": None},
                "dnsdumpster": {"available": True, "selectors": 2, "error": None},
                "shodan": {"available": False}, "censys": {"available": False},
                "active_smtp": {"used": True, "mx_covered": 1, "mx_total": 1}}}
    a = {"domain": "example.com", "score": 72.0, "rating": "strong",
         "no_mail": False, "control_scores": {c: 80 for c in see_monitor._CONTROLS},
         "findings": [{"control": "spf", "severity": "warning", "message": "x"}]}
    basic = see_monitor._render_scan(scan, a, verbose=False)
    assert "example.com" in basic
    assert "SecurityTrails: MX×1, 3 selectors" in basic
    assert "DNSDumpster: 2 selectors" in basic
    # debug view adds the DMARC record and the finding line
    debug = see_monitor._render_scan(scan, a, verbose=True)
    assert "v=DMARC1; p=reject" in debug
    assert "detail" in debug


def test_spf_ordering_and_denyall():
    from scanner import spf_check

    class FakeDNS:
        def __init__(self, rec):
            self.rec = rec

        def txt(self, name):
            return [self.rec] if name == "d.example" else []

    bad = spf_check.check_spf("d.example",
                              FakeDNS("v=spf1 -all include:x.example"))
    assert bad["all_is_last"] is False
    assert any("not the last" in i for i in bad["issues"])

    deny = spf_check.check_spf("d.example", FakeDNS("v=spf1 -all"))
    assert deny["deny_all"] is True

    ptr = spf_check.check_spf("d.example", FakeDNS("v=spf1 ptr -all"))
    assert ptr["uses_ptr"] is True


def test_dkim_dual_algorithm_and_bounds():
    from scanner import dkim_check

    class FakeDNS:
        def txt(self, name):
            if name == "rsa._domainkey.d.example":
                return ["v=DKIM1; k=rsa; p=" + "A" * 400]        # ~2048
            if name == "big._domainkey.d.example":
                return ["v=DKIM1; k=rsa; h=sha1:sha256; p=" + "A" * 720]  # >2048
            if name == "ed._domainkey.d.example":
                return ["v=DKIM1; k=ed25519; p=" + "B" * 43]
            return []

    r = dkim_check.check_dkim(
        "d.example", registered_selectors=["rsa", "big", "ed"],
        dns_client=FakeDNS(), use_wordlist=False)
    assert r["has_rsa"] and r["has_ed25519"]
    assert set(r["algorithms"]) == {"rsa", "ed25519"}
    assert r["any_oversized_rsa"] is True
    assert r["any_sha1_hash"] is True


def test_dmarc_strict_ruf_external():
    from scanner import dmarc_check

    class FakeDNS:
        def txt(self, name):
            if name == "_dmarc.d.example":
                return ["v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; "
                        "rua=mailto:agg@thirdparty.net; ruf=mailto:f@d.example"]
            return []

    r = dmarc_check.check_dmarc("d.example", FakeDNS())
    assert r["strict_alignment"] is True
    assert r["has_ruf"] is True
    assert r["external_rua_domains"] == ["thirdparty.net"]
    assert r["external_ruf_domains"] == []       # same org


def _profile_scan(**over):
    """A fully-compliant scan; override individual checks to break a profile."""
    scan = _strong_scan("p.example")
    scan["checks"]["spf"].update(all_is_last=True, uses_ptr=False,
                                 deny_all=False)
    scan["checks"]["dkim"].update(has_rsa=True, has_ed25519=True,
                                  any_oversized_rsa=False, any_sha1_hash=False)
    scan["checks"]["dmarc"].update(strict_alignment=True, has_ruf=False,
                                   subdomain_policy="reject")
    for control, patch in over.items():
        scan["checks"].setdefault(control, {}).update(patch)
    return scan


def test_bsi_profile_gating():
    from scanner.assessor import assess_domain
    ok = assess_domain(_profile_scan(), guideline_id="bsi_tr03182")
    assert ok["compliant"] is True and ok["rating"] == "compliant"
    # Missing Ed25519 => BSI non-compliant, demoted below the top band
    bad = assess_domain(_profile_scan(dkim={"has_ed25519": False}),
                        guideline_id="bsi_tr03182")
    assert bad["compliant"] is False
    assert bad["rating"] != "compliant"
    assert any("Ed25519" in f["message"] for f in bad["findings"])


def test_acn_requires_ruf_bsi_forbids_it():
    from scanner.assessor import assess_domain
    scan = _profile_scan(dmarc={"has_ruf": True})          # ruf present
    acn = assess_domain(scan, guideline_id="acn_email")
    bsi = assess_domain(scan, guideline_id="bsi_tr03182")
    assert acn["compliance"]["dmarc_ruf"] is True          # ACN satisfied
    assert bsi["compliance"]["dmarc_no_ruf"] is False       # BSI violated
    assert bsi["compliant"] is False


def test_client_tls_na_does_not_block_ccn():
    from scanner.assessor import assess_domain
    scan = _profile_scan()          # no client_tls key => not applicable
    ccn = assess_domain(scan, guideline_id="ccn_cert_bp02")
    assert ccn["control_scores"]["client_tls"] is None
    assert ccn["compliance"]["client_tls_all"] is None      # n/a, not blocking
    assert ccn["compliant"] is True


def test_multiprofile_db_roundtrip():
    from scanner.assessor import assess_domain
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    scan = _profile_scan()
    run_id = db.create_run(["p.example"])
    db.save_scan_result(run_id, scan)
    for gid in ("nist_800_177r1", "bsi_tr03182", "acn_email"):
        db.save_assessment(run_id, assess_domain(scan, guideline_id=gid))
    db.finish_run(run_id)

    assert set(db.get_guidelines_present()) >= {
        "nist_800_177r1", "bsi_tr03182", "acn_email"}
    # default guideline filter returns exactly one row per domain
    nist = db.get_latest_assessments()
    assert len(nist) == 1 and nist[0]["guideline"] == "nist_800_177r1"
    bsi = db.get_latest_assessments(guideline="bsi_tr03182")
    assert len(bsi) == 1 and bsi[0]["guideline"] == "bsi_tr03182"
    # across-all view returns one row per (domain, guideline)
    allp = db.get_latest_assessments(guideline=None)
    assert len({a["guideline"] for a in allp}) == 3


def _mk_assessment(domain, ts, score, rating, gid="nist_800_177r1"):
    return {"domain": domain, "assessed_at": ts, "guideline": gid,
            "score": score, "rating": rating, "no_mail": False,
            "control_scores": {"spf": score}, "findings": []}


def test_timeline_bucketing():
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    run = db.create_run(["a.com", "b.com"])
    for d, ts, sc, rt in [
        ("a.com", "2026-06-01T10:00:00+00:00", 40, "medium"),
        ("b.com", "2026-06-02T10:00:00+00:00", 20, "not_implemented"),
        ("a.com", "2026-06-09T10:00:00+00:00", 70, "strong"),
        ("a.com", "2026-07-01T10:00:00+00:00", 90, "very_strong"),
    ]:
        db.save_assessment(run, _mk_assessment(d, ts, sc, rt))
    db.finish_run(run)

    weekly = db.get_timeline(["a.com", "b.com"], "nist_800_177r1", "weekly")
    labels = [b["label"] for b in weekly]
    assert labels == ["2026-W23", "2026-W24", "2026-W27"]   # chronological
    assert weekly[0]["avg_score"] == 30.0                   # mean of 40 & 20
    assert weekly[0]["scans"] == 2 and weekly[0]["domains"] == 2
    assert weekly[0]["ratings"] == {"medium": 1, "not_implemented": 1}

    monthly = db.get_timeline(None, "nist_800_177r1", "monthly")
    assert [b["label"] for b in monthly] == ["Jun 2026", "Jul 2026"]
    assert monthly[0]["scans"] == 3

    # scope filter honoured
    only_a = db.get_timeline(["a.com"], "nist_800_177r1", "monthly")
    assert only_a[0]["domains"] == 1


def test_timeline_and_guidelines_api():
    os.environ["SEE_SECRET_KEY"] = "y" * 32
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    run = db.create_run(["a.com"])
    db.save_assessment(run, _mk_assessment(
        "a.com", "2026-06-09T10:00:00+00:00", 80, "compliant", "bsi_tr03182"))
    db.finish_run(run)

    from app_factory import create_app
    app = create_app({"db_path": path, "scanning": {"active_smtp": False}})
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "changeme123"})

    gl = client.get("/app/api/guidelines").get_json()
    by_id = {g["id"]: g for g in gl}
    assert by_id["nist_800_177r1"]["bands"]                 # bands exposed
    assert len(by_id["bsi_tr03182"]["bands"]) == 3
    assert by_id["bsi_tr03182"]["has_data"] is True

    tl = client.get(
        "/app/api/timeline?period=quarterly&guideline=bsi_tr03182").get_json()
    assert tl["period"] == "quarterly"
    assert tl["buckets"][0]["ratings"] == {"compliant": 1}


def test_pdf_reports_generate():
    import pytest
    pytest.importorskip("reportlab")
    from reports.pdf_report import (
        build_scope_report_pdf, build_trend_report_pdf)
    bands = [{"rating": "not_implemented", "min_score": 0, "color": "#d64545"},
             {"rating": "partial", "min_score": 40, "color": "#e0a030"},
             {"rating": "compliant", "min_score": 80, "color": "#3aa76d"}]
    meta = {"scope_label": "org: X", "guideline_id": "bsi_tr03182",
            "guideline_name": "BSI TR-03182", "generated_at": "2026-07-22",
            "total": 2, "avg_score": 55.0,
            "ratings": {"compliant": 1, "not_implemented": 1}, "period": "weekly"}
    ass = [{"domain": "a", "score": 90, "rating": "compliant"},
           {"domain": "b", "score": 20, "rating": "not_implemented"}]
    buckets = [{"label": "2026-W24", "avg_score": 55, "domains": 2, "scans": 2,
                "ratings": {"compliant": 1, "not_implemented": 1}}]
    assert build_scope_report_pdf(meta, ass, buckets, bands)[:4] == b"%PDF"
    assert build_trend_report_pdf(meta, buckets, bands)[:4] == b"%PDF"
    # empty scope must not raise
    assert build_scope_report_pdf({**meta, "total": 0, "ratings": {}}, [], [],
                                  bands)[:4] == b"%PDF"


def test_report_pdf_endpoints():
    import pytest
    pytest.importorskip("reportlab")
    os.environ["SEE_SECRET_KEY"] = "p" * 32
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    run = db.create_run(["a.com"])
    db.save_assessment(run, _mk_assessment(
        "a.com", "2026-06-10T10:00:00+00:00", 80, "strong"))
    db.finish_run(run)
    from app_factory import create_app
    app = create_app({"db_path": path, "scanning": {"active_smtp": False}})
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "changeme123"})
    for url in ("/app/api/report/pdf", "/app/api/report/trend.pdf?period=monthly",
                "/app/api/report/pdf?domain=a.com"):
        r = client.get(url)
        assert r.status_code == 200
        assert r.headers["Content-Type"] == "application/pdf"
        assert r.get_data()[:4] == b"%PDF"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
